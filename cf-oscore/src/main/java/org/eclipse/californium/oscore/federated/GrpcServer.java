/*******************************************************************************
 * Copyright (c) 2020 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial creation
 *    Rikard Höglund (RISE SICS) - Group OSCORE receiver functionality
 ******************************************************************************/
package org.eclipse.californium.oscore.federated;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.nd4j.evaluation.classification.EvaluationBinary;
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.dataset.DataSet;
import org.nd4j.linalg.dataset.MiniBatchFileDataSetIterator;
import org.nd4j.linalg.dataset.SplitTestAndTrain;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.dataset.api.iterator.TestDataSetIterator;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.nd4j.linalg.dataset.api.preprocessor.DataNormalization;
import org.nd4j.linalg.dataset.api.preprocessor.NormalizerStandardize;
import org.nd4j.linalg.dimensionalityreduction.PCA;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.learning.config.Sgd;
import org.datavec.api.records.reader.RecordReader;
import org.datavec.api.records.reader.impl.csv.CSVRecordReader;
import org.datavec.api.split.FileSplit;
import org.deeplearning4j.datasets.datavec.RecordReaderDataSetIterator;
import org.deeplearning4j.nn.conf.GradientNormalization;
import org.deeplearning4j.nn.conf.MultiLayerConfiguration;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.layers.DenseLayer;
import org.deeplearning4j.nn.conf.layers.OutputLayer;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.nn.weights.WeightInit;
import org.deeplearning4j.optimize.listeners.ScoreIterationListener;

/**
 * Test receiver using {@link UdpMulticastConnector}.
 */
public class GrpcServer {


	/**
	 * Maximum message size
	 */
	private static int MAX_MSG_SIZE = 1400;

	/**
	 * Controls whether or not the receiver will reply to incoming multicast
	 * non-confirmable requests.
	 * 
	 * The receiver will always reply to confirmable requests (can be used with
	 * unicast).
	 * 
	 */
	static final boolean replyToNonConfirmable = true;

	/**
	 * Whether to use gRPC or not.
	 */
	static boolean useGrpc = true;

	/**
	 * Use unicast (one-by-one to the servers)
	 */
	static boolean unicastMode = true;

	/**
	 * Total server count in the federation
	 */
	static int serverCount;
	static int serverId;

	/* --- Parameters used for model training --- */
	private static int nLocalEpochs = 5; // Number of training epochs
	private static int outputNum = 1; // Number of outputs
	private static int numInputs = 30; // Number of intput features to the model
	private static int batchSize = 256; // Batch size
	private static int ReadFileBatch = 64; // Batch size
	private static int seed = 77; // seed number
	private static MultiLayerConfiguration conf;
	private static MultiLayerNetwork model;
	private static DataSetIterator IterLoad;
	private static DataSetIterator trainIter;
	private static DataSetIterator testIter;
	private static boolean serverIsInitialized = false;

	private static int latestVersionNumber = -1;

	// For gRPC
	private static int grpcPort = 5080;
	private static FedResourceServlet theServlet = null;
	private static boolean useTls = false;

	/**
	 * Main method
	 * 
	 * @param args command line arguments
	 * @throws Exception on setup or message processing failure
	 */
	public static void main(String[] args) throws Exception {

		// Parse command line arguments
		HashMap<String, String> cmdArgs = new HashMap<>();
		if (args.length % 2 != 0) {
			printHelp();
		}

		for (int i = 0; i < args.length; i += 2) {

			if (args[i + 1].toLowerCase().equals("null")) {
				;
			} else {
				cmdArgs.put(args[i], args[i + 1]);
			}
		}

		if (cmdArgs.containsValue("--help")) {
			printHelp();
		}

		String serverDataset = null;
		boolean useFederatedLearning = true;
		boolean debugPrint = true;
		try {
			serverId = Integer.parseInt(cmdArgs.get("--server-id"));
			serverCount = Integer.parseInt(cmdArgs.get("--server-count"));
			serverDataset = cmdArgs.get("--server-data");
			useGrpc = Boolean.parseBoolean(cmdArgs.getOrDefault("--grpc", "true"));
			useTls = Boolean.parseBoolean(cmdArgs.getOrDefault("--tls", "false"));
			unicastMode = Boolean.parseBoolean(cmdArgs.getOrDefault("--unicast", "true"));
			useFederatedLearning = Boolean.parseBoolean(cmdArgs.getOrDefault("--federated-learning", "true"));
			debugPrint = Boolean.parseBoolean(cmdArgs.getOrDefault("--debug", "true"));
		} catch (Exception e) {
			printHelp();
		}

		if (!debugPrint) {
			DebugOut.ENABLE_PRINTING = false;
		}

		if (serverCount == -1 || serverId == -1 || serverDataset == null) {
			printHelp();
		}

		if (useGrpc && !unicastMode) {
			DebugOut.println("Invalid config:");
			DebugOut.println("useOSCORE: " + useGrpc);
			DebugOut.println("unicastMode: " + unicastMode);
			DebugOut.println();
			printHelp();
		}

		// End parse command line arguments

		Server server = null;
		if (useTls == false) {
			server = startGrpcServerNoTls();
		} else {
			server = startGrpcServerTls(serverId);
		}

		DebugOut.println("gRPC server started on port: " + grpcPort);

		String endpoint = "Undetermined";
		if (server != null && server.getURI() != null) {
			endpoint = server.getURI().toASCIIString();
		}

		// Information about the receiver
		DebugOut.println("==================");
		DebugOut.println("*Receiver");
		DebugOut.println("Uses gRPC: " + useGrpc);
		DebugOut.println("Use multicast: " + !unicastMode);
		DebugOut.println("Unicast IP: " + endpoint);
		DebugOut.println("Unicast port: " + grpcPort);
		DebugOut.println("Use TLS: " + useTls);
		DebugOut.println("Server ID: " + serverId);
		DebugOut.println("Total server count: " + serverCount);
		DebugOut.println("Dataset: " + serverDataset);
		DebugOut.println("");
		DebugOut.println("==================");

		/*
		 * Create an iterator using the batch size for one iteration for
		 * MnistData
		 */
		DebugOut.println("Load data....");

		/*
		 * Load Data from local csv file
		 */
		int numLinesToSkip = 1;
		char delimiter = ',';
		// Labels: a single integer representing the class index in column
		// number 116
		int labelIndex = 0;
		int numLabelClasses = 1; // 2 classes for the label
		int maxServers = 32;
		int numTrunks = 0;
		int startTrunkId = 0;
		DataSet allData = null;

		/*
		 * Load the training and test dataset for three datasets
		 */
		if (serverDataset.endsWith("IoT")) {

			labelIndex = 115;
			seed = 11;

			/*
			 * Load the training dataset
			 */

			if (serverCount == maxServers) {
				//
				RecordReader rr = new CSVRecordReader(numLinesToSkip, delimiter);
				rr.initialize(new FileSplit(new File(Credentials.serverIoTDatasets.get(serverId))));
				List<DataSet> ret = new ArrayList<>();
				IterLoad = new RecordReaderDataSetIterator(rr, ReadFileBatch, labelIndex, numLabelClasses);
				while (IterLoad.hasNext()) {
					ret.add(IterLoad.next());
				}
				allData = DataSet.merge(ret);

			} else {

				RecordReader rrTrain = new CSVRecordReader(numLinesToSkip, delimiter);
				numTrunks = Math.floorDiv(maxServers, serverCount); // Get the number of
														// trunks to read files
				startTrunkId = numTrunks * serverId; // Get the starting Trunk
														// Id
				if (useFederatedLearning == false) {
					startTrunkId = 0;
				}
				List<DataSet> ret = new ArrayList<>();

				for (int i = startTrunkId; i < (startTrunkId + numTrunks); i++) {
					rrTrain.initialize(new FileSplit(new File(Credentials.serverIoTDatasets.get(i))));
					IterLoad = new RecordReaderDataSetIterator(rrTrain, ReadFileBatch, labelIndex, numLabelClasses);
					while (IterLoad.hasNext()) {
						ret.add(IterLoad.next());
					}
				}
				allData = DataSet.merge(ret);

			}

			conf = new NeuralNetConfiguration.Builder().seed(seed).weightInit(WeightInit.XAVIER)
					.updater(new Sgd.Builder().learningRate(1e-3).build())
					.gradientNormalization(GradientNormalization.RenormalizeL2PerLayer).l2(1e-4).biasInit(0).list()
					.layer(new DenseLayer.Builder().nIn(numInputs).nOut(8).dropOut(0.8).weightInit(WeightInit.XAVIER)
							.activation(Activation.LEAKYRELU).hasLayerNorm(true).build())
					.layer(new DenseLayer.Builder().nIn(8).nOut(3).dropOut(0.8).weightInit(WeightInit.XAVIER)
							.activation(Activation.LEAKYRELU).hasLayerNorm(true).build())
					.layer(new OutputLayer.Builder(LossFunctions.LossFunction.XENT).weightInit(WeightInit.XAVIER)
							.activation(Activation.SIGMOID).nIn(3).nOut(outputNum).build())
					.build();

		} else if (serverDataset.endsWith("SD")) {

			labelIndex = 14;
			numInputs = 14;
			batchSize = 256;
			/*
			 * Load the training dataset
			 */

			if (serverCount == maxServers) {

				//
				RecordReader rr = new CSVRecordReader(numLinesToSkip, delimiter);
				rr.initialize(new FileSplit(new File(Credentials.serverSmokeDetectDatasets.get(serverId))));
				List<DataSet> ret = new ArrayList<>();
				IterLoad = new RecordReaderDataSetIterator(rr, ReadFileBatch, labelIndex, numLabelClasses);
				while (IterLoad.hasNext()) {
					ret.add(IterLoad.next());
				}
				allData = DataSet.merge(ret);

			} else {

				RecordReader rr = new CSVRecordReader(numLinesToSkip, delimiter);
				numTrunks =Math.floorDiv(maxServers, serverCount); // Get the number of
														// trunks to read files
				startTrunkId = numTrunks * serverId; // Get the starting Trunk
														// Id
				List<DataSet> ret = new ArrayList<>();

				for (int i = startTrunkId; i < (startTrunkId + numTrunks); i++) {
					rr.initialize(new FileSplit(new File(Credentials.serverSmokeDetectDatasets.get(i))));
					IterLoad = new RecordReaderDataSetIterator(rr, batchSize, labelIndex, numLabelClasses);
					while (IterLoad.hasNext()) {
						ret.add(IterLoad.next());
					}
				}
				allData = DataSet.merge(ret);

			}

			conf = new NeuralNetConfiguration.Builder().seed(seed).weightInit(WeightInit.XAVIER)
					.updater(new Sgd.Builder().learningRate(0.00015).build())
					.gradientNormalization(GradientNormalization.RenormalizeL2PerLayer).l2(1e-3).biasInit(0).list()
					.layer(new DenseLayer.Builder().nIn(numInputs).nOut(8).dropOut(0.6).weightInit(WeightInit.XAVIER)
							.activation(Activation.LEAKYRELU).hasLayerNorm(true).build())
					.layer(new DenseLayer.Builder().nIn(8).nOut(3).dropOut(0.6).weightInit(WeightInit.XAVIER)
							.activation(Activation.LEAKYRELU).hasLayerNorm(true).build())
					.layer(new OutputLayer.Builder(LossFunctions.LossFunction.XENT).weightInit(WeightInit.XAVIER)
							.activation(Activation.SIGMOID).nIn(3).nOut(outputNum).build())
					.build();

		} else if (serverDataset.endsWith("Tro")) {

			labelIndex = 30;

			if (serverCount == maxServers) {
				//
				RecordReader rr = new CSVRecordReader(numLinesToSkip, delimiter);
				rr.initialize(new FileSplit(new File(Credentials.serverTrojanDatasets.get(serverId))));
				List<DataSet> ret_train = new ArrayList<>();
				IterLoad = new RecordReaderDataSetIterator(rr, ReadFileBatch, labelIndex, numLabelClasses);
				while (IterLoad.hasNext()) {
					ret_train.add(IterLoad.next());
				}
				allData = DataSet.merge(ret_train);

			} else {

				RecordReader rr = new CSVRecordReader(numLinesToSkip, delimiter);
				numTrunks = Math.floorDiv(maxServers, serverCount); // Get the number of
														// trunks to read files
				startTrunkId = numTrunks * serverId; // Get the starting Trunk
														// Id
				List<DataSet> ret = new ArrayList<>();

				for (int i = startTrunkId; i < (startTrunkId + numTrunks); i++) {
					rr.initialize(new FileSplit(new File(Credentials.serverTrojanDatasets.get(i))));
					IterLoad = new RecordReaderDataSetIterator(rr, ReadFileBatch, labelIndex, numLabelClasses);
					while (IterLoad.hasNext()) {
						ret.add(IterLoad.next());
					}
				}
				allData = DataSet.merge(ret);

			}

			conf = new NeuralNetConfiguration.Builder().seed(seed).weightInit(WeightInit.XAVIER)
					.updater(new Sgd.Builder().learningRate(1e-3).build())
					.gradientNormalization(GradientNormalization.RenormalizeL2PerLayer).l2(1e-2).biasInit(0).list()
					.layer(new DenseLayer.Builder().nIn(numInputs).nOut(8).weightInit(WeightInit.XAVIER)
							.activation(Activation.LEAKYRELU).hasLayerNorm(true).build())
					.layer(new DenseLayer.Builder().nIn(8).nOut(3).weightInit(WeightInit.XAVIER)
							.activation(Activation.LEAKYRELU).hasLayerNorm(true).build())
					.layer(new OutputLayer.Builder(LossFunctions.LossFunction.XENT).weightInit(WeightInit.XAVIER)
							.activation(Activation.SIGMOID).nIn(3).nOut(outputNum).build())
					.build();

		}

		allData.shuffle(seed);
		// allData_test.shuffle(seed);

		INDArray features_train = allData.getFeatures();
		// INDArray features_test = test_Data.getFeatures();
		if (labelIndex > numInputs) {
			features_train = PCA.pca(features_train, numInputs, true);
			// features_test = PCA.pca(features_test, numInputs, true);
			DebugOut.println("PCA is done.");
			allData = new DataSet(features_train, allData.getLabels());

		}

		SplitTestAndTrain testAndTrain = allData.splitTestAndTrain(0.9);

		DataSet training_Data = testAndTrain.getTrain();
		DataSet test_Data = testAndTrain.getTest();

		/*
		 * Normalize the training and test dataset
		 */
		DataNormalization normalizer = new NormalizerStandardize();
		// Collect the statistics (mean/stdev) from the training data. This does
		// not modify the input data
		normalizer.fit(training_Data);
		// Apply normalization to the training data
		normalizer.transform(training_Data);

		// Apply normalization to the training data
		normalizer.transform(test_Data);

		DebugOut.println("Number of examples in the training set: " + training_Data.numExamples());
		DebugOut.println("Number of examples in the test set: " + test_Data.numExamples());

		trainIter = new MiniBatchFileDataSetIterator(training_Data, batchSize);
		testIter = new TestDataSetIterator(test_Data, batchSize);

		/*
		 * Construct the neural network
		 */
		DebugOut.println("Build model....");

		DebugOut.println("Model Data Type: " + conf.getDataType());
		DebugOut.println("==================");
		DebugOut.println("Server Ready");
	}

	private static Server startGrpcServerTls(int serverId) throws Exception {
		Server server = new Server();

		// The HTTP configuration object.
		HttpConfiguration httpConfig = new HttpConfiguration();
		// Add the SecureRequestCustomizer because TLS is used.
		SecureRequestCustomizer src = new SecureRequestCustomizer();
		src.setSniHostCheck(false);
		httpConfig.addCustomizer(src);

		// The ConnectionFactory for HTTP/1.1.
		HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfig);

		// The ConnectionFactory for HTTP/2.
		HTTP2ServerConnectionFactory h2 = new HTTP2ServerConnectionFactory(httpConfig);

		// The ALPN ConnectionFactory.
		ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory();
		// The default protocol to use in case there is no negotiation.
		alpn.setDefaultProtocol(h2.getProtocol()); // Changed

		// Configure the SslContextFactory with the keyStore information.
		SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
		sslContextFactory.setKeyStorePath("keystore.jks");
		sslContextFactory.setKeyStorePassword("secret");

		// The ConnectionFactory for TLS.
		SslConnectionFactory tls = new SslConnectionFactory(sslContextFactory, alpn.getProtocol());

		// The ServerConnector instance.
		ServerConnector connector = new ServerConnector(server, tls, alpn, h2, http11);
		connector.setPort(grpcPort);

		server.addConnector(connector);

		//

		// Create a servlet context handler at the root path
		ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath("/");
		server.setHandler(context);

		// Add a simple Hello World servlet
		GrpcServer grpcServer = new GrpcServer();
		theServlet = new FedResourceServlet(grpcServer);
		context.addServlet(new ServletHolder(theServlet), "/helloworld.Greeter/SayHello");
		//

		server.start();
		return server;
	}

	/**
	 * @return
	 * @throws Exception
	 */
	private static Server startGrpcServerNoTls() throws Exception {
		// === Start gRPC server (no TLS)

		Server server = new Server();

		HttpConfiguration httpConfig = new HttpConfiguration();

		// For HTTP/1.1 cleartext:
		HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfig);

		// For HTTP/2 cleartext (h2c):
		HTTP2CServerConnectionFactory h2c = new HTTP2CServerConnectionFactory(httpConfig);

		// Create a cleartext ServerConnector
		ServerConnector connector = new ServerConnector(server, http11, h2c);
		connector.setPort(grpcPort);

		// Add the connector to the server.
		server.addConnector(connector);

		// Jetty setup of handlers, servlets, etc.
		ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath("/");
		server.setHandler(context);

		GrpcServer grpcServer = new GrpcServer();
		theServlet = new FedResourceServlet(grpcServer);
		context.addServlet(new ServletHolder(theServlet), "/helloworld.Greeter/SayHello");

		server.start();

		// === End start gRPC server
		return server;
	}

	private static double TrainModel(INDArray updateModel, boolean initFlag, boolean processRequestModel) {

		if (initFlag == true) {
			model = new MultiLayerNetwork(conf);
			model.init();
			serverIsInitialized = true;
			DebugOut.println(model.summary());
		} else {
			DebugOut.println("Update Local model...");
			if (processRequestModel) {
				model.setParams(updateModel);
			}
		}

		DebugOut.println("Train local model...");
		// Print score every 10 iterations and evaluate on test set every epoch
		model.setListeners(new ScoreIterationListener(1));

		DebugOut.println("The parameters before training: " + model.params());
		EvaluationBinary eval_train = new EvaluationBinary();
		for (int i = 0; i < nLocalEpochs; i++) {

			model.fit(trainIter);
			DebugOut.println("Loss:" + model.score());
			model.doEvaluation(trainIter, eval_train);

		}
		DebugOut.println(eval_train.stats());

		DebugOut.println("The parameters after training: " + model.params());
		DebugOut.println("The length of model's parameters: " + model.params().length());

		EvaluationBinary eval = new EvaluationBinary();
		DebugOut.println("Evaluate with test dataset");
		while (testIter.hasNext()) {
			DataSet t = testIter.next();
			INDArray features = t.getFeatures();
			INDArray labels = t.getLabels();
			INDArray predicted = model.output(features, false);
			eval.eval(labels, predicted);
		}
		testIter.reset();

		// Print the evaluation statistics
		DebugOut.println(eval.stats());

		double accuracy = eval.accuracy(0);

		return accuracy;

	}

	public byte[] handleIncoming(byte[] incomingPayload) {
		DebugOut.println("Accessing model resource");

		// Parse and handle request
		byte[] payloadReq = incomingPayload;

		// Extract model version from payload
		int receivedVersion = (int) payloadReq[payloadReq.length - 1];
		byte[] newArray = Arrays.copyOf(payloadReq, payloadReq.length - 1);
		payloadReq = Arrays.copyOf(newArray, newArray.length);

		// Check for exiting (experiment over)
		if (incomingPayload.length <= 20) {
			String payloadText = new String(incomingPayload, StandardCharsets.UTF_8);
			if (payloadText.startsWith("EXIT123")) {
				System.exit(0);
			}
		}

		// Parse bytes in request payload into float vector
		float[] modelReq = FloatConverter.bytesToFloatVector(payloadReq);

		DebugOut.print("Incoming payload: ");
		for (int i = 0; i < modelReq.length; i++) {
			DebugOut.print(modelReq[i] + " ");

		}
		DebugOut.println();

		/*
		 * Get the updated model from the request message, and create a INDArray
		 * to get
		 */
		INDArray updatedModel = Nd4j.create(modelReq);
		DebugOut.println(updatedModel.length());

		boolean initFlag = false;
		// Train
		if (modelReq.length == 0) {
			initFlag = true;
			DebugOut.println("Model with size 0 received! Initializing model.");
		} else {
			if (serverIsInitialized == false) {
				initFlag = true;
				DebugOut.println(
						"Model with size non-zero size received! Initializing model (must have missed the message with empty payload)");
			}
		}

		boolean processRequestModel;
		if (receivedVersion <= latestVersionNumber) {
			processRequestModel = false;
			initFlag = false;
		} else {
			processRequestModel = true;
			latestVersionNumber = receivedVersion;
		}

		// Add accuracy to float vector end
		float epochAccuracy = (float) TrainModel(updatedModel, initFlag, processRequestModel);
		float[] modelResPre = model.params().toFloatVector();
		float[] modelRes = new float[modelResPre.length + 1];
		System.arraycopy(modelResPre, 0, modelRes, 0, modelResPre.length);
		modelRes[modelResPre.length] = epochAccuracy;

		// Build byte payload to send from float vector
		byte[] payloadRes = FloatConverter.floatVectorToBytes(modelRes);

		DebugOut.println();
		if (payloadRes.length > MAX_MSG_SIZE) {
			DebugOut.errPrintln("Error: Payload exceeds maximum messages size (" + MAX_MSG_SIZE + " bytes)");
		}

		// All 3 not needed
		// FedResourceServlet.setResponsePayload(payloadRes);
		// theServlet.setResponsePayload(payloadRes);
		return payloadRes.clone();
}

	private static void printHelp() {
		System.out.println("Arguments:");
		System.out.println("--server-count: Total number of servers");
		System.out.println("--server-data: Dataset for this server [IoT, SD, Diabetes]");
		System.out.println("--server-id: ID for this server");
		System.out.println("--federated-learning: Use Federated Learning [Optional. Default: true]");
		System.out.println("--grpc: Use gRPC [Optional. Default: true]");
		System.out.println("--tls: Use TLS (for gRPC) [Optional. Default: false]");
		System.out.println("--unicast: Use unicast (one-by-one to the servers) [Optional. Default: true]");
		System.out.println("--debug: Enable/disable debug printing [Optional. Default: true]");
		System.exit(1);
	}
}
