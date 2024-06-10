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
import java.io.IOException;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Random;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreResource;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.MultiKey;
import org.nd4j.evaluation.classification.Evaluation;
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.dataset.DataSet;
import org.nd4j.linalg.dataset.MiniBatchFileDataSetIterator;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.dataset.api.iterator.TestDataSetIterator;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.nd4j.linalg.dataset.api.preprocessor.DataNormalization;
import org.nd4j.linalg.dataset.api.preprocessor.NormalizerStandardize;
import org.nd4j.linalg.dimensionalityreduction.PCA;
import org.nd4j.linalg.factory.Nd4j;

import org.datavec.api.records.reader.RecordReader;
import org.datavec.api.records.reader.impl.csv.CSVRecordReader;
import org.datavec.api.split.FileSplit;
import org.deeplearning4j.datasets.datavec.RecordReaderDataSetIterator;
import org.deeplearning4j.nn.conf.MultiLayerConfiguration;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.layers.DenseLayer;
import org.deeplearning4j.nn.conf.layers.DropoutLayer;
import org.deeplearning4j.nn.conf.layers.OutputLayer;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.nn.weights.WeightInit;
import org.deeplearning4j.optimize.listeners.ScoreIterationListener;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test receiver using {@link UdpMulticastConnector}.
 */
public class GroupOscoreServer {

	private static final Logger LOGGER = LoggerFactory.getLogger(GroupOscoreServer.class);

	static {
		CoapConfig.register();
	}

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
	 * Whether to use Group OSCORE or not.
	 */
	static boolean useGroupOSCORE = true;

	/**
	 * Multicast address to listen to (use the first line to set a custom one).
	 */
	// static InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	// static InetAddress multicastIP = CoAP.MULTICAST_IPV4;
	static InetAddress multicastIP;

	// Use IPv4
	private static boolean ipv4;
	private static final boolean LOOPBACK = false;

	/**
	 * Port to listen to.
	 */
	static final int listenPort = CoAP.DEFAULT_COAP_PORT;

	/**
	 * Unicast port to respond from.
	 */
	static int unicastPort = CoAP.DEFAULT_COAP_PORT + 10;

	/**
	 * ED25519 curve value.
	 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
	 */
	// static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); //Integer value
	// 6

	/* --- OSCORE Security Context information (receiver) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature (EdDSA)
	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;

	// Encryption algorithm for when using Group mode
	private final static AlgorithmID algGroupEnc = AlgorithmID.AES_CCM_16_64_128;

	// Algorithm for key agreement
	private final static AlgorithmID algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] masterSecret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
			0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] masterSalt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };

	private static final int REPLAY_WINDOW = 32;

	private final static byte[] gmPublicKeyBytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F6D79736974652E6578616D706C652E636F6D026C67726F75706D616E6167657203781A636F6170733A2F2F646F6D61696E2E6578616D706C652E6F7267041AAB9B154F08A101A4010103272006215820CDE3EFD3BC3F99C9C9EE210415C6CBA55061B5046E963B8A58C9143A61166472");

	private static byte[] sid;
	private static byte[] serverPublicKey;
	private static byte[] serverPrivateKey;

	private final static byte[] clientRid = new byte[] { (byte) 0xFE };
	private final static byte[] clientPublicKeyBytes = StringUtil.hex2ByteArray(
			"A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
	private static MultiKey clientPublicKey;

	private final static byte[] groupIdentifier = new byte[] { 0x44, 0x61, 0x6c }; // GID

	/* --- OSCORE Security Context information --- */

	private static Random random;

	/* --- Parameters used for model training --- */
	private static int nLocalEpochs = 50; // Number of training epochs
	private static int outputNum = 2; // Number of outputs
	private static int numInputs = 30; // Number of intput features to the model
	private static int batchSize = 640; // Batch size
	private static MultiLayerConfiguration conf;
	private static MultiLayerNetwork model;
	private static DataSetIterator IterTrain;
	private static DataSetIterator IterTest;
	private static DataSetIterator trainIter;
	private static DataSetIterator testIter;

	/**
	 * Main method
	 * 
	 * @param args command line arguments
	 * @throws Exception on setup or message processing failure
	 */
	public static void main(String[] args) throws Exception {

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		// Set sender & receiver keys for countersignatures
		clientPublicKey = new MultiKey(clientPublicKeyBytes);

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

		int serverCount = -1;
		int serverId = -1;
		String multicastStr = "ipv4";
		String serverDataset = null;
		try {
			serverId = Integer.parseInt(cmdArgs.get("--server-id"));
			serverCount = Integer.parseInt(cmdArgs.get("--server-count"));
			serverDataset = cmdArgs.get("--server-data");
			multicastStr = cmdArgs.get("--multicast-ip");
			useGroupOSCORE = Boolean.parseBoolean(cmdArgs.get("--group-oscore"));
		} catch (Exception e) {
			printHelp();
		}

		// Multicast IP to use
		if (multicastStr.toLowerCase().equals("ipv4")) {
			multicastIP = CoAP.MULTICAST_IPV4;
			ipv4 = true;
		} else if (multicastStr.toLowerCase().equals("ipv6")) {
			multicastIP = CoAP.MULTICAST_IPV6_SITELOCAL;
			ipv4 = false;
		} else {
			System.err.println("Invalid option for --multicast-ip, must be IPv4 or IPv6");
		}

		if (serverCount == -1 || serverId == -1) {
			printHelp();
		}
		// End parse command line arguments

		MultiKey serverPublicPrivateKey = null;
		unicastPort = unicastPort + serverId;
		sid = Credentials.serverSenderIds.get(serverId);
		serverPublicKey = Credentials.serverPublicKeys.get(serverId);
		serverPrivateKey = Credentials.serverPrivateKeys.get(serverId);
		serverPublicPrivateKey = new MultiKey(serverPublicKey, serverPrivateKey);
		System.out.println("Starting with SID " + StringUtil.byteArray2Hex(sid));

		// If OSCORE is being used set the context information
		if (useGroupOSCORE) {

			byte[] gmPublicKey = gmPublicKeyBytes;
			GroupCtx commonCtx = new GroupCtx(masterSecret, masterSalt, alg, kdf, groupIdentifier, algCountersign,
					algGroupEnc, algKeyAgreement, gmPublicKey);

			commonCtx.addSenderCtxCcs(sid, serverPublicPrivateKey);
			commonCtx.addRecipientCtxCcs(clientRid, REPLAY_WINDOW, clientPublicKey);
			commonCtx.setResponsesIncludePartialIV(false);
			commonCtx.setPairwiseModeResponses(true);

			db.addContext(uriLocal, commonCtx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		// Initialize random number generator
		random = new Random();

		Configuration config = Configuration.getStandard();
		config.set(CoapConfig.PREFERRED_BLOCK_SIZE, MAX_MSG_SIZE);
		config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, MAX_MSG_SIZE);
		config.set(CoapConfig.MAX_MESSAGE_SIZE, MAX_MSG_SIZE);

		CoapServer server = new CoapServer(config);
		createEndpoints(server, unicastPort, listenPort, config);
		Endpoint endpoint = server.getEndpoint(unicastPort);
		server.add(new HelloWorldResource());
		server.add(new ModelResource());

		// Information about the receiver
		System.out.println("==================");
		System.out.println("*Multicast receiver");
		System.out.println("Uses Group OSCORE: " + useGroupOSCORE);
		System.out.println("Respond to non-confirmable messages: " + replyToNonConfirmable);
		System.out.println("Listening to Multicast IP: " + multicastIP.getHostAddress());
		System.out.println("Unicast IP: " + endpoint.getAddress().getHostString());
		System.out.println("Unicast port: " + endpoint.getAddress().getPort());
		System.out.println("Multicast port: " + listenPort);
		System.out.println("Server ID: " + serverId);
		System.out.println("Total server count: " + serverCount);
		System.out.println("Dataset: " + serverDataset);
		System.out.print("CoAP resources: ");
		for (Resource res : server.getRoot().getChildren()) {
			System.out.print(res.getURI() + " ");
		}
		System.out.println("");
		System.out.println("==================");

		/*
		 * Create an iterator using the batch size for one iteration for
		 * MnistData
		 */
		LOGGER.info("Load data....");

		/*
		 * Load Data from local csv file
		 */
		int numLinesToSkip = 1;
		char delimiter = ',';
		// Labels: a single integer representing the class index in column
		// number 116
		int labelIndex = 0;
		int numLabelClasses = 2; // 2 classes for the label
		int Max_servers = 32;
		int numTrunks = 0;
		int startTrunkId = 0;
		DataSet allData_train = null;
		DataSet allData_test = null;

		/*
		 * Load the training and test dataset for three datasets
		 */
		if (serverDataset.endsWith("IoT")) {

			/*
			 * Load the training dataset
			 */

			if (serverCount == Max_servers) {
				//
				RecordReader rrTrain = new CSVRecordReader(numLinesToSkip, delimiter);
				rrTrain.initialize(new FileSplit(new File(Credentials.serverIoTDatasets.get(serverId))));
				List<DataSet> ret_train = new ArrayList<>();
				IterTrain = new RecordReaderDataSetIterator(rrTrain, batchSize, labelIndex, numLabelClasses);
				while (IterTrain.hasNext()) {
					ret_train.add(IterTrain.next());
				}
				allData_train = DataSet.merge(ret_train);

			} else {

				RecordReader rrTrain = new CSVRecordReader(numLinesToSkip, delimiter);
				numTrunks = Max_servers / serverCount; // Get the number of
														// trunks to read files
				startTrunkId = numTrunks * serverId; // Get the starting Trunk
														// Id
				List<DataSet> ret_train = new ArrayList<>();

				for (int i = startTrunkId; i < (startTrunkId + numTrunks); i++) {

					rrTrain.initialize(new FileSplit(new File(Credentials.serverIoTDatasets.get(i))));
					IterTrain = new RecordReaderDataSetIterator(rrTrain, batchSize, labelIndex, numLabelClasses);
					while (IterTrain.hasNext()) {
						ret_train.add(IterTrain.next());
					}
				}
				allData_train = DataSet.merge(ret_train);

			}

			/*
			 * Load the test dataset
			 */
			List<DataSet> ret_test = new ArrayList<>();
			RecordReader rrTest = new CSVRecordReader(numLinesToSkip, delimiter);
			rrTest.initialize(new FileSplit(new File("datasets/N_BaIoT/IoT_test.csv")));
			IterTest = new RecordReaderDataSetIterator(rrTest, batchSize, labelIndex, numLabelClasses);
			while (IterTest.hasNext()) {
				ret_test.add(IterTest.next());
			}
			allData_test = DataSet.merge(ret_test);

			labelIndex = 115;

		} else if (serverDataset.endsWith("SD")) {
			/*
			 * Load the training dataset
			 */

			if (serverCount == Max_servers) {
				//
				RecordReader rrTrain = new CSVRecordReader(numLinesToSkip, delimiter);
				rrTrain.initialize(new FileSplit(new File(Credentials.serverSmokeDetectDatasets.get(serverId))));
				List<DataSet> ret_train = new ArrayList<>();
				IterTrain = new RecordReaderDataSetIterator(rrTrain, batchSize, labelIndex, numLabelClasses);
				while (IterTrain.hasNext()) {
					ret_train.add(IterTrain.next());
				}
				allData_train = DataSet.merge(ret_train);

			} else {

				RecordReader rrTrain = new CSVRecordReader(numLinesToSkip, delimiter);
				numTrunks = Max_servers / serverCount; // Get the number of
														// trunks to read files
				startTrunkId = numTrunks * serverId; // Get the starting Trunk
														// Id
				List<DataSet> ret_train = new ArrayList<>();

				for (int i = startTrunkId; i < (startTrunkId + numTrunks); i++) {

					rrTrain.initialize(new FileSplit(new File(Credentials.serverSmokeDetectDatasets.get(i))));
					IterTrain = new RecordReaderDataSetIterator(rrTrain, batchSize, labelIndex, numLabelClasses);
					while (IterTrain.hasNext()) {
						ret_train.add(IterTrain.next());
					}
				}
				allData_train = DataSet.merge(ret_train);

			}

			/*
			 * Load the test dataset
			 */
			List<DataSet> ret_test = new ArrayList<>();
			RecordReader rrTest = new CSVRecordReader(numLinesToSkip, delimiter);
			rrTest.initialize(new FileSplit(new File("datasets/Smoke_Detection/SD_test.csv")));
			IterTest = new RecordReaderDataSetIterator(rrTest, batchSize, labelIndex, numLabelClasses);
			while (IterTest.hasNext()) {
				ret_test.add(IterTest.next());
			}
			allData_test = DataSet.merge(ret_test);

			labelIndex = 14;
		} else if (serverDataset.endsWith("Diabetes")) {

			if (serverCount == Max_servers) {
				//
				RecordReader rrTrain = new CSVRecordReader(numLinesToSkip, delimiter);
				rrTrain.initialize(new FileSplit(new File(Credentials.serverDiabetesDatasets.get(serverId))));
				List<DataSet> ret_train = new ArrayList<>();
				IterTrain = new RecordReaderDataSetIterator(rrTrain, batchSize, labelIndex, numLabelClasses);
				while (IterTrain.hasNext()) {
					ret_train.add(IterTrain.next());
				}
				allData_train = DataSet.merge(ret_train);

			} else {

				RecordReader rrTrain = new CSVRecordReader(numLinesToSkip, delimiter);
				numTrunks = Max_servers / serverCount; // Get the number of
														// trunks to read files
				startTrunkId = numTrunks * serverId; // Get the starting Trunk
														// Id
				List<DataSet> ret_train = new ArrayList<>();

				for (int i = startTrunkId; i < (startTrunkId + numTrunks); i++) {

					rrTrain.initialize(new FileSplit(new File(Credentials.serverDiabetesDatasets.get(i))));
					IterTrain = new RecordReaderDataSetIterator(rrTrain, batchSize, labelIndex, numLabelClasses);
					while (IterTrain.hasNext()) {
						ret_train.add(IterTrain.next());
					}
				}
				allData_train = DataSet.merge(ret_train);

			}

			/*
			 * Load the test dataset
			 */
			List<DataSet> ret_test = new ArrayList<>();
			RecordReader rrTest = new CSVRecordReader(numLinesToSkip, delimiter);
			rrTest.initialize(new FileSplit(new File("datasets/Diabetes/Dia_test.csv")));
			IterTest = new RecordReaderDataSetIterator(rrTest, batchSize, labelIndex, numLabelClasses);
			while (IterTest.hasNext()) {
				ret_test.add(IterTest.next());
			}
			allData_test = DataSet.merge(ret_test);

			labelIndex = 8;
		}

		allData_train.shuffle();
		allData_test.shuffle();
		INDArray features_train = allData_train.getFeatures();
		INDArray features_test = allData_test.getFeatures();
		if (labelIndex > numInputs) {
			features_train = PCA.pca(features_train, numInputs, true);
			features_test = PCA.pca(features_test, numInputs, true);
		}
		DataSet trainingData = new DataSet(features_train, allData_train.getLabels());
		DataSet testData = new DataSet(features_test, allData_test.getLabels());
		System.out.println("Number of examples in the training set: " + trainingData.numExamples());
		System.out.println("Number of examples in thee test set: " + testData.numExamples());

		/*
		 * Normalize the training and test dataset
		 */
		DataNormalization normalizer_train = new NormalizerStandardize();
		// Collect the statistics (mean/stdev) from the training data. This does
		// not modify the input data
		normalizer_train.fit(trainingData);
		// Apply normalization to the training data
		normalizer_train.transform(trainingData);

		DataNormalization normalizer_test = new NormalizerStandardize();
		// Collect the statistics (mean/stdev) from the training data. This does
		// not modify the input data
		normalizer_test.fit(testData);
		// Apply normalization to the training data
		normalizer_test.transform(testData);

		trainIter = new MiniBatchFileDataSetIterator(trainingData, batchSize);
		testIter = new TestDataSetIterator(testData, batchSize);

		/*
		 * Construct the neural network
		 */
		System.out.println("Build model....");
		int seed = 123;
		conf = new NeuralNetConfiguration.Builder().seed(seed).activation(Activation.RELU).weightInit(WeightInit.XAVIER)
				.l2(1e-4).list().layer(new DenseLayer.Builder().nIn(numInputs).nOut(8).hasLayerNorm(true).build())
				.layer(new DropoutLayer.Builder(0.1).build())
				.layer(new DenseLayer.Builder().nIn(8).nOut(3).hasLayerNorm(true).build())
				.layer(new DropoutLayer.Builder(0.1).build())
				.layer(new OutputLayer.Builder(LossFunctions.LossFunction.MSE).activation(Activation.SIGMOID).nIn(3)
						.nOut(outputNum).build())
				.build();

		System.out.println("");
		System.out.println("==================");

		server.start();
		System.out.println("CoAP server started on port: " + unicastPort);
	}

	private static void TrainModel(INDArray updateModel, boolean initFlag) {

		if (initFlag == true) {
			model = new MultiLayerNetwork(conf);
			model.init();
			System.out.println(model.summary());
		} else {
			System.out.println("Update Local model...");
			model.setParams(updateModel);
		}

		System.out.println("Train local model...");
		// Print score every 10 iterations and evaluate on test set every epoch
		model.setListeners(new ScoreIterationListener(1));

		System.out.println("The parameters before training: " + model.params());

		for (int i = 0; i < nLocalEpochs; i++) {
			model.fit(trainIter);
		}

		System.out.println("The parameters after training: " + model.params());
		System.out.println("The length of model's parameters: " + model.params().length());

		Evaluation eval = new Evaluation(outputNum);
		System.out.println("Evaluate with test dataset");
		while (testIter.hasNext()) {
			DataSet t = testIter.next();
			INDArray features = t.getFeatures();
			INDArray labels = t.getLabels();
			INDArray predicted = model.output(features, false);
			eval.eval(labels, predicted);
		}
		testIter.reset();

		// Print the evaluation statistics
		System.out.println(eval.stats());

	}

	private static class ModelResource extends OSCoreResource {

		private ModelResource() {
			// set resource identifier
			super("model", true); // Changed

			// set display name
			getAttributes().setTitle("Model Resource");

		}

		@Override
		public void handlePOST(CoapExchange exchange) {
			System.out.println("Accessing model resource");

			// Parse and handle request
			byte[] payloadReq = exchange.getRequestPayload();

			final int floatSize = Float.SIZE / 8;
			int numElements = payloadReq.length / floatSize;

			float[] modelReq = new float[numElements];
			for (int i = 0; i < numElements; i++) {
				byte[] elementBytes = new byte[floatSize];
				System.arraycopy(payloadReq, i * floatSize, elementBytes, 0, floatSize);
				modelReq[i] = ByteBuffer.wrap(elementBytes).getFloat();
			}

			System.out.print("Incoming payload: ");
			for (int i = 0; i < numElements; i++) {
				System.out.print(modelReq[i] + " ");

			}
			System.out.println();

			/*
			 * Get the updated model from the request message, and create a
			 * INDArray to get
			 * 
			 * TODO: add the flag or a message to indicate the current round
			 */
			INDArray updatedModel = Nd4j.create(modelReq);
			System.out.println(updatedModel.length());

			boolean initFlag = false;
			// Train
			if (modelReq.length == 0) {
				initFlag = true;
			}
			TrainModel(updatedModel, initFlag);

			float[] modelRes = model.params().toFloatVector();

			numElements = modelRes.length;
			byte[] payloadRes = new byte[floatSize * numElements];
			for (int i = 0; i < numElements; i++) {
				byte[] elementBytes = ByteBuffer.allocate(floatSize).putFloat(modelRes[i]).array();
				System.arraycopy(elementBytes, 0, payloadRes, i * floatSize, floatSize);
			}

			System.out.println();
			if (payloadRes.length > MAX_MSG_SIZE) {
				System.err.println("Error: Payload exceeds maximum messages size (" + MAX_MSG_SIZE + " bytes)");
			}

			// Create response
			Response r = new Response(ResponseCode.CHANGED);
			r.setPayload(payloadRes);
			r.setType(Type.NON);
			exchange.respond(r);

		}

	}

	private static class HelloWorldResource extends CoapResource {

		private int id;
		private int count = 0;

		private HelloWorldResource() {
			// set resource identifier
			super("helloWorld"); // Changed

			// set display name
			getAttributes().setTitle("Hello-World Resource");

			id = random.nextInt(1000);

			System.out.println("Incoming Request to HelloWorld Resource");
			System.out.println("coap receiver: " + id);
		}

		// Added for handling GET
		@Override
		public void handleGET(CoapExchange exchange) {
			handlePOST(exchange);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {

			System.out.println("Receiving request #" + count);
			count++;

			System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
			System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());

			System.out.println(Utils.prettyPrint(exchange.advanced().getRequest()));

			boolean isConfirmable = exchange.advanced().getRequest().isConfirmable();

			// respond to the request if confirmable or replies are set to be
			// sent for non-confirmable payload is set to request payload
			// changed to uppercase plus the receiver ID
			if (isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.setPayload(exchange.getRequestText().toUpperCase() + ". ID: " + id);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				if (isConfirmable) {
					r.setType(Type.ACK);
				} else {
					r.setType(Type.NON);
				}

				System.out.println();
				System.out.println("Sending to: " + r.getDestinationContext().getPeerAddress());
				System.out.println("Sending from: " + exchange.advanced().getEndpoint().getAddress());
				System.out.println(Utils.prettyPrint(r));

				exchange.respond(r);
			}

		}

	}

	/**
	 * Methods below from MulticastTestServer to set up multicast listening.
	 */

	/**
	 * From MulticastTestServer
	 * 
	 * @param server
	 * @param unicastPort
	 * @param multicastPort
	 * @param config
	 */
	private static void createEndpoints(CoapServer server, int unicastPort, int multicastPort, Configuration config)
			throws SocketException {
		// UDPConnector udpConnector = new UDPConnector(new
		// InetSocketAddress(unicastPort));
		// udpConnector.setReuseAddress(true);
		// CoapEndpoint coapEndpoint = new
		// CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector).build();

		// NetworkInterface networkInterface =
		// NetworkInterfacesUtil.getMulticastInterface().getByName("wlp3s0");
		NetworkInterface networkInterface = NetworkInterfacesUtil.getMulticastInterface();

		if (networkInterface == null) {
			LOGGER.warn("No multicast network-interface found!");
			throw new Error("No multicast network-interface found!");
		}
		LOGGER.info("Multicast Network Interface: {}", networkInterface.getDisplayName());

		UdpMulticastConnector.Builder builder = new UdpMulticastConnector.Builder();

		if (!ipv4 && NetworkInterfacesUtil.isAnyIpv6()) {
			Inet6Address ipv6 = NetworkInterfacesUtil.getMulticastInterfaceIpv6();
			LOGGER.info("Multicast: IPv6 Network Address: {}", StringUtil.toString(ipv6));
			UDPConnector udpConnector = new UDPConnector(new InetSocketAddress(ipv6, unicastPort), config);
			udpConnector.setReuseAddress(true);
			CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector)
					.build();

			builder = new UdpMulticastConnector.Builder().setLocalAddress(multicastIP, multicastPort)
					.addMulticastGroup(multicastIP, networkInterface);
			createReceiver(builder, udpConnector);

			/*
			 * https://bugs.openjdk.java.net/browse/JDK-8210493 link-local
			 * multicast is broken
			 */
			builder = new UdpMulticastConnector.Builder().setLocalAddress(multicastIP, multicastPort)
					.addMulticastGroup(multicastIP, networkInterface);
			createReceiver(builder, udpConnector);

			server.addEndpoint(coapEndpoint);
			LOGGER.info("IPv6 - multicast");
		}

		if (ipv4 && NetworkInterfacesUtil.isAnyIpv4()) {
			Inet4Address ipv4 = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
			LOGGER.info("Multicast: IPv4 Network Address: {}", StringUtil.toString(ipv4));
			UDPConnector udpConnector = new UDPConnector(new InetSocketAddress(ipv4, unicastPort), config);
			udpConnector.setReuseAddress(true);
			CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector)
					.build();

			builder = new UdpMulticastConnector.Builder().setLocalAddress(multicastIP, multicastPort)
					.addMulticastGroup(multicastIP, networkInterface);
			createReceiver(builder, udpConnector);

			Inet4Address broadcast = NetworkInterfacesUtil.getBroadcastIpv4();
			if (broadcast != null) {
				// windows seems to fail to open a broadcast receiver
				builder = new UdpMulticastConnector.Builder().setLocalAddress(broadcast, multicastPort);
				createReceiver(builder, udpConnector);
			}
			server.addEndpoint(coapEndpoint);
			LOGGER.info("IPv4 - multicast");
		}
		UDPConnector udpConnector = new UDPConnector(
				new InetSocketAddress(InetAddress.getLoopbackAddress(), unicastPort), config);
		udpConnector.setReuseAddress(true);
		CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector)
				.build();
		server.addEndpoint(coapEndpoint);
		LOGGER.info("loopback");
	}

	/**
	 * From MulticastTestServer
	 * 
	 * @param builder
	 * @param connector
	 */
	private static void createReceiver(UdpMulticastConnector.Builder builder, UDPConnector connector) {
		UdpMulticastConnector multicastConnector = builder.setMulticastReceiver(true).build();
		multicastConnector.setLoopbackMode(LOOPBACK);
		try {
			multicastConnector.start();
		} catch (BindException ex) {
			// binding to multicast seems to fail on windows
			if (builder.getLocalAddress().getAddress().isMulticastAddress()) {
				int port = builder.getLocalAddress().getPort();
				builder.setLocalPort(port);
				multicastConnector = builder.build();
				multicastConnector.setLoopbackMode(LOOPBACK);
				try {
					multicastConnector.start();
				} catch (IOException e) {
					e.printStackTrace();
					multicastConnector = null;
				}
			} else {
				ex.printStackTrace();
				multicastConnector = null;
			}
		} catch (IOException e) {
			e.printStackTrace();
			multicastConnector = null;
		}
		if (multicastConnector != null && connector != null) {
			connector.addMulticastReceiver(multicastConnector);
		}
	}

	private static void printHelp() {
		System.out.println("Arguments:");
		System.out.println("--multicast-ip: IPv4 or IPv6 [Optional]");
		System.out.println("--server-count: Total number of servers");
		System.out.println("--server-data: Dataset for this server");
		System.out.println("--server-id: ID for this server");
		System.out.println("--group-oscore: Use Group OSCORE [Optional. Default: true]");
		System.exit(1);
	}
}
