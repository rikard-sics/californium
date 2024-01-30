package org.eclipse.californium.oscore.federated;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FilenameUtils;
import org.deeplearning4j.datasets.iterator.impl.MnistDataSetIterator;
import org.deeplearning4j.nn.conf.MultiLayerConfiguration;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.inputs.InputType;
import org.deeplearning4j.nn.conf.layers.ConvolutionLayer;
import org.deeplearning4j.nn.conf.layers.DenseLayer;
import org.deeplearning4j.nn.conf.layers.OutputLayer;
import org.deeplearning4j.nn.conf.layers.PoolingType;
import org.deeplearning4j.nn.conf.layers.SubsamplingLayer;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.nn.weights.WeightInit;
import org.deeplearning4j.optimize.api.InvocationType;
import org.deeplearning4j.optimize.listeners.EvaluativeListener;
import org.deeplearning4j.optimize.listeners.ScoreIterationListener;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreResource;
import org.eclipse.californium.oscore.OSException;
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.learning.config.Adam;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LeNeTMNIST_Sever {
	
	private static final Logger log = LoggerFactory.getLogger(LeNetMNIST.class);

	
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[] { 0x01 };
	private final static byte[] rid = new byte[0];
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	public static void main(String[] args)  throws OSException, IOException {
		// TODO Auto-generated method stub
		
		
		int nChannels = 1; // Number of input channels
		int outputNum = 10; // The number of possible outcomes
		int batchSize = 64; // Test batch size
		int nEpochs = 1; // Number of training epochs
		int seed = 123; //
		
		/*
		 * Create an iterator using the batch size for one iteration
		 */
		log.info("Load data....");
		DataSetIterator mnistTrain = new MnistDataSetIterator(batchSize, true, 12345);
		DataSetIterator mnistTest = new MnistDataSetIterator(batchSize, false, 12345);

		/*
		 * Construct the neural network
		 */
		log.info("Build model....");

		MultiLayerConfiguration conf = new NeuralNetConfiguration.Builder().seed(seed).l2(0.0005)
				.weightInit(WeightInit.XAVIER).updater(new Adam(1e-3)).list().layer(new ConvolutionLayer.Builder(5, 5)
						// nIn and nOut specify depth. nIn here is the nChannels
						// and nOut is the number of filters to be applied
						.nIn(nChannels).stride(1, 1).nOut(20).activation(Activation.IDENTITY).build())
				.layer(new SubsamplingLayer.Builder(PoolingType.MAX).kernelSize(2, 2).stride(2, 2).build())
				.layer(new ConvolutionLayer.Builder(5, 5)
						// Note that nIn need not be specified in later layers
						.stride(1, 1).nOut(50).activation(Activation.IDENTITY).build())
				.layer(new SubsamplingLayer.Builder(PoolingType.MAX).kernelSize(2, 2).stride(2, 2).build())
				.layer(new DenseLayer.Builder().activation(Activation.RELU).nOut(500).build())
				.layer(new OutputLayer.Builder(LossFunctions.LossFunction.NEGATIVELOGLIKELIHOOD).nOut(outputNum)
						.activation(Activation.SOFTMAX).build())
				.setInputType(InputType.convolutionalFlat(28, 28, 1)) // See
																		// note
																		// below
				.build();
		
		MultiLayerNetwork model = new MultiLayerNetwork(conf);
		model.init();

		log.info("Train model...");
		model.setListeners(new ScoreIterationListener(10),
				new EvaluativeListener(mnistTest, 1, InvocationType.EPOCH_END)); // Print
																					// score
																					// every
																					// 10
																					// iterations
																					// and
																					// evaluate
																					// on
																					// test
																					// set
																					// every
																					// epoch
		model.fit(mnistTrain, nEpochs);

		log.info(model.params().toString());
		System.out.println(model.params());
		log.info(model.summary());
		System.out.println(model.params().length());

		log.info("****************Training finished********************");
		
		OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, null, MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriLocal, ctx);
		OSCoreCoapStackFactory.useAsDefault(db);

		final CoapServer server = new CoapServer(5683);

		OSCoreResource hello = new OSCoreResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello Resource");
				exchange.respond(r);
			}
		};

		OSCoreResource modelResource = new OSCoreResource("model", true) {

			@Override
			public void handlePOST(CoapExchange exchange) {
				byte[] payload = exchange.getRequestPayload();
				System.out.println("Accessing hello/1 resource");
				
			
				Response r = new Response(ResponseCode.CHANGED);
				r.setPayload(model.params().toString());
				log.info(model.params().toString());
				exchange.respond(r);
				server.destroy();
			}
		};

		server.add(hello);
		server.add(modelResource);
		
		server.start();

		
	}

}
