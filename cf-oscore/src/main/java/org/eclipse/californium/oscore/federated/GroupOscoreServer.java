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

import java.io.IOException;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.Provider;
import java.security.Security;
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
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.learning.config.Adam;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

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

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test receiver using {@link UdpMulticastConnector}.
 */
public class GroupOscoreServer {

	private static final Logger LOGGER = LoggerFactory.getLogger(GroupOscoreServer.class);

	/**
	 * Maximum message size
	 */
	private static int MAX_MSG_SIZE = 1400;

	/**
	 * Maximum size of vectors to send (so it fits in the message). It seems
	 * every number takes around 6 bytes on average
	 */
	private static int MAX_VECTOR_SIZE = MAX_MSG_SIZE / 6;

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
	 * Whether to use OSCORE or not.
	 */
	static final boolean useOSCORE = true;

	/**
	 * Give the receiver a random unicast IP (from the loopback 127.0.0.0/8
	 * range) FIXME: Communication does not work with this turned on
	 */
	static final boolean randomUnicastIP = false;

	/**
	 * Multicast address to listen to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	// Use IPv4
	private static boolean ipv4 = true;
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

	private final static byte[] clientRid = new byte[] { 0x25 };
	private final static byte[] clientPublicKeyBytes = StringUtil.hex2ByteArray(
			"A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
	private static MultiKey clientPublicKey;

	private final static byte[] groupIdentifier = new byte[] { 0x44, 0x61, 0x6c }; // GID

	/* --- OSCORE Security Context information --- */

	private static Random random;

	static MultiLayerNetwork model;

	/**
	 * Main method
	 * 
	 * @param args command line arguments
	 * @throws Exception on setup or message processing failure
	 */
	public static void main(String[] args) throws Exception {

		int nChannels = 1; // Number of input channels
		int outputNum = 10; // The number of possible outcomes
		int batchSize = 64; // Test batch size
		int nEpochs = 1; // Number of training epochs
		int seed = 123; //

		/*
		 * Create an iterator using the batch size for one iteration
		 */
		LOGGER.info("Load data....");
		DataSetIterator mnistTrain = new MnistDataSetIterator(batchSize, true, 12345);
		DataSetIterator mnistTest = new MnistDataSetIterator(batchSize, false, 12345);

		/*
		 * Construct the neural network
		 */
		LOGGER.info("Build model....");

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

		model = new MultiLayerNetwork(conf);
		model.init();

		LOGGER.info("Train model...");
		// Print score every 10 iterations and evaluate on test set every epoch
		model.setListeners(new ScoreIterationListener(10),
				new EvaluativeListener(mnistTest, 1, InvocationType.EPOCH_END));

		model.fit(mnistTrain, nEpochs);

		LOGGER.info(model.params().toString());
		System.out.println(model.params());
		LOGGER.info(model.summary());
		System.out.println(model.params().length());

		LOGGER.info("****************Training finished********************");

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		// Set sender & receiver keys for countersignatures
		clientPublicKey = new MultiKey(clientPublicKeyBytes);

		// Check command line arguments (integer representing a server to run)
		MultiKey serverPublicPrivateKey = null;
		int serverNr;
		if (args.length == 0) {
			serverNr = 0;
		} else {
			serverNr = Integer.parseInt(args[0].replace("-", ""));
		}
		unicastPort = unicastPort + serverNr;
		sid = Credentials.serverSenderIds.get(serverNr);
		serverPublicKey = Credentials.serverPublicKeys.get(serverNr);
		serverPrivateKey = Credentials.serverPrivateKeys.get(serverNr);
		serverPublicPrivateKey = new MultiKey(serverPublicKey, serverPrivateKey);
		System.out.println("Starting with SID " + StringUtil.byteArray2Hex(sid));

		// If OSCORE is being used set the context information
		if (useOSCORE) {

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
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Respond to non-confirmable messages: " + replyToNonConfirmable);
		System.out.println("Listening to Multicast IP: " + multicastIP.getHostAddress());
		System.out.println("Unicast IP: " + endpoint.getAddress().getHostString());
		System.out.println("Unicast port: " + endpoint.getAddress().getPort());
		System.out.println("Multicast port: " + listenPort);
		System.out.print("CoAP resources: ");
		for (Resource res : server.getRoot().getChildren()) {
			System.out.print(res.getURI() + " ");
		}
		System.out.println("");
		System.out.println("==================");

		server.start();
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
			CBORObject arrayReq = CBORObject.DecodeFromBytes(payloadReq);
			float[] modelReq = new float[arrayReq.size()];

			System.out.print("Incoming payload: ");
			for (int i = 0; i < arrayReq.size(); i++) {
				modelReq[i] = arrayReq.get(i).AsSingle();
				System.out.print(modelReq[i] + " ");

			}
			System.out.println();

			// Train
			float[] modelRes = null;

			// Create response
			Response r = new Response(ResponseCode.CHANGED);

			modelRes = model.params().toFloatVector();

			CBORObject arrayRes = CBORObject.NewArray();
			System.out.print("Outgoing payload: ");
			for (int i = 0; i < modelRes.length && i < MAX_VECTOR_SIZE; i++) {
				arrayRes.Add(modelRes[i]);
				System.out.print(modelRes[i] + " ");
			}
			System.out.println();

			byte[] payloadRes = arrayRes.EncodeToBytes();
			System.out.println("Payload Length: " + payloadRes.length);
			if (payloadRes.length > MAX_MSG_SIZE) {
				System.err.println("Too large payload in response!");
			}
			r.setPayload(payloadRes);

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
}
