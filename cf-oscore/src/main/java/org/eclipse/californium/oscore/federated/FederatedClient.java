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
 *    Rikard Höglund (RISE SICS) - Group OSCORE sender functionality
 ******************************************************************************/
package org.eclipse.californium.oscore.federated;

import static org.eclipse.californium.oscore.OSCoreEndpointContextInfo.OSCORE_RECIPIENT_ID;

import java.io.File;
import java.io.FileWriter;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.security.Provider;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.Collections;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.MultiKey;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.factory.Nd4j;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;

/**
 * Test sender configured to support multicast requests. Rebased.
 */
public class FederatedClient {

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumMulticast.properties");

	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Multicast Client";

	/**
	 * Maximum message size
	 */
	private static int MAX_MSG_SIZE = 1400;

	/**
	 * Special network configuration defaults handler.
	 */
	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MULTICAST_BASE_MID, 65000);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, MAX_MSG_SIZE);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, MAX_MSG_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, MAX_MSG_SIZE);
		}

	};

	/**
	 * Time to wait before checking for the first time if responses from 80% of
	 * the servers have been received.
	 */
	private static int CHECK1_TIMEOUT = 15000;

	/**
	 * Time to wait before checking for the second time if responses from 80% of
	 * the servers have been received.
	 */
	private static int CHECK2_TIMEOUT = 22000;

	/**
	 * Maximum time to wait for replies to the multicast request
	 */
	private static int FINAL_TIMEOUT = 30000;

	/**
	 * Maximum time to wait for replies when using unicast (one by one)
	 */
	private static final int UNICAST_TIMEOUT = 30000;

	/**
	 * Ratio of servers that need to have responded for the client to stop
	 * listening at the check points
	 */
	private static final double SERVER_RESPONSE_RATIO = 0.8;

	/**
	 * Whether to use Group OSCORE or not.
	 */
	static boolean useGroupOSCORE = true;

	/**
	 * Whether to use OSCORE or not.
	 */
	static boolean useOSCORE = false;

	/**
	 * Use unicast one-by-one to the servers
	 */
	static boolean unicastMode = false;

	/**
	 * Multicast address to send to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	// static InetAddress multicastIP = CoAP.MULTICAST_IPV4;
	static InetAddress multicastIP;

	/**
	 * Port to send to.
	 */
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT;

	/**
	 * Resource to perform request against.
	 */
	static String requestResource = "/model";

	/**
	 * MAX UNFRAGMENTED SIZE parameter for block-wise (block-wise is not used)
	 */
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	/* --- OSCORE Security Context information (sender) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature (EdDSA)
	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;

	// Encryption algorithm for when using Group mode
	private final static AlgorithmID algGroupEnc = AlgorithmID.AES_CCM_16_64_128;

	// Algorithm for key agreement
	private final static AlgorithmID algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] masterSecret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
			0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] masterSalt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };

	private static final int REPLAY_WINDOW = 32;

	private final static byte[] gm_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F6D79736974652E6578616D706C652E636F6D026C67726F75706D616E6167657203781A636F6170733A2F2F646F6D61696E2E6578616D706C652E6F7267041AAB9B154F08A101A4010103272006215820CDE3EFD3BC3F99C9C9EE210415C6CBA55061B5046E963B8A58C9143A61166472");

	private final static byte[] clientSid = new byte[] { (byte) 0xFE };
	private final static byte[] clientPublicKeyBytes = StringUtil.hex2ByteArray(
			"A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
	private static MultiKey clientPublicPrivateKey;
	private static byte[] clientPrivateKeyBytes = new byte[] { (byte) 0x64, (byte) 0x71, (byte) 0x4D, (byte) 0x41,
			(byte) 0xA2, (byte) 0x40, (byte) 0xB6, (byte) 0x1D, (byte) 0x8D, (byte) 0x82, (byte) 0x35, (byte) 0x02,
			(byte) 0x71, (byte) 0x7A, (byte) 0xB0, (byte) 0x88, (byte) 0xC9, (byte) 0xF4, (byte) 0xAF, (byte) 0x6F,
			(byte) 0xC9, (byte) 0x84, (byte) 0x45, (byte) 0x53, (byte) 0xE4, (byte) 0xAD, (byte) 0x4C, (byte) 0x42,
			(byte) 0xCC, (byte) 0x73, (byte) 0x52, (byte) 0x39 };

	private final static byte[] groupIdentifier = new byte[] { 0x44, 0x61, 0x6c }; // GID

	/* --- OSCORE Security Context information --- */

	private static List<INDArray> models = new ArrayList<>();
	private static int MAX_GLOBAL_EPOCHS;
	private static int modelsize = 0;

	// For early stopping
	private static int epochsNoImprovement = 0;
	private final static float CONTINUE_TRESHOLD = 0.005f;
	private final static int NO_IMPROVEMENT_EPOCHS = 5;
	private static boolean stopEarly = false;

	// Variables for storing experimental results
	private static List<Long> epochTimes = new ArrayList<Long>();
	private static Map<String, long[]> rtts = new HashMap<>();
	private static HashMap<String, Float> accuracies = new HashMap<String, Float>();
	private static Map<String, float[]> storedAccuracies = new HashMap<>();

	// For controlling aggregation and model version
	private static int latestModelVersion = -1;
	private static int AGGREGATION_THRESHOLD;
	private static boolean didAggregation = true;
	private static HashMap<String, Boolean> sentInitialRequest = new HashMap<String, Boolean>();

	/**
	 * Main method
	 * 
	 * @param args command line arguments
	 * @throws Exception on setup or message processing failure
	 */
	public static void main(String args[]) throws Exception {

		long start = System.nanoTime();

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		// InstallCryptoProviders.generateCounterSignKey();

		// Parse command line arguments
		HashMap<String, String> cmdArgs = new HashMap<>();

		for (int i = 0; i < args.length; i += 2) {

			if (i + 1 >= args.length) {
				continue;
			}

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
		String multicastStr = null;
		boolean useFederatedLearning = true;
		boolean debugPrint = true;
		try {
			serverCount = Integer.parseInt(cmdArgs.get("--server-count"));
			multicastStr = cmdArgs.getOrDefault("--multicast-ip", "ipv4");
			useGroupOSCORE = Boolean.parseBoolean(cmdArgs.getOrDefault("--group-oscore", "true"));
			useFederatedLearning = Boolean.parseBoolean(cmdArgs.getOrDefault("--federated-learning", "true"));
			useOSCORE = Boolean.parseBoolean(cmdArgs.getOrDefault("--oscore", "false"));
			unicastMode = Boolean.parseBoolean(cmdArgs.getOrDefault("--unicast", "false"));
			MAX_GLOBAL_EPOCHS = Integer.parseInt(cmdArgs.getOrDefault("--max-epochs", "100"));
			debugPrint = Boolean.parseBoolean(cmdArgs.getOrDefault("--debug", "true"));
			modelsize = Integer.parseInt(cmdArgs.getOrDefault("--model-size", "-1"));
		} catch (Exception e) {
			printHelp();
		}

		if (!debugPrint) {
			DebugOut.ENABLE_PRINTING = false;
		}

		// Multicast IP to use
		if (multicastStr.toLowerCase().equals("ipv4")) {
			multicastIP = CoAP.MULTICAST_IPV4;
		} else if (multicastStr.toLowerCase().equals("ipv6")) {
			multicastIP = CoAP.MULTICAST_IPV6_SITELOCAL;
		} else {
			DebugOut.errPrintln("Invalid option for --multicast-ip, must be IPv4 or IPv6");
		}

		if (serverCount == -1) {
			printHelp();
		}

		if (useOSCORE && !unicastMode) {
			DebugOut.println("Invalid config:");
			DebugOut.println("useOSCORE: " + useOSCORE);
			DebugOut.println("unicastMode: " + unicastMode);
			DebugOut.println();
			printHelp();
		}

		if (useGroupOSCORE && unicastMode) {
			DebugOut.println("Invalid config:");
			DebugOut.println("useGroupOSCORE: " + useGroupOSCORE);
			DebugOut.println("unicastMode: " + unicastMode);
			DebugOut.println();
			printHelp();
		}

		// Parse list of IPs for the servers
		List<String> unicastServerIps = new ArrayList<String>();
		if (unicastMode) {
			Pattern ipv4Pattern = Pattern
					.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
			Pattern ipv6Pattern = Pattern.compile("\\A(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\z");

			for (int i = 0; i < args.length; i++) {
				if (ipv4Pattern.matcher(args[i]).matches()) {
					unicastServerIps.add(args[i]);
				}
				if (ipv6Pattern.matcher(args[i]).matches()) {
					unicastServerIps.add(args[i]);
				}
				if (args[i].contains(":")) {
					unicastServerIps.add(args[i]);
				}

			}
		}
		if (unicastMode) {
			CHECK1_TIMEOUT = UNICAST_TIMEOUT / 3;
			CHECK2_TIMEOUT = 2 * (UNICAST_TIMEOUT / 3);
			FINAL_TIMEOUT = UNICAST_TIMEOUT;
		}

		// End parse command line arguments

		// Set threshold for doing aggregation (ceil 40%)
		AGGREGATION_THRESHOLD = (int) Math.ceil(serverCount * 0.40);

		// Set request target when not using federated learning
		if (useFederatedLearning == false) {
			requestResource = "/helloWorld";
		}

		/**
		 * URI to perform request against. Need to check for IPv6 to surround it
		 * with []
		 */
		String requestURI;
		if (multicastIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort + requestResource;
		} else {
			requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort + requestResource;
		}

		// If Group OSCORE is being used set the context information
		if (useGroupOSCORE) {

			// Add private & public keys for sender & receiver(s)
			clientPublicPrivateKey = new MultiKey(clientPublicKeyBytes, clientPrivateKeyBytes);

			byte[] gmPublicKey = gm_public_key_bytes;
			GroupCtx commonCtx = new GroupCtx(masterSecret, masterSalt, alg, kdf, groupIdentifier, algCountersign,
					algGroupEnc, algKeyAgreement, gmPublicKey);

			commonCtx.addSenderCtxCcs(clientSid, clientPublicPrivateKey);
			addGroupServerContexts(commonCtx);

			db.addContext(requestURI, commonCtx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		// If OSCORE is being used set the context information
		if (useOSCORE) {
			addServerContexts(unicastServerIps);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);

		client.setURI(requestURI);

		// Information about the sender
		DebugOut.println("==================");
		DebugOut.println("*Sender");
		DebugOut.println("Uses Group OSCORE: " + useGroupOSCORE);
		DebugOut.println("Uses OSCORE: " + useOSCORE);
		DebugOut.println("Use multicast: " + !unicastMode);
		DebugOut.println("Request destination: " + requestURI);
		DebugOut.println("Request destination port: " + destinationPort);
		DebugOut.println("Outgoing port: " + endpoint.getAddress().getPort());
		DebugOut.println("Total server count: " + serverCount);
		DebugOut.println("Max epochs: " + MAX_GLOBAL_EPOCHS);
		DebugOut.println("Expected model size: " + modelsize);

		if (unicastMode) {
			DebugOut.println("Unicast Server IPs: ");
			for (int i = 0; i < unicastServerIps.size(); i++) {
				DebugOut.println(unicastServerIps.get(i));
			}
		}
		DebugOut.println("==================");

		byte[] prevPayloadReq = null;

		int currentEpoch = 0;
		for (int i = 0; i < MAX_GLOBAL_EPOCHS && stopEarly == false; i++) {

			currentEpoch = i;
			long epochStart = System.nanoTime();

			DebugOut.println("=== Communication Epoch: " + i + " ===");
			Request request = Request.newPost();

			float[] modelReq = new float[0];

			byte[] payloadReq;
			if (i == 0) {
				payloadReq = new byte[0];

				// Append version number to payload
				latestModelVersion++;
				byte[] tempArray = Arrays.copyOf(payloadReq, payloadReq.length + 1);
				tempArray[tempArray.length - 1] = (byte) latestModelVersion;
				payloadReq = Arrays.copyOf(tempArray, tempArray.length);

			} else {

				// If there are more received responses
				if (models.size() > 1) {

					INDArray avgModel = getAverage(models, modelsize);
					modelReq = avgModel.toFloatVector();

				} else if (models.size() == 1) {
					// If there is only one model in the buffer list
					modelReq = models.get(0).toFloatVector();
				} else {
					DebugOut.errPrintln("Error: No model received");
				}

				// Ensure that the model to be sent is valid
				boolean invalidModel = false;
				if (modelReq == null || modelReq.length != modelsize) {
					invalidModel = true;
				}

				if (!didAggregation) {
					DebugOut.errPrintln("Not sending latest model since aggregation was not done!");
				}
				if (invalidModel) {
					DebugOut.errPrintln("Not sending latest model since it is invalid!");
				}

				// Build byte payload to send from float vector
				if (didAggregation == true && invalidModel == false) {
					payloadReq = FloatConverter.floatVectorToBytes(modelReq);
					prevPayloadReq = Arrays.copyOf(payloadReq, payloadReq.length);
					latestModelVersion++;
				} else {
					// Send previous model
					payloadReq = Arrays.copyOf(prevPayloadReq, prevPayloadReq.length);
				}

				// Error checking model size
				if (modelReq.length != modelsize) {
					DebugOut.errPrintln("Invalid model size when sending!");
					DebugOut.errPrintln("Expected model size: " + modelsize + " but sending: " + modelReq.length);
				}

				// Append version number to payload
				byte[] tempArray = Arrays.copyOf(payloadReq, payloadReq.length + 1);
				tempArray[tempArray.length - 1] = (byte) latestModelVersion;
				payloadReq = Arrays.copyOf(tempArray, tempArray.length);

				DebugOut.print("Outgoing request payload: ");
				for (int j = 0; j < modelReq.length; j++) {
					DebugOut.print(modelReq[j] + " ");
				}
				if (payloadReq.length > MAX_MSG_SIZE) {
					DebugOut.errPrintln("Error: Payload exceeds maximum messages size (" + MAX_MSG_SIZE + " bytes)");
				}

				models.clear();

			}

			request.setPayload(payloadReq);
			request.setType(Type.NON);
			if (useGroupOSCORE) {
				// For group mode request
				request.getOptions().setOscore(Bytes.EMPTY);
			}

			// Create handler for responses
			MultiCoapHandler handler = new MultiCoapHandler(serverCount);

			// Either loop and send unicast requests or send 1 multicast
			if (unicastMode) {

				handler.clearResponses();
				Collections.shuffle(unicastServerIps);
				
				for (int n = 0; n < unicastServerIps.size(); n++) {

					// Empty payload for servers being contacted first time
					byte[] emptyPayload = new byte[0];
					// Append version number to payload
					byte[] tempArray2 = Arrays.copyOf(emptyPayload, emptyPayload.length + 1);
					tempArray2[tempArray2.length - 1] = (byte) latestModelVersion;
					emptyPayload = Arrays.copyOf(tempArray2, tempArray2.length);

					// Stop if sufficient servers have responded this epoch
					if (handler.getResponses().size() > serverCount * SERVER_RESPONSE_RATIO) {
						break;
					}

					request = Request.newPost();

					// Use empty request for servers not yet contacted
					if (sentInitialRequest.containsKey(unicastServerIps.get(n)) == false
							|| sentInitialRequest.get(unicastServerIps.get(n)) == false) {
						request.setPayload(emptyPayload);
						sentInitialRequest.put(unicastServerIps.get(n), true);
					} else {
						request.setPayload(payloadReq);
					}

					handler.resumeWaiting(true);

					URI unicastURI;
					if (unicastServerIps.get(n).contains(":")) {
						unicastURI = URI.create("coap://" + "[" + unicastServerIps.get(n) + "]");
					} else {
						unicastURI = URI.create("coap://" + unicastServerIps.get(n));
					}
					requestURI = unicastURI + requestResource;

					if (useOSCORE) {
						request.getOptions().setOscore(Bytes.EMPTY);
					}

					request.setType(Type.NON);
					client = new CoapClient();
					client.setURI(requestURI);
					request.setURI(requestURI);

					DebugOut.println("Sending request to: " + client.getURI());
					DebugOut.println(Utils.prettyPrint(request));
					client.advanced(handler, request);
					while (handler.waitOn(UNICAST_TIMEOUT)) {
						// Wait for responses
					}
				}

			} else {
				// sends a multicast request
				handler.clearResponses();
				DebugOut.println("Sending request to: " + client.getURI());
				DebugOut.println("Sending from: " + client.getEndpoint().getAddress());
				DebugOut.println(Utils.prettyPrint(request));

				client.advanced(handler, request);
				while (handler.waitOn(FINAL_TIMEOUT)) {
					// Wait for responses
				}
			}

			// Print received responses
			List<CoapResponse> responses = handler.getResponses();

			if (responses.size() == 0) {

				DebugOut.errPrintln("ERROR: No Response from servers.");

			}
			
			boolean toBeContinued = false;
			// Ensure to continue if no responses were received this epoch
			if (responses == null || responses.size() == 0) {
				toBeContinued = true;
				didAggregation = false;
			}
			
			for (int j = 0; j < responses.size(); j++) {
				CoapResponse resp = responses.get(j);

				DebugOut.println("=== Response " + (j + 1) + " ===");
				DebugOut.println("Response from from: " + resp.advanced().getSourceContext().getPeerAddress());

				// Error checking
				if (resp.getOptions().getContentFormat() == MediaTypeRegistry.TEXT_PLAIN
						|| resp.getPayloadSize() < 400) {
					DebugOut.println("Ignoring error or insufficiently small message from server");
					DebugOut.println(" === ");
					DebugOut.println(Utils.prettyPrint(resp));
					DebugOut.println(" === ");
					continue;
				}

				// Parse and handle response
				DebugOut.println(Utils.prettyPrint(resp));

				// Parse bytes in response payload into float vector
				byte[] payloadRes = resp.getPayload();
				float[] modelResPre = FloatConverter.bytesToFloatVector(payloadRes);

				// Error checking of model size
				if (modelsize != (modelResPre.length - 1)) {
					DebugOut.errPrintln("Invalid model size received! Ignoring response.");
					DebugOut.errPrintln("Expected model size: " + modelsize + " but received: " + modelResPre.length);
					continue;
				}

				// Retrieve Recipient ID of the server
				EndpointContext responseSourceContext = resp.advanced().getSourceContext();
				String serverRid = responseSourceContext.get(OSCORE_RECIPIENT_ID);

				// Save received bytes and RTT
				if (!rtts.containsKey(serverRid)) {
					rtts.put(serverRid, new long[MAX_GLOBAL_EPOCHS]);
					Arrays.fill(rtts.get(serverRid), -1);
				}
				rtts.get(serverRid)[currentEpoch] = resp.advanced().getApplicationRttNanos();

				// Check for early stopping
				float serverAccuracy = modelResPre[modelResPre.length - 1];
				float lastAccuracy = accuracies.getOrDefault(serverRid, 0f);
				if (serverAccuracy < 0.9 || serverAccuracy - lastAccuracy > CONTINUE_TRESHOLD) {
					toBeContinued = true;
				}
				accuracies.remove(serverRid);
				accuracies.put(serverRid, serverAccuracy);

				// Save accuracies form the servers
				if (!storedAccuracies.containsKey(serverRid)) {
					storedAccuracies.put(serverRid, new float[MAX_GLOBAL_EPOCHS]);
					Arrays.fill(storedAccuracies.get(serverRid), -1);
				}
				storedAccuracies.get(serverRid)[currentEpoch] = serverAccuracy;
				float[] modelRes = new float[modelResPre.length - 1];
				System.arraycopy(modelResPre, 0, modelRes, 0, modelResPre.length - 1);

				DebugOut.println();

				DebugOut.print("Incoming payload in response: ");
				for (int k = 0; k < modelRes.length; k++) {
					DebugOut.print(modelRes[k] + " ");

				}

				if (responses.size() < AGGREGATION_THRESHOLD) {
					// Do not aggregate
					didAggregation = false;
				} else {
					INDArray model = Nd4j.create(modelRes);
					DebugOut.println("Received model size: " + model.length());
					models.add(model);
					didAggregation = true;
				}

			}

			// Check early stopping criteria
			if (epochsNoImprovement >= NO_IMPROVEMENT_EPOCHS) {
				DebugOut.print("Early stopping criteria fulfilled");
				stopEarly = true;
			}

			if (toBeContinued == true) {
				epochsNoImprovement = 0;
			} else {
				// Only count as epoch of no improvement if aggregation happened
				if (didAggregation == true) {
					epochsNoImprovement++;
				}
			}

			long epochEnd = System.nanoTime();
			long epochTotal = epochEnd - epochStart;
			epochTimes.add(epochTotal);

		}

		long finish = System.nanoTime();
		long timeElapsed = finish - start;

		LocalDateTime now = LocalDateTime.now();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd_HHmm");
		String dateString = now.format(formatter);
		String newl = System.getProperty("line.separator");

		/** Write results to file **/
		FileWriter myWriter = new FileWriter(dateString + "-res.txt");
		myWriter.write("Cumulative UDP payload data sent (bytes): " + UDPConnector.getSentPayload() + newl);
		myWriter.write("Cumulative UDP payload data received (bytes): " + UDPConnector.getReceivedPayload() + newl);
		myWriter.write("Time until stop condition (ns): " + timeElapsed + newl);
		myWriter.write("Number of epochs: " + (currentEpoch + 1) + newl + newl);

		myWriter.write("Times for each epoch" + newl);
		for (int i = 0; i < epochTimes.size(); i++) {
			myWriter.write(i + " " + epochTimes.get(i) + newl);
		}
		myWriter.write(newl);

		myWriter.write("RTT" + newl);
		myWriter.write("ID # ns" + newl);
		for (Map.Entry<String, long[]> entry : rtts.entrySet()) {
			String serverId = entry.getKey();
			long[] rttArray = entry.getValue();

			for (int i = 0; i < rttArray.length; i++) {
				String val = Long.toString(rttArray[i]);

				if (rttArray[i] == -1) {
					val = "N/A";
				}

				myWriter.write(serverId + " " + i + " " + val + newl);
			}
		}
		myWriter.write(newl);

		myWriter.write("Server Accuracy" + newl);
		myWriter.write("ID # acc" + newl);
		for (Map.Entry<String, float[]> entry : storedAccuracies.entrySet()) {
			String serverId = entry.getKey();
			float[] accuracyArray = entry.getValue();

			for (int i = 0; i < accuracyArray.length; i++) {
				String val = String.format("%.12f", accuracyArray[i]);

				if (accuracyArray[i] == -1) {
					val = "N/A";
				}

				myWriter.write(serverId + " " + i + " " + val + newl);
			}
		}
		myWriter.write(newl);

		myWriter.close();

	}

	public static INDArray getAverage(List<INDArray> list, int modelsize) {

		INDArray avg = Nd4j.zeros(modelsize);
		for (int i = 0; i < list.size(); i++) {
			INDArray arr = list.get(i);
			DebugOut.println("Model:" + arr);
			avg = avg.add(arr);
		}

		avg = avg.div(list.size());
		DebugOut.println("Updated Model:" + avg);

		return avg;
	}

	/**
	 * Add the Group OSCORE contexts for the servers
	 * 
	 * @param commonCtx the group context
	 * @throws OSException on failure to add contexts
	 */
	private static void addGroupServerContexts(GroupCtx commonCtx) throws OSException {

		for (int i = 0; i < Credentials.serverPublicKeys.size(); i++) {
			MultiKey serverPublicKey = new MultiKey(Credentials.serverPublicKeys.get(i));
			byte[] rid = Credentials.serverSenderIds.get(i);
			DebugOut.println("=== Adding Group OSCORE Server Context for RID " + StringUtil.byteArray2Hex(rid));
			commonCtx.addRecipientCtxCcs(rid, REPLAY_WINDOW, serverPublicKey);
		}

		commonCtx.setResponsesIncludePartialIV(false);
	}

	/**
	 * Add the OSCORE contexts for the servers
	 * 
	 * @throws OSException on failure to add contexts
	 */
	private static void addServerContexts(List<String> unicastServerIps) throws OSException {

		for (int i = 0; i < unicastServerIps.size(); i++) {
			URI unicastURI;
			if (unicastServerIps.get(i).contains(":")) {
				unicastURI = URI.create("coap://" + "[" + unicastServerIps.get(i) + "]");
			} else {
				unicastURI = URI.create("coap://" + unicastServerIps.get(i));
			}
			String requestURI = unicastURI + requestResource;

			byte[] rid = Credentials.serverSenderIds.get(i);
			OSCoreCtx ctx = new OSCoreCtx(masterSecret, false, alg, clientSid, rid, kdf, 32, masterSalt, null,
					MAX_UNFRAGMENTED_SIZE);
			ctx.setResponsesIncludePartialIV(false);
			DebugOut.println("=== Adding OSCORE Server Context for RID " + StringUtil.byteArray2Hex(rid));
			db.addContext(requestURI, ctx);
		}
	}

	/**
	 * Handler for sending requests and receiving responses
	 *
	 */
	private static class MultiCoapHandler implements CoapHandler {

		// Check amount of received responses periodically to stop early
		private int interval1 = CHECK1_TIMEOUT;
		private int interval2 = CHECK2_TIMEOUT - CHECK1_TIMEOUT;
		private int interval3 = FINAL_TIMEOUT - CHECK2_TIMEOUT;

		List<CoapResponse> responses = new ArrayList<CoapResponse>();
		private boolean on;
		int serverCount = 0;
		boolean keepWaiting = true;

		public void resumeWaiting(boolean resume) {
			keepWaiting = resume;
		}

		public MultiCoapHandler(int serverCount) {
			this.serverCount = serverCount;

			if(interval1 == 0 || interval2 == 0 || interval3 == 0) {
				DebugOut.errPrintln("error: invalid wait intervals in handler");
				throw new IllegalArgumentException("Invalid wait intervals in handler");
			}
		}

		public List<CoapResponse> getResponses() {
			return responses;
		}

		public void clearResponses() {
			responses.clear();
		}

		public synchronized boolean waitOn(long timeout) {
			on = false;
			try {

				// First waiting period (split into parts of 10 to stop early if
				// all responses are received)
				for (int i = 0; keepWaiting && i < 10; i++) {
					wait(interval1 / 10);
				}
				if (responses.size() > serverCount * SERVER_RESPONSE_RATIO) {
					keepWaiting = false;
				}

				// Second waiting period
				for (int i = 0; keepWaiting && i < 10; i++) {
					wait(interval2 / 10);
				}
				if (responses.size() > serverCount * SERVER_RESPONSE_RATIO) {
					keepWaiting = false;
				}

				// Final waiting period
				for (int i = 0; keepWaiting && i < 10; i++) {
					wait(interval3 / 10);
				}
				if (responses.size() > serverCount * SERVER_RESPONSE_RATIO) {
					keepWaiting = false;
				}

			} catch (InterruptedException e) {
				//
			}
			return on;
		}

		private synchronized void on() {
			on = true;
			notifyAll();
		}

		/**
		 * Handle and parse incoming responses.
		 */
		@Override
		public void onLoad(CoapResponse response) {
			on();

			// Add response to list of responses
			responses.add(response);

			// Stop waiting if all servers have responded
			if (responses.size() == serverCount || unicastMode) {
				keepWaiting = false;
			}
		}

		@Override
		public void onError() {
			DebugOut.errPrintln("error");
		}
	}

	private static void printHelp() {
		System.out.println("Arguments: ");
		System.out.println("--server-count: Total number of servers [Mandatory.]");
		System.out.println("--model-size: The size of the model. [Mandatory.]");
		System.out.println("--federated-learning: Use Federated Learning [Optional. Default: true]");
		System.out.println("--group-oscore: Use Group OSCORE [Optional. Default: true]");
		System.out.println("--multicast-ip: IPv4 or IPv6 [Optional. Default: ipv4]");
		System.out.println("--oscore: Use OSCORE [Optional. Default: false]");
		System.out.println("--unicast: Use unicast one-by-one to the servers [Optional. Default: false]");
		System.out.println("--max-epochs: Stop the training after this many epochs [Optional. Default: 100]");
		System.out.println("--debug: Enable/disable debug printing [Optional. Default: true]");
		System.exit(1);
	}

	public static final String DATE_FORMAT_NOW = "yyyy-MM-dd_HH-mm-ss";

	public static String now() {
		Calendar cal = Calendar.getInstance();
		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);
		return sdf.format(cal.getTime());
	}

}
