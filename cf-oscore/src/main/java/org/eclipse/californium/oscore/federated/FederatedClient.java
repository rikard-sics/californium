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

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
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
	private static final int UNICAST_TIMEOUT = 5000;

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
	private static int commuEpoch = 50;
	private static int modelsize = 0;

	/**
	 * Main method
	 * 
	 * @param args command line arguments
	 * @throws Exception on setup or message processing failure
	 */
	public static void main(String args[]) throws Exception {

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
		try {
			serverCount = Integer.parseInt(cmdArgs.get("--server-count"));
			multicastStr = cmdArgs.getOrDefault("--multicast-ip", "ipv4");
			useGroupOSCORE = Boolean.parseBoolean(cmdArgs.getOrDefault("--group-oscore", "true"));
			useFederatedLearning = Boolean.parseBoolean(cmdArgs.getOrDefault("--federated-learning", "true"));
			useOSCORE = Boolean.parseBoolean(cmdArgs.getOrDefault("--oscore", "false"));
			unicastMode = Boolean.parseBoolean(cmdArgs.getOrDefault("--unicast", "false"));
		} catch (Exception e) {
			printHelp();
		}

		// Multicast IP to use
		if (multicastStr.toLowerCase().equals("ipv4")) {
			multicastIP = CoAP.MULTICAST_IPV4;
		} else if (multicastStr.toLowerCase().equals("ipv6")) {
			multicastIP = CoAP.MULTICAST_IPV6_SITELOCAL;
		} else {
			System.err.println("Invalid option for --multicast-ip, must be IPv4 or IPv6");
		}

		if (serverCount == -1) {
			printHelp();
		}

		if (useOSCORE && !unicastMode) {
			System.out.println("Invalid config:");
			System.out.println("useOSCORE: " + useOSCORE);
			System.out.println("unicastMode: " + unicastMode);
			System.out.println();
			printHelp();
		}

		if (useGroupOSCORE && unicastMode) {
			System.out.println("Invalid config:");
			System.out.println("useGroupOSCORE: " + useGroupOSCORE);
			System.out.println("unicastMode: " + unicastMode);
			System.out.println();
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
			}
		}
		if (unicastMode) {
			CHECK1_TIMEOUT = UNICAST_TIMEOUT;
			CHECK2_TIMEOUT = UNICAST_TIMEOUT;
			FINAL_TIMEOUT = UNICAST_TIMEOUT;
		}

		// End parse command line arguments

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
		System.out.println("==================");
		System.out.println("*Sender");
		System.out.println("Uses Group OSCORE: " + useGroupOSCORE);
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Use multicast: " + !unicastMode);
		System.out.println("Request destination: " + requestURI);
		System.out.println("Request destination port: " + destinationPort);
		System.out.println("Outgoing port: " + endpoint.getAddress().getPort());
		System.out.println("Total server count: " + serverCount);

		if (unicastMode) {
			System.out.println("Unicast Server IPs: ");
			for (int i = 0; i < unicastServerIps.size(); i++) {
				System.out.println(unicastServerIps.get(i));
			}
		}
		System.out.println("==================");

		for (int i = 0; i <= commuEpoch; i++) {

			System.out.println("=== Communication Epoch: " + i + " ===");
			Request request = Request.newPost();

			float[] modelReq = null;

			byte[] payloadReq;
			if (i == 0) {
				payloadReq = new byte[0];

			} else {

				// If there are more received clients
				if (models.size() > 1) {

					INDArray avgModel = getAverage(models, modelsize);
					modelReq = avgModel.toFloatVector();

				} else if (models.size() == 1) {
					// If there is only one model in the buffer list
					modelReq = models.get(0).toFloatVector();
				} else {
					System.err.println("Error: No model received");
				}

				// Build byte payload to send from float vector
				payloadReq = FloatConverter.floatVectorToBytes(modelReq);

				System.out.print("Outgoing request payload: ");
				for (int j = 0; j < modelReq.length; j++) {
					System.out.print(modelReq[j] + " ");
				}
				if (payloadReq.length > MAX_MSG_SIZE) {
					System.err.println("Error: Payload exceeds maximum messages size (" + MAX_MSG_SIZE + " bytes)");
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

				for (int n = 0; n < unicastServerIps.size(); n++) {
					URI unicastURI;
					if (unicastServerIps.get(n).contains(":")) {
						unicastURI = URI.create("coap://" + "[" + unicastServerIps.get(n) + "]");
					} else {
						unicastURI = URI.create("coap://" + unicastServerIps.get(n));
					}
					requestURI = unicastURI + requestResource;

					request = Request.newPost();
					if (useOSCORE) {
						request.getOptions().setOscore(Bytes.EMPTY);
					}
					request.setPayload(payloadReq);
					request.setType(Type.NON);
					client = new CoapClient();
					client.setURI(requestURI);
					request.setURI(requestURI);

					System.out.println("Sending request to: " + client.getURI());
					System.out.println(Utils.prettyPrint(request));
					client.advanced(handler, request);
					while (handler.waitOn(UNICAST_TIMEOUT)) {
						// Wait for responses
					}
				}

			} else {
				// sends a multicast request
				handler.clearResponses();
				System.out.println("Sending request to: " + client.getURI());
				System.out.println("Sending from: " + client.getEndpoint().getAddress());
				System.out.println(Utils.prettyPrint(request));

				client.advanced(handler, request);
				while (handler.waitOn(FINAL_TIMEOUT)) {
					// Wait for responses
				}
			}

			// Print received responses
			List<CoapResponse> responses = handler.getResponses();

			if (responses.size() == 0) {

				System.err.println("ERROR: No Response from servers.");

			}
			for (int j = 0; j < responses.size(); j++) {
				CoapResponse resp = responses.get(j);

				System.out.println("=== Response " + (j + 1) + " ===");
				System.out.println("Response from from: " + resp.advanced().getSourceContext().getPeerAddress());

				// Parse and handle response
				System.out.println(Utils.prettyPrint(resp));
				// System.out.println("Payload: " + resp.getResponseText());

				byte[] payloadRes = resp.getPayload();

				// Parse bytes in response payload into float vector
				float[] modelRes = FloatConverter.bytesToFloatVector(payloadRes);

				System.out.println();

				System.out.print("Incoming payload in response: ");
				for (int k = 0; k < modelRes.length; k++) {
					System.out.print(modelRes[k] + " ");

				}

				INDArray model = Nd4j.create(modelRes);
				System.out.println(model.length());
				modelsize = (int) model.length();
				models.add(model);
			}

		}

	}

	public static INDArray getAverage(List<INDArray> list, int modelsize) {

		INDArray avg = Nd4j.zeros(modelsize);
		for (int i = 0; i < list.size(); i++) {
			INDArray arr = list.get(i);
			System.out.println("Model:" + arr);
			avg = avg.add(arr);
		}

		avg = avg.div(list.size());
		System.out.println("Updated Model:" + avg);

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
			System.out.println("=== Adding Group OSCORE Server Context for RID " + StringUtil.byteArray2Hex(rid));
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
			System.out.println("=== Adding OSCORE Server Context for RID " + StringUtil.byteArray2Hex(rid));
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

		public MultiCoapHandler(int serverCount) {
			this.serverCount = serverCount;
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

			// FIXME: Check that response is semantically valid. And only accept
			// one response from each server.

			// Add response to list of responses
			responses.add(response);

			// Stop waiting if all servers have responded
			if (responses.size() == serverCount || unicastMode) {
				keepWaiting = false;
			}
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	}

	private static void printHelp() {
		System.out.println("Arguments: ");
		System.out.println("--server-count: Total number of servers");
		System.out.println("--federated-learning: Use Federated Learning [Optional. Default: true]");
		System.out.println("--group-oscore: Use Group OSCORE [Optional. Default: true]");
		System.out.println("--multicast-ip: IPv4 or IPv6 [Optional. Default: ipv4]");
		System.out.println("--oscore: Use OSCORE [Optional. Default: false]");
		System.out.println("--unicast: Use unicast one-by-one to the servers [Optional. Default: false]");
		System.exit(1);
	}

}
