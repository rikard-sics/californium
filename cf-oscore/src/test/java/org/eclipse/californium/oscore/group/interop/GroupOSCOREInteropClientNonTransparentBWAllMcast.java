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
package org.eclipse.californium.oscore.group.interop;

import static org.junit.Assert.assertArrayEquals;

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.GroupRecipientCtx;
import org.eclipse.californium.oscore.group.GroupSenderCtx;
import org.eclipse.californium.oscore.group.OneKeyDecoder;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test sender configured to support multicast requests.
 */
public class GroupOSCOREInteropClientNonTransparentBWAllMcast {

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumMulticast.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Multicast Client";
	/**
	 * Special network configuration defaults handler.
	 */
	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MULTICAST_BASE_MID, 65000);
		}

	};

	/**
	 * Time to wait for replies to the multicast request
	 */
	private static final int HANDLER_TIMEOUT = 800;

	/**
	 * Whether to use OSCORE or not. (Case 1)
	 */
	static final boolean useOSCORE = false;

	/**
	 * Whether to use Group OSCORE or normal OSCORE.
	 */
	static final boolean GroupOSCORE = false;

	/**
	 * Multicast address to send to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	static final InetAddress destinationIP = CoAP.MULTICAST_IPV4;
	// static final InetAddress destinationIP = new
	// InetSocketAddress("127.0.0.1", 0).getAddress();

	/**
	 * Port to send to.
	 */
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT;

	/**
	 * Resource to perform request against.
	 */
	// static final String requestResource = "/test";
	static final String requestResource = "/oscore/hello/bw";

	/**
	 * The method to use for the request. (Should be GET)
	 */
	static final CoAP.Code requestMethod = CoAP.Code.GET;

	/* --- OSCORE Security Context information (sender) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature
	private final static AlgorithmID algCountersign = AlgorithmID.ECDSA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = InteropParametersNew.RIKARD_MASTER_SECRET_ECDSA;
	private final static byte[] master_salt = InteropParametersNew.RIKARD_MASTER_SALT_ECDSA;

	private static final int REPLAY_WINDOW = 32;

	// Public and private keys for group members
	private final static byte[] sid = InteropParametersNew.RIKARD_ENTITY_3_KID_ECDSA;
	private static OneKey sid_private_key;

	private final static byte[] rid1 = InteropParametersNew.RIKARD_ENTITY_1_KID_ECDSA;
	private static OneKey rid1_public_key;

	private final static byte[] rid2 = InteropParametersNew.RIKARD_ENTITY_2_KID_ECDSA;
	private static OneKey rid2_public_key;

	private final static byte[] rid0 = new byte[] { (byte) 0xCC }; // Dummy

	private final static byte[] group_identifier = InteropParametersNew.RIKARD_GROUP_ID_ECDSA;

	/* --- OSCORE Security Context information --- */

	/**
	 * Payload in request sent (POST)
	 */
	static final String requestPayload = "Post from " + Utils.toHexString(sid);

	public static void main(String args[]) throws Exception {

		// Disable replay detection
		OSCoreCtx.DISABLE_REPLAY_CHECKS = true;

		/**
		 * URI to perform request against. Need to check for IPv6 to surround it
		 * with []
		 */
		String requestURI;
		if (destinationIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + destinationIP.getHostAddress() + "]" + ":" + destinationPort + requestResource;
		} else {
			requestURI = "coap://" + destinationIP.getHostAddress() + ":" + destinationPort + requestResource;
		}

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);
		// InstallCryptoProviders.generateCounterSignKey();

		// Add private & public keys for sender & receiver(s)
		sid_private_key = OneKeyDecoder.parseDiagnostic(InteropParametersNew.RIKARD_ENTITY_3_KEY_ECDSA);
		rid1_public_key = OneKeyDecoder.parseDiagnostic(InteropParametersNew.RIKARD_ENTITY_1_KEY_ECDSA);
		rid2_public_key = OneKeyDecoder.parseDiagnostic(InteropParametersNew.RIKARD_ENTITY_2_KEY_ECDSA);

		// Check that KIDs in public/private keys match corresponding
		// recipient/sender ID (just to double check configuration)
		assertArrayEquals(sid, sid_private_key.get(KeyKeys.KeyId).GetByteString());
		assertArrayEquals(rid1, rid1_public_key.get(KeyKeys.KeyId).GetByteString());
		assertArrayEquals(rid2, rid2_public_key.get(KeyKeys.KeyId).GetByteString());

		// If OSCORE is being used set the context information
		@SuppressWarnings("unused")
		GroupSenderCtx senderCtx;
		@SuppressWarnings("unused")
		GroupRecipientCtx recipient1Ctx;
		@SuppressWarnings("unused")
		GroupRecipientCtx recipient2Ctx;
		if (useOSCORE) {

			GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign);

			commonCtx.addSenderCtx(sid, sid_private_key);

			commonCtx.addRecipientCtx(rid0, REPLAY_WINDOW, null);
			commonCtx.addRecipientCtx(rid1, REPLAY_WINDOW, rid1_public_key);
			commonCtx.addRecipientCtx(rid2, REPLAY_WINDOW, rid2_public_key);

			// commonCtx.setResponsesIncludePartialIV(true);
			// commonCtx.setResponsesIncludePartialIV(true);

			if (GroupOSCORE) {
				System.out.println("Using Group OSCORE!");
				db.addContext(requestURI, commonCtx);
			} else {
				// Add instead a normal OSCORE context
				System.out.println("Using standard OSCORE!");
				addOSCOREContext(requestURI);
			}

			OSCoreCoapStackFactory.useAsDefault(db);

			// Retrieve the sender and recipient contexts
			if (GroupOSCORE) {
				senderCtx = (GroupSenderCtx) db.getContext(requestURI);
				recipient1Ctx = (GroupRecipientCtx) db.getContext(rid1, group_identifier);
				recipient2Ctx = (GroupRecipientCtx) db.getContext(rid2, group_identifier);
			}

			// --- Test cases ---
			// Case 3: Add key for the recipient for dynamic derivation
			// Comment out context addition above
			// commonCtx.addPublicKeyForRID(rid1, rid1_public_key);

			// Case 6: Server request decryption failure
			// senderCtx.setSenderKey(new byte[16]);

			// Case 8: Server request signature failure
			// senderCtx.setAsymmetricSenderKey(OneKey.generateKey(algCountersign));


		}

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);

		client.setURI(requestURI);

		// Information about the sender
		System.out.println("==================");
		System.out.println("*Interop sender");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Request destination: " + requestURI);
		System.out.println("Request destination port: " + destinationPort);
		System.out.println("Using multicast: " + destinationIP.isMulticastAddress());
		// System.out.println("Request method: " + multicastRequest.getCode());
		System.out.println("Request payload: " + requestPayload);
		System.out.println("Outgoing port: " + endpoint.getAddress().getPort());
		System.out.println("==================");

		try {
			String host = new URI(client.getURI()).getHost();
			int port = new URI(client.getURI()).getPort();
			System.out.println("Sending to: " + host + ":" + port);
		} catch (URISyntaxException e) {
			System.err.println("Failed to parse destination URI");
			e.printStackTrace();
		}
		System.out.println("Sending from: " + client.getEndpoint().getAddress());

		
		// //If observe is to be used
		// if (requestURI.endsWith("observe")) {
		// multicastRequest.setObserve();
		// }
		
		/* === Sends the initial multicast request */
		int blockSize = 0;
		HashMap<String, String> returnedPayloads = new HashMap<String, String>();

		Request multicastRequest = null;
		if (requestMethod == Code.POST) {
			multicastRequest = Request.newPost();
			multicastRequest.setPayload(requestPayload);
		} else if (requestMethod == Code.GET) {
			multicastRequest = Request.newGet();
		}

		// Use non-confirmable for multicast requests
		if (destinationIP.isMulticastAddress()) {
			multicastRequest.setType(Type.NON);
		} else {
			multicastRequest.setType(Type.CON);
		}

		if (useOSCORE) {
			multicastRequest.getOptions().setOscore(Bytes.EMPTY);
			// For pairwise request:
			// multicastRequest.getOptions().setOscore(OptionEncoder.set(true,
			// requestURI, rid2));
		}
		System.out.println("Initial Multicast Request:");
		System.out.println(Utils.prettyPrint(multicastRequest));

		client.advanced(handler, multicastRequest);
		while (handler.waitOn(HANDLER_TIMEOUT)) {
			// Wait for responses
		}

		// Save responses
		List<CoapResponse> responses = handler.getResponses();
		for (int i = 0; i < responses.size(); i++) {
			String senderAddress = responses.get(i).advanced().getSourceContext().toString();
			String responsePayload = responses.get(i).getResponseText();
			returnedPayloads.put(senderAddress, responsePayload);
		}

		// Set the block size based on the responses
		blockSize = responses.get(0).getOptions().getBlock2().getSize();
		System.out.println("Block size of first response: " + blockSize);

		// Understand the full size of the resource
		int nrOfBlocks = (responses.get(0).getOptions().getSize2() / blockSize) + 1;

		// Calculate szx
		int power = (int) (Math.log(blockSize) / Math.log(2));
		int szx = power - 4;

		/* === Now send the follow-up multicast requests */

		// Loop over the block to retrieve
		for (int block = 1; block < nrOfBlocks; block++) {

			multicastRequest = null;
			if (requestMethod == Code.POST) {
				multicastRequest = Request.newPost();
				multicastRequest.setPayload(requestPayload);
			} else if (requestMethod == Code.GET) {
				multicastRequest = Request.newGet();
			}

			// Use non-confirmable for multicast requests
			if (destinationIP.isMulticastAddress()) {
				multicastRequest.setType(Type.NON);
			} else {
				multicastRequest.setType(Type.CON);
			}

			if (useOSCORE) {
				multicastRequest.getOptions().setOscore(Bytes.EMPTY);
			}

			// Apply block option
			multicastRequest.getOptions().setBlock2(szx, false, block);

			System.out.println("Follow up Multicast Request:");
			System.out.println(Utils.prettyPrint(multicastRequest));

			handler.clearResponses();
			client.advanced(handler, multicastRequest);
			while (handler.waitOn(HANDLER_TIMEOUT)) {
				// Wait for responses
			}

			// Save response payloads
			responses = handler.getResponses();
			for (int i = 0; i < responses.size(); i++) {
				String senderAddress = responses.get(i).advanced().getSourceContext().toString();
				String responsePayload = responses.get(i).getResponseText();
				String payloadSoFar = returnedPayloads.get(senderAddress);
				returnedPayloads.put(senderAddress, payloadSoFar + responsePayload);
			}

		}

		// Print all payloads
		System.out.println("Full payloads: ");
		Iterator<?> it = returnedPayloads.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<?, ?> pair = (Map.Entry<?, ?>) it.next();
			System.out.println(pair.getKey() + " =\r\n" + pair.getValue());
			it.remove(); // avoids a ConcurrentModificationException
		}

		/** Case 9: Client sends replay **/
		// senderCtx.setSenderSeq(0);
		// multicastRequest = Request.newPost();
		// multicastRequest.setPayload(requestPayload);
		// multicastRequest.setType(Type.NON);
		// multicastRequest.getOptions().setOscore(Bytes.EMPTY);
		// client.advanced(handler, multicastRequest);
		// while (handler.waitOn(HANDLER_TIMEOUT)) {
		// // Wait for responses
		// }

		// // Start observation with an ObserveHandler:
		//
		// class ObserveHandler implements CoapHandler {
		//
		// int count = 1;
		// int abort = 0;
		//
		// // Triggered when a Observe response is received
		// @Override
		// public void onLoad(CoapResponse response) {
		// abort++;
		//
		// String content = response.getResponseText();
		// System.out.println("NOTIFICATION (#" + count + "): " + content);
		//
		// count++;
		// }
		//
		// @Override
		// public void onError() {
		// System.err.println("Observing failed");
		// }
		// }
		//
		// int cancelAfterMessages = 10;
		// multicastRequest.setObserve();
		// ObserveHandler handler = new ObserveHandler();
		// client.advanced(handler, multicastRequest);
		//
		// // Wait until a certain number of messages have been received
		// while (handler.count <= cancelAfterMessages) {
		// Thread.sleep(550);
		//
		// // Failsafe to abort test if needed
		// if (handler.abort > cancelAfterMessages + 10) {
		// System.exit(0);
		// break;
		// }
		// }

	}

	private static final MultiCoapHandler handler = new MultiCoapHandler();

	private static class MultiCoapHandler implements CoapHandler {

		List<CoapResponse> responses = new ArrayList<CoapResponse>();

		private boolean on;

		public List<CoapResponse> getResponses() {
			return responses;
		}

		public void clearResponses() {
			responses.clear();
		}

		public synchronized boolean waitOn(long timeout) {
			on = false;
			try {
				wait(timeout);
			} catch (InterruptedException e) {
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

			// System.out.println("Receiving to: "); //TODO
			System.out.println("Receiving from: " + response.advanced().getSourceContext().getPeerAddress());

			responses.add(response);
			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	}

	/**
	 * Add an OSCORE Context to the DB (OSCORE RFC C.2.2.)
	 */
	static OSCoreCtx oscoreCtx;
	private static void addOSCOREContext(String requestURI) {
		byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				0x0f, 0x10 };
		byte[] master_salt = null;
		byte[] rid = new byte[] { 0x01 };
		byte[] sid = new byte[] { 0x00 };
		byte[] id_context = null;

		try {
			oscoreCtx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, id_context);
			// oscoreCtx.setResponsesIncludePartialIV(true);
			db.addContext(requestURI, oscoreCtx);
		} catch (OSException e) {
			System.err.println("Failed to add OSCORE context!");
			e.printStackTrace();
		}
	}
}
