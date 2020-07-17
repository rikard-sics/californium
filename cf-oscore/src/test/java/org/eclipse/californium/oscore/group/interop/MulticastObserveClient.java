/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 * 
 * Contributors: 
 *    Rikard Höglund (RISE SICS) - testing Observe messages
 ******************************************************************************/
package org.eclipse.californium.oscore.group.interop;


import java.io.File;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.Provider;
import java.security.Security;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.GroupCtx;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;

public class MulticastObserveClient {

	static boolean useOSCORE = true;

	/* --- OSCORE Security Context information (sender) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature (EdDSA)
	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };

	private static final int REPLAY_WINDOW = 32;

	/*
	 * Rikard: Note regarding countersignature keys. The sid_private_key
	 * contains both the public and private keys. The rid*_public_key contains
	 * only the public key. For information on the keys see the Countersign_Keys
	 * file.
	 */

	private final static byte[] sid = new byte[] { 0x25 };
	private final static String sid_private_key_string = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";
	private static OneKey sid_private_key;

	private final static byte[] rid1 = new byte[] { 0x52 }; // Recipient 1
	private final static String rid1_public_key_string = "pAMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0Yzib";
	private static OneKey rid1_public_key;

	private final static byte[] rid2 = new byte[] { 0x77 }; // Recipient 2
	private final static String rid2_public_key_string = "pAMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bou";
	private static OneKey rid2_public_key;

	private final static byte[] rid0 = new byte[] { (byte) 0xCC }; // Dummy

	private final static byte[] group_identifier = new byte[] { 0x44, 0x61, 0x6c }; // GID

	/* --- OSCORE Security Context information --- */

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
	@SuppressWarnings("unused")
	private static final int HANDLER_TIMEOUT = 2000;

	/**
	 * Multicast address to send to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	/**
	 * Port to send to.
	 */
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT;

	// private static int cancelAfterMessages = 20;

	public static void main(String[] args)
			throws InterruptedException, ConnectorException, IOException, CoseException, OSException {

		String resourceUri = "/base/observe2";

		/**
		 * URI to perform request against. Need to check for IPv6 to surround it
		 * with []
		 */
		String requestURI;
		if (multicastIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort + resourceUri;
		} else {
			requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort + resourceUri;
		}

		// If OSCORE is being used
		if (useOSCORE) {

			// Install cryptographic providers
			Provider EdDSA = new EdDSASecurityProvider();
			Security.insertProviderAt(EdDSA, 0);

			// Add private & public keys for sender & receiver(s)
			sid_private_key = new OneKey(
					CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary((sid_private_key_string))));
			rid1_public_key = new OneKey(
					CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary((rid1_public_key_string))));
			rid2_public_key = new OneKey(
					CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary((rid2_public_key_string))));

			GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign);

			commonCtx.addSenderCtx(sid, sid_private_key);

			commonCtx.addRecipientCtx(rid0, REPLAY_WINDOW, null);
			commonCtx.addRecipientCtx(rid1, REPLAY_WINDOW, rid1_public_key);
			commonCtx.addRecipientCtx(rid2, REPLAY_WINDOW, rid2_public_key);

			commonCtx.setResponsesIncludePartialIV(true);
			commonCtx.setResponsesIncludePartialIV(true);

			db.addContext(requestURI, commonCtx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		testObserve(requestURI);
	}

	/**
	 * Tests Observe functionality. Registers to a resource and listens for 10
	 * notifications. After this the observation is cancelled.
	 * 
	 * @throws InterruptedException if sleep fails
	 */
	public static void testObserve(String requestURI)
			throws InterruptedException, ConnectorException, IOException, CoseException, OSException {

		// Configure client
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		CoapClient client = new CoapClient();
		client.setEndpoint(endpoint);
		client.setURI(requestURI);

		// // Handler for Observe responses
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

		// Create request and initiate Observe relationship
		byte[] token = new byte[8];
		new Random().nextBytes(token);

		Request r = Request.newGet();
		if (useOSCORE) {
			r.getOptions().setOscore(Bytes.EMPTY);
		}
		r.setURI(requestURI);
		r.setType(Type.NON);
		r.setToken(token);
		r.setObserve();

		// Normal way to start observations (for unicast):
		// @SuppressWarnings("unused")
		// CoapObserveRelation relation = client.observe(r, handler);

		// Start observation with an ObserveHandler:
		// ObserveHandler handler = new ObserveHandler();
		// client.advanced(handler, r);

		// Also works to start it with a MultiCoapHandler:
		client.advanced(handlerMulti, r);
		while (handlerMulti.waitOn(HANDLER_TIMEOUT)) {
			;
		}
		
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

		// Now cancel the Observe and wait for the final response
		// r = createClientRequest(Code.GET, resourceUri);
		// r.setToken(token);
		// r.getOptions().setObserve(1); // Deregister Observe
		// r.send();
		//
		// Response resp = r.waitForResponse(1000);
		//
		// String content = resp.getPayloadString();
		// System.out.println("Response (last): " + content);

		client.shutdown();
	}

	private static final MultiCoapHandler handlerMulti = new MultiCoapHandler();

	private static class MultiCoapHandler implements CoapHandler {

		private boolean on;

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

			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	};

}
