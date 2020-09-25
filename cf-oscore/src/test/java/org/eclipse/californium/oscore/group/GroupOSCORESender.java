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
package org.eclipse.californium.oscore.group;

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.security.Security;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;

/**
 * Test sender configured to support multicast requests.
 * Rebased.
 */
public class GroupOSCORESender {

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
	private static final int HANDLER_TIMEOUT = 2000;

	/**
	 * Whether to use OSCORE or not.
	 */
	static final boolean useOSCORE = true;

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

	/**
	 * Resource to perform request against.
	 */
	static final String requestResource = "/helloWorld";

	/**
	 * Payload in request sent (POST)
	 */
	static final String requestPayload = "test";

	/**
	 * ED25519 curve value.
	 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
	 */
	// static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); //Integer value
	// 6

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

	public static void main(String args[]) throws Exception {
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

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);
		// InstallCryptoProviders.generateCounterSignKey();

		// Add private & public keys for sender & receiver(s)
		sid_private_key = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary((sid_private_key_string))));
		rid1_public_key = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary((rid1_public_key_string))));
		rid2_public_key = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary((rid2_public_key_string))));

		// If OSCORE is being used set the context information
		if (useOSCORE) {

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

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);

		client.setURI(requestURI);
		Request multicastRequest = Request.newPost();
		multicastRequest.setPayload(requestPayload);
		multicastRequest.setType(Type.NON);
		if (useOSCORE) {
			multicastRequest.getOptions().setOscore(Bytes.EMPTY);
		}

		// Information about the sender
		System.out.println("==================");
		System.out.println("*Multicast sender");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Request destination: " + requestURI);
		System.out.println("Request destination port: " + destinationPort);
		System.out.println("Request method: " + multicastRequest.getCode());
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
		System.out.println(Utils.prettyPrint(multicastRequest));

		// sends a multicast request
		client.advanced(handler, multicastRequest);
		while (handler.waitOn(HANDLER_TIMEOUT)) {
			// Wait for responses
		}

	}

	private static final MultiCoapHandler handler = new MultiCoapHandler();

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
	}
}
