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

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;

/**
 * Test sender configured to support multicast requests. Rebased.
 */
public class GroupOSCORESenderCfg {

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
	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MULTICAST_BASE_MID, 65000);
		}

	};

	private final static HashMapCtxDB db = new HashMapCtxDB();

	private static final int HANDLER_TIMEOUT = AppConfigSender.getInt("HANDLER_TIMEOUT");
	static final boolean useOSCORE = AppConfigSender.getBoolean("useOSCORE");
	static final InetAddress multicastIP = AppConfigSender.getInetAddress("multicast_ip");
	private static final int destinationPort = AppConfigSender.getInt("destination_port");
	static final String requestResource = AppConfigSender.getString("request_resource");
	static final String requestPayload = AppConfigSender.getString("request_payload");

	private static final AlgorithmID alg = AppConfigSender.getAlg("alg");
	private static final AlgorithmID kdf = AppConfigSender.getAlg("kdf");
	private static final AlgorithmID algCountersign = AppConfigSender.getAlg("algCountersign");
	private static final AlgorithmID algGroupEnc = AppConfigSender.getAlg("algGroupEnc");
	private static final AlgorithmID algKeyAgreement = AppConfigSender.getAlg("algKeyAgreement");

	private static final byte[] master_secret = AppConfigSender.getHexByteArray("master_secret");
	private static final byte[] master_salt = AppConfigSender.getHexByteArray("master_salt");
	private static final int REPLAY_WINDOW = AppConfigSender.getInt("replay_window");

	private static final byte[] gm_public_key_bytes = AppConfigSender.getHexByteArray("gm_public_key");

	private static final byte[] sid = AppConfigSender.getHexByteArray("sid");
	private static final byte[] sid_public_key_bytes = AppConfigSender.getHexByteArray("sid_public_key");
	private static byte[] sid_private_key_bytes = AppConfigSender.getHexByteArray("sid_private_key");
	private static MultiKey sid_private_key;

	private static final byte[] rid0 = AppConfigSender.getHexByteArray("rid0");
	private static final byte[] rid1 = AppConfigSender.getHexByteArray("rid1");
	private static final byte[] rid1_public_key_bytes = AppConfigSender.getHexByteArray("rid1_public_key");
	private static final byte[] rid2 = AppConfigSender.getHexByteArray("rid2");
	private static final byte[] rid2_public_key_bytes = AppConfigSender.getHexByteArray("rid2_public_key");

	private static final byte[] group_identifier = AppConfigSender.getHexByteArray("group_identifier");

	static final boolean pairwiseMode = AppConfigSender.getBoolean("pairwise_mode");

	/* --- OSCORE Security Context information --- */

	/**
	 * Main method
	 * 
	 * @param args command line arguments
	 * @throws Exception on setup or message processing failure
	 */
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
		Security.insertProviderAt(EdDSA, 1);
		// InstallCryptoProviders.generateCounterSignKey();

		// Add private & public keys for sender & receiver(s)
		sid_private_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);
		MultiKey rid1_public_key = new MultiKey(rid1_public_key_bytes);
		MultiKey rid2_public_key = new MultiKey(rid2_public_key_bytes);

		// If OSCORE is being used set the context information
		if (useOSCORE) {

			byte[] gmPublicKey = gm_public_key_bytes;
			GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
					algGroupEnc, algKeyAgreement, gmPublicKey);

			commonCtx.addSenderCtxCcs(sid, sid_private_key);

			commonCtx.addRecipientCtxCcs(rid0, REPLAY_WINDOW, null);
			commonCtx.addRecipientCtxCcs(rid1, REPLAY_WINDOW, rid1_public_key);
			commonCtx.addRecipientCtxCcs(rid2, REPLAY_WINDOW, rid2_public_key);

			db.addContext(requestURI, commonCtx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);

		client.setURI(requestURI);
		Request multicastRequest = Request.newPost();
		multicastRequest.setPayload(requestPayload);
		multicastRequest.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		multicastRequest.setType(Type.NON);
		if (useOSCORE) {

			if (pairwiseMode) {
				// For pairwise request:
				multicastRequest.getOptions().setOscore(OptionEncoder.set(true, requestURI, rid1));

			} else {
				// For group mode request
				multicastRequest.getOptions().setOscore(Bytes.EMPTY);
			}

		}

		// Information about the sender
		System.out.println("==================");
		System.out.println("*Multicast sender");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Using pairwise mode: " + pairwiseMode);
		if (pairwiseMode) {
			System.out.println("Pairwise mode target: " + requestURI + " " + Utils.toHexString(rid1));
		} else {
			System.out.println("Request destination: " + requestURI);
		}
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
