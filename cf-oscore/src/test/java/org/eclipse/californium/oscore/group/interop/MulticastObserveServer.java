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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.Provider;
import java.security.Security;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.GroupCtx;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class MulticastObserveServer {

	static boolean useOSCORE = true;

	/* --- OSCORE Security Context information (receiver) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature (EdDSA)
	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;

	// test vector OSCORE draft Appendix C.1.2
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

	private static byte[] sid = new byte[] { 0x52 };
	private static String sid_private_key_string = "pQMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0YzibI1gghX62HT9tcKJ4o2dA0TLAmfYogO1Jfie9/UaF+howTyY=";
	private static OneKey sid_private_key;

	private final static byte[] rid1 = new byte[] { 0x25 };
	private final static String rid1_public_key_string = "pAMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6";
	private static OneKey rid1_public_key;

	private final static byte[] group_identifier = new byte[] { 0x44, 0x61, 0x6c }; // GID

	/* --- OSCORE Security Context information --- */

	/**
	 * Multicast address to send to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	/**
	 * Port to listen on.
	 */
	private static final int listenPort = CoAP.DEFAULT_COAP_PORT;

	private static CoapServer server;

	public static void main(String[] args)
			throws InterruptedException, UnknownHostException, CoseException, OSException {

		// If OSCORE is being used
		if (useOSCORE) {

			// Install cryptographic providers
			Provider EdDSA = new EdDSASecurityProvider();
			Security.insertProviderAt(EdDSA, 0);

			// Set sender & receiver keys for countersignatures
			sid_private_key = new OneKey(
					CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(sid_private_key_string)));
			rid1_public_key = new OneKey(
					CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(rid1_public_key_string)));

			// Check command line arguments (flag to use different sid and sid
			// key)
			if (args.length != 0) {
				System.out.println("Starting with alternative sid 0x77.");
				sid = new byte[] { 0x77 };
				sid_private_key_string = "pQMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bouI1gge/Yvdn7Rz0xgkR/En9/Mub1HzH6fr0HLZjadXIUIsjk=";
				sid_private_key = new OneKey(
						CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(sid_private_key_string)));
			} else {
				System.out.println("Starting with sid 0x52.");
			}

			GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign);

			commonCtx.addSenderCtx(sid, sid_private_key);

			commonCtx.addRecipientCtx(rid1, REPLAY_WINDOW, rid1_public_key);

			commonCtx.setResponsesIncludePartialIV(true);

			db.addContext(uriLocal, commonCtx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		createServer();
	}

	/**
	 * Creates server with resources to test Observe functionality
	 * 
	 * @throws InterruptedException if resource update task fails
	 */
	public static void createServer() throws InterruptedException, UnknownHostException {

		Random rand = new Random();
		final int serverID = rand.nextInt(100);

		System.out.println("Server Name: " + serverID);

		// Create server
		NetworkConfig config = NetworkConfig.getStandard();
		CoapEndpoint endpoint = createEndpoints(config);

		server = new CoapServer(config);
		server.addEndpoint(endpoint);

		/** --- Resources for Observe tests follow --- **/

		// Base resource for Observe test resources
		CoapResource base = new CoapResource("base", true);

		// Second level base resource for Observe test resources
		CoapResource hello = new CoapResource("hello", true);

		/**
		 * The resource for testing Observe support
		 * 
		 */
		class ObserveResource extends CoapResource {

			int counter = 0;
			private boolean firstRequestReceived = false;

			public ObserveResource(String name, boolean visible) {
				super(name, visible);

				this.setObservable(true);
				this.setObserveType(Type.NON);
				this.getAttributes().setObservable();

				Timer timer = new Timer();
				timer.schedule(new UpdateTask(), 0, 1500);
			}

			@Override
			public void handleGET(CoapExchange exchange) {
				firstRequestReceived = true;
				String response = "Server Name: " + serverID + ". Value: " + counter;
				System.out.println(response);
				exchange.respond(response);
			}

			// Update the resource value when timer triggers (if 1st request is
			// received)
			class UpdateTask extends TimerTask {

				@Override
				public void run() {
					if (firstRequestReceived) {
						counter++;
						changed(); // notify all observers
					}
				}
			}
		}

		// observe2 resource for Observe tests
		ObserveResource observe2 = new ObserveResource("observe2", true);

		// Creating resource hierarchy
		base.add(hello);
		base.add(observe2);

		server.add(base);

		/** --- End of resources for Observe tests **/

		// Start server
		server.start();
	}

	private static CoapEndpoint createEndpoints(NetworkConfig config) throws UnknownHostException {
		int port = listenPort;

		InetSocketAddress localAddress;
		// Set the wildcard address (0.0.0.0)
		localAddress = new InetSocketAddress(port);

		Connector connector = new UdpMulticastConnector(localAddress, multicastIP);
		return new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(connector).build();
	}

	// @After
	// public void after() {
	// if (null != server) {
	// server.destroy();
	// }
	// System.out.println("End " + getClass().getSimpleName());
	// }
}
