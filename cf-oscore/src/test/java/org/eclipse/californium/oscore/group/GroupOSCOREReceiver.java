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
package org.eclipse.californium.oscore.group;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.Provider;
import java.security.Security;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test receiver using {@link UdpMulticastConnector}.
 */
public class GroupOSCOREReceiver {

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

	/**
	 * Port to listen to.
	 */
	static final int listenPort = CoAP.DEFAULT_COAP_PORT;

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
	private final static int[] countersign_key_type_capab = new int[] { KeyKeys.KeyType_OKP.AsInt32(),
			KeyKeys.OKP_Ed25519.AsInt32() };
	private final static int[] countersign_alg_capab = new int[] { KeyKeys.KeyType_OKP.AsInt32() };
	private final static int[][] parCountersign = new int[][] { countersign_alg_capab, countersign_key_type_capab };
	private final static int[] parCountersignKey = countersign_key_type_capab;

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

	private static Random random;

	public static void main(String[] args) throws Exception {
		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

		// Set sender & receiver keys for countersignatures
		sid_private_key = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(sid_private_key_string)));
		rid1_public_key = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(rid1_public_key_string)));

		// Check command line arguments (flag to use different sid and sid key)
		if (args.length != 0) {
			System.out.println("Starting with alternative sid 0x77.");
			sid = new byte[] { 0x77 };
			sid_private_key_string = "pQMnAQEgBiFYIBBbjGqMiAGb8MNUWSk0EwuqgAc5nMKsO+hFiEYT1bouI1gge/Yvdn7Rz0xgkR/En9/Mub1HzH6fr0HLZjadXIUIsjk=";
			sid_private_key = new OneKey(
					CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(sid_private_key_string)));
		} else {
			System.out.println("Starting with sid 0x52.");
		}

		// If OSCORE is being used set the context information
		if (useOSCORE) {

			GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
					parCountersign, parCountersignKey);

			commonCtx.addSenderCtx(sid, sid_private_key);

			commonCtx.addRecipientCtx(rid1, REPLAY_WINDOW, rid1_public_key);

			commonCtx.setResponsesIncludePartialIV(true);

			db.addContext(uriLocal, commonCtx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		// Initialize random number generator
		random = new Random();

		NetworkConfig config = NetworkConfig.getStandard();
		CoapEndpoint endpoint = createEndpoints(config);
		CoapServer server = new CoapServer(config);
		server.addEndpoint(endpoint);
		server.add(new HelloWorldResource());

		// Information about the receiver
		System.out.println("==================");
		System.out.println("*Multicast receiver");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Respond to non-confirmable messages: " + replyToNonConfirmable);
		System.out.println("Listening to Multicast IP: " + multicastIP.getHostAddress());
		System.out.println("Unicast IP: " + endpoint.getAddress().getHostString());
		System.out.println("Incoming port: " + endpoint.getAddress().getPort());
		System.out.print("CoAP resources: ");
		for (Resource res : server.getRoot().getChildren()) {
			System.out.print(res.getURI() + " ");
		}
		System.out.println("");
		System.out.println("==================");

		server.start();
	}

	private static CoapEndpoint createEndpoints(NetworkConfig config) throws UnknownHostException {
		int port = listenPort;

		InetSocketAddress localAddress;
		// Set a random loopback address in 127.0.0.0/8
		if (randomUnicastIP) {
			byte[] b = new byte[4];
			random.nextBytes(b);
			b[0] = 127;
			b[1] = 0;
			InetAddress inetAdd = InetAddress.getByAddress(b);

			localAddress = new InetSocketAddress(inetAdd, port);
		} else { // Set the wildcard address (0.0.0.0)
			localAddress = new InetSocketAddress(port);
		}

		Connector connector = new UdpMulticastConnector(localAddress, multicastIP);
		return new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(connector).build();
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
			// sent for non-confirmable
			// payload is set to request payload changed to uppercase plus the
			// receiver ID
			if (isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.setPayload(exchange.getRequestText().toUpperCase() + ". ID: " + id);
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
}
