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
package org.eclipse.californium.oscore.group.interop;

import static org.junit.Assert.assertArrayEquals;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.cose.ASN1;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreEndpointContextInfo;
import org.eclipse.californium.oscore.OSCoreResource;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.GroupRecipientCtx;
import org.eclipse.californium.oscore.group.GroupSenderCtx;
import org.eclipse.californium.oscore.group.OneKeyDecoder;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test receiver using {@link UdpMulticastConnector}.
 */
public class GroupOSCOREInteropServer {

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
	 * Whether to use OSCORE or not. (Case 1)
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
	static final InetAddress listenIP = CoAP.MULTICAST_IPV4;
	// static final InetAddress listenIP = new InetSocketAddress("127.0.0.1",
	// 0).getAddress();

	/**
	 * Build endpoint to listen on multicast IP.
	 */
	static final boolean useMulticast = listenIP.isMulticastAddress();

	/**
	 * Port to listen to.
	 */
	static final int listenPort = CoAP.DEFAULT_COAP_PORT;

	/* --- OSCORE Security Context information (receiver) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature
	private final static AlgorithmID algCountersign = AlgorithmID.ECDSA_256;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = InteropParametersNew.RIKARD_MASTER_SECRET_ECDSA;
	private final static byte[] master_salt = InteropParametersNew.RIKARD_MASTER_SALT_ECDSA;

	private static final int REPLAY_WINDOW = 32;

	// Public and private keys for group members

	private static byte[] sid = InteropParametersNew.RIKARD_ENTITY_1_KID_ECDSA;
	private static OneKey sid_private_key;

	private final static byte[] rid1 = InteropParametersNew.RIKARD_ENTITY_3_KID_ECDSA;
	private static OneKey rid1_public_key;

	private final static byte[] group_identifier = InteropParametersNew.RIKARD_GROUP_ID_ECDSA;

	/* --- OSCORE Security Context information --- */

	private static Random random;

	private static int DEFAULT_BLOCK_SIZE = 512;

    static Random rand;
    static int myId;

	public static void main(String[] args) throws Exception {

        // final Provider PROVIDER = new BouncyCastleProvider();
        final Provider EdDSA = new EdDSASecurityProvider();
        // Security.insertProviderAt(PROVIDER, 1);
        Security.insertProviderAt(EdDSA, 0);
		//
		// OneKey mykey = OneKey.generateKey(AlgorithmID.EDDSA);
		//
		// ArrayList<ASN1.TagValue> spki =
		// ASN1.DecodeSubjectPublicKeyInfo(mykey.AsPublicKey().getEncoded());
		// ArrayList<ASN1.TagValue> alg = spki.get(0).list;
		//
		// // System.out.println("Value0: " +
		// // Utils.toHexString(spki.get(0).value));
		// // System.out.println("List0: " + (spki.get(0).list));
		// //
		// // System.out.println("Value1: " +
		// // Utils.toHexString(spki.get(1).value));
		// // System.out.println("List1: " + (spki.get(1).list));
		// //
		// // System.out.println("Value2: " +
		// // Utils.toHexString(spki.get(2).value));
		// // System.out.println("List2: " + (spki.get(2).list));
		//
		// System.out.println("alg0 " + Utils.toHexString(alg.get(0).value));
		// // System.out.println("alg1 " + Utils.toHexString(alg.get(1).value));
		// // System.out.println("alg3 " + Utils.toHexString(alg.get(2).value));
		// // System.out.println("alg4 " + Utils.toHexString(alg.get(3).value));
		//
		// System.out.println("SPKI: ");
		// for (int i = 0; i < spki.size(); i++) {
		// ArrayList<ASN1.TagValue> spkiCurrentList = spki.get(i).list;
		// byte[] spkiCurrentValue = spki.get(i).value;
		//
		// System.out.println("i " + i + " spki current value " +
		// Utils.toHexString(spkiCurrentValue));
		//
		// if (spkiCurrentList == null || spkiCurrentList == null) {
		// continue;
		// }
		//
		// for (int n = 0; n < spkiCurrentList.size(); n++) {
		//
		// ArrayList<ASN1.TagValue> aaa = spkiCurrentList.get(n).list;
		// byte[] aaa2 = spkiCurrentList.get(n).value;
		//
		// if (aaa == null) {
		// continue;
		// }
		//
		// System.out.print("i " + i + " n " + n);
		// System.out.println(" val " + Utils.toHexString(aaa2));
		//
		// // ArrayList<ASN1.TagValue> inner = spkiCurrent.get(n).list;
		// // System.out.println("inner " +
		// // Utils.toHexString(inner.get(0).value));
		// }
		//
		// }
		//
		// System.out.println("OUR X : " +
		// Utils.toHexString(mykey.PublicKey().get(KeyKeys.OKP_X).GetByteString()));
		//
		//
		//
		// byte[] oid = (byte[]) alg.get(0).value;
		// byte[] keyData = (byte[]) spki.get(1).value;
		//
		// // OneKey mykey2 = new OneKey(mykey.AsPublicKey(),
		// // mykey.AsPrivateKey());
		// OneKey mykey2 = new OneKey(mykey.AsPublicKey(), null);
		// System.out.println("OUR NEW X : " +
		// Utils.toHexString(mykey2.PublicKey().get(KeyKeys.OKP_X).GetByteString()));
		//
		// System.out.println("END");
		//
		// if (mykey.PublicKey().equals(mykey2)) {
		// System.out.println("SAME");
		// } else {
		// System.out.println("NOT THE SAME");
		// }
		//
		// System.out.println("mykey public " +
		// mykey.PublicKey().AsCBOR().toString());
		// System.out.println("mykey2 " + mykey2.AsCBOR().toString());
		//
		//
		//
		//
		//
		//
		// byte[] mykeyPublicBytes = mykey.PublicKey().AsCBOR().EncodeToBytes();
		// byte[] mykey2Bytes = mykey2.AsCBOR().EncodeToBytes();
		//
		// if(Arrays.equals(mykeyPublicBytes, mykey2Bytes)) {
		// System.out.println("SAME bytes");
		// } else {
		// System.out.println("NOT THE SAME bytes");
		// }
		//
		//
		//
		// System.out.println("Part 1");
		//
		// System.out.println("OUR D : " +
		// Utils.toHexString(mykey.get(KeyKeys.OKP_D).GetByteString()));
		//
		// // OneKey mykeyECDSA = OneKey.generateKey(AlgorithmID.ECDSA_256);

		OneKey mykey = OneKey.generateKey(AlgorithmID.EDDSA);
		System.out.println("OUR D : " + Utils.toHexString(mykey.get(KeyKeys.OKP_D).GetByteString()));
		System.out.println("First generated key: " + mykey.AsCBOR().toString());

		OneKey mykeyFull = new OneKey(mykey.AsPublicKey(), mykey.AsPrivateKey());
		System.out.println("OUR mykeyFull D : " + Utils.toHexString(mykeyFull.get(KeyKeys.OKP_D).GetByteString()));
		System.out.println("New rebuilt key:     " + mykeyFull.AsCBOR().toString());

		System.out.println("Private encoded: " + Utils.toHexString(mykey.AsPrivateKey().getEncoded()));
		System.out.println("Public encoded: " + Utils.toHexString(mykey.AsPublicKey().getEncoded()));

		OneKey fromCBOR = new OneKey(mykey.AsCBOR());
		System.out.println("CBOR Private encoded: " + Utils.toHexString(fromCBOR.AsPrivateKey().getEncoded()));
		System.out.println("CBOR Public encoded: " + Utils.toHexString(fromCBOR.AsPublicKey().getEncoded()));

		// RFC8410, RFC8419

		// rand = new Random();
		// myId = rand.nextInt(1000);
		//
		// System.out.println("ID: " + myId);
		//
		// // Disable replay detection
		// OSCoreCtx.DISABLE_REPLAY_CHECKS = true;
		//
		// // Set sender & receiver keys for countersignatures
		// sid_private_key =
		// OneKeyDecoder.parseDiagnostic(InteropParametersNew.RIKARD_ENTITY_1_KEY_ECDSA);
		// rid1_public_key =
		// OneKeyDecoder.parseDiagnostic(InteropParametersNew.RIKARD_ENTITY_3_KEY_ECDSA);
		//
		// // Check command line arguments (flag to use different sid and sid
		// key)
		// if (args.length != 0) {
		// sid = InteropParametersNew.RIKARD_ENTITY_2_KID_ECDSA;
		// System.out.println("Starting with alternative sid " +
		// Utils.toHexString(sid));
		// sid_private_key =
		// OneKeyDecoder.parseDiagnostic(InteropParametersNew.RIKARD_ENTITY_2_KEY_ECDSA);
		// } else {
		// System.out.println("Starting with sid " + Utils.toHexString(sid));
		// }
		//
		// // Check that KIDs in public/private keys match corresponding
		// // recipient/sender ID (just to double check configuration)
		// assertArrayEquals(sid,
		// sid_private_key.get(KeyKeys.KeyId).GetByteString());
		// assertArrayEquals(rid1,
		// rid1_public_key.get(KeyKeys.KeyId).GetByteString());
		//
		// // If OSCORE is being used set the context information
		// @SuppressWarnings("unused")
		// GroupSenderCtx senderCtx;
		// @SuppressWarnings("unused")
		// GroupRecipientCtx recipientCtx;
		// if (useOSCORE) {
		//
		// GroupCtx commonCtx = null;
		//
		// commonCtx.addSenderCtx(sid, sid_private_key);
		//
		// commonCtx.addRecipientCtx(rid1, REPLAY_WINDOW, rid1_public_key);
		//
		// // commonCtx.setResponsesIncludePartialIV(true);
		//
		// db.addContext(uriLocal, commonCtx);
		//
		// // Also add a normal OSCORE context (defined in that method)
		// addOSCOREContext();
		//
		// OSCoreCoapStackFactory.useAsDefault(db);
		//
		// // Retrieve the sender and recipient contexts
		// senderCtx = (GroupSenderCtx) db.getContext(uriLocal);
		// recipientCtx = (GroupRecipientCtx) db.getContext(rid1,
		// group_identifier);
		//
		// // --- Test cases ---
		// // Case 4: Add key for the recipient for dynamic derivation
		// // // Comment out context addition above
		// // commonCtx.addPublicKeyForRID(rid1, rid1_public_key);
		//
		// // Case 5: Client response decryption failure
		// // senderCtx.setSenderKey(new byte[16]);
		//
		// // Case 7: Client response signature failure
		// //
		// senderCtx.setAsymmetricSenderKey(OneKey.generateKey(algCountersign));
		//
		// // For pairwise responses:
		// // commonCtx.setPairwiseModeResponses(true);
		// }
		//
		// // Initialize random number generator
		// random = new Random();
		//
		// NetworkConfig config = NetworkConfig.getStandard();
		//
		// // For BW (needed? Seems not)
		// // MatcherMode mode = MatcherMode.STRICT;
		// // config = config.setInt(Keys.ACK_TIMEOUT,
		// // 200).setFloat(Keys.ACK_RANDOM_FACTOR, 1f)
		// // .setFloat(Keys.ACK_TIMEOUT_SCALE, 1f)
		// // // set response timeout (indirect) to 10s
		// // .setLong(Keys.EXCHANGE_LIFETIME, 10 *
		// // 1000L).setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE)
		// // .setInt(Keys.PREFERRED_BLOCK_SIZE,
		// // DEFAULT_BLOCK_SIZE).setString(Keys.RESPONSE_MATCHING,
		// mode.name());
		//
		// CoapEndpoint endpoint = createEndpoints(config);
		//
		// // Case 9: Duplicate server response
		// // endpoint.setDuplicateResponse(true);
		//
		// CoapServer server = new CoapServer(config);
		// server.addEndpoint(endpoint);
		// server.add(new OtherOscoreResource());
		//
		// // Build resource hierarchy
		// CoapResource oscore = new CoapResource("oscore", true);
		// CoapResource oscore_hello = new CoapResource("hello", true);
		//
		// oscore_hello.add(new CoapHelloWorldResource());
		// oscore_hello.add(new OscoreHelloWorldResource());
		// oscore_hello.add(new BlockWiseResource());
		// oscore_hello.add(new BlockWiseResource2());
		// oscore_hello.add(new ObserveResource("observe", true));
		//
		// oscore.add(oscore_hello);
		// server.add(oscore);
		//
		// // Information about the receiver
		// System.out.println("==================");
		// System.out.println("*Interop receiver");
		// System.out.println("Uses OSCORE: " + useOSCORE);
		// System.out.println("Respond to non-confirmable messages: " +
		// replyToNonConfirmable);
		// System.out.println("Listening to IP: " + listenIP.getHostAddress());
		// System.out.println("Using multicast: " + useMulticast);
		// System.out.println("Unicast IP: " +
		// endpoint.getAddress().getHostString());
		// System.out.println("Incoming port: " +
		// endpoint.getAddress().getPort());
		// System.out.print("CoAP resources: ");
		// for (Resource res : server.getRoot().getChildren()) {
		// System.out.print(res.getURI() + " ");
		// }
		// System.out.println("");
		// System.out.println("==================");
		//
		// server.start();
	}

	private static CoapEndpoint createEndpoints(NetworkConfig config) throws UnknownHostException {

		InetSocketAddress localAddress;
		// Set a random loopback address in 127.0.0.0/8
		if (randomUnicastIP) {
			byte[] b = new byte[4];
			random.nextBytes(b);
			b[0] = 127;
			b[1] = 0;
			InetAddress inetAdd = InetAddress.getByAddress(b);

			localAddress = new InetSocketAddress(inetAdd, listenPort);
		} else { // Set the wildcard address (0.0.0.0)
			localAddress = new InetSocketAddress(listenPort);
		}

        // localAddress = new InetSocketAddress(InetAddress.getByName("0.0.0.0"), listenPort);

		Connector connector = null;
		if (useMulticast) {
            // connector = new UdpMulticastConnector(localAddress, listenIP);
            UdpMulticastConnector.Builder builder = new UdpMulticastConnector.Builder();
            builder.setLocalAddress(localAddress);
            builder.addMulticastGroup(listenIP);
            builder.setOutgoingMulticastInterface(InetAddress.getByName("172.17.0.1"));
            // NetworkInterface if = new NetworkInterface();
            // builder.setOutgoingMulticastInterface(if);
            // builder.set
            connector = builder.build();

		} else {
			InetSocketAddress unicastAddress = new InetSocketAddress(listenIP, listenPort);
			connector = new UDPConnector(unicastAddress);
		}
		return new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(connector).build();
	}

	/**
	 * Add an OSCORE Context to the DB (OSCORE RFC C.2.2.)
	 */
	static OSCoreCtx oscoreCtx;
	private static void addOSCOREContext() {
		byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				0x0f, 0x10 };
		byte[] master_salt = null;
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[] { 0x00 };
		byte[] id_context = null;

		try {
			oscoreCtx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, id_context);
			// oscoreCtx.setResponsesIncludePartialIV(true);
			db.addContext(oscoreCtx);
		} catch (OSException e) {
			System.err.println("Failed to add OSCORE context!");
			e.printStackTrace();
		}
	}

	// == Define resources ===

	/**
	 * The resource for testing Observe support
	 * 
	 */
	private static class ObserveResource extends CoapResource {

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
			String response = "Server Name: " + Utils.toHexString(sid) + ". Value: " + counter;
			System.out.println(response);
			exchange.respond(response);
		}

		// Update the resource value when timer triggers (if 1st request is
		// received)
		class UpdateTask extends TimerTask {

			@Override
			public void run() {
				if (firstRequestReceived && (counter + 1) % 10 == 0) {
					// Stop after every 10 requests
					counter++;
					changed(); // notify all observers
					clearObserveRelations(); // Clear observers
					firstRequestReceived = false;
				} else if (firstRequestReceived) {
					counter++;
					changed(); // notify all observers
				}
			}
		}
	}

	private static class CoapHelloWorldResource extends CoapResource {

		private CoapHelloWorldResource() {
			// set resource identifier
			super("coap");

			// set display name
			getAttributes().setTitle("CoAP Hello-World Resource");

		}

		// Handling GET
		@Override
		public void handleGET(CoapExchange exchange) {
			System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
			System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());

			System.out.println(Utils.prettyPrint(exchange.advanced().getRequest()));

			boolean isConfirmable = exchange.advanced().getRequest().isConfirmable();

			if (isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				r.setPayload("Hello World!");

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

	private static class OscoreHelloWorldResource extends OSCoreResource {

		private OscoreHelloWorldResource() {
			// set resource identifier
			super("1", true);

			// set display name
			getAttributes().setTitle("OSCORE Hello-World Resource");

		}

		// Handling GET
		@Override
		public void handleGET(CoapExchange exchange) {

			System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
			System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());

			System.out.println(Utils.prettyPrint(exchange.advanced().getRequest()));

			boolean isConfirmable = exchange.advanced().getRequest().isConfirmable();

			if (isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				r.setPayload("Hello World!");

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

	private static class BlockWiseResource2 extends CoapResource {

		/**
		 * Request counter. Ensure, that transparent blockwise is not accidently
		 * split into "intermediary block" requests.
		 */
		private final AtomicInteger counter = new AtomicInteger();
        private volatile String currentPayload = myId + " "
                + bwPayload.substring(0, DEFAULT_BLOCK_SIZE * 5 - 6).concat(" (END)");

		public BlockWiseResource2() {
			super("bw2");
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			// db.removeContext(oscoreCtx);
			// addOSCOREContext();
			// System.out.println("CLEAR CTX");

			counter.incrementAndGet();
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(currentPayload);
			exchange.respond(response);
			//
			// db.removeContext(oscoreCtx);
			// addOSCOREContext();
			// System.out.println("CLEAR CTX");
		}

		@Override
		public void handlePUT(CoapExchange exchange) {
			counter.incrementAndGet();
			currentPayload = exchange.getRequestText();
			Response response = new Response(ResponseCode.CHANGED);
			exchange.respond(response);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {
			counter.incrementAndGet();
			currentPayload += exchange.getRequestText();
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(currentPayload);
			exchange.respond(response);
		}
	}

	private static class BlockWiseResource extends CoapResource {

		private BlockWiseResource() {
			// set resource identifier
			super("bw");

			// set display name
			getAttributes().setTitle("CoAP Block-Wise Resource");
		}

		// Handling GET
		@Override
		public void handleGET(CoapExchange exchange) {
			System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
			System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());

			System.out.println(Utils.prettyPrint(exchange.advanced().getRequest()));

			boolean isConfirmable = exchange.advanced().getRequest().isConfirmable();

			if (isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				r.setPayload(bwPayload);

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

	private static class OtherOscoreResource extends CoapResource {

		private String id;
		private int count = 0;

		private OtherOscoreResource() {
			// set resource identifier
			super("test"); // Changed

			// set display name
			getAttributes().setTitle("Hello-World Resource");

			// id = Integer.toString(random.nextInt(1000));
			id = Utils.toHexString(sid);

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
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				String requestPayload = exchange.getRequestText().toUpperCase();

				// Get the SID on my end (Group OSCORE doesn't support this yet
				// so some tricks are needed)
				EndpointContext ctx = exchange.advanced().getRequest().getSourceContext();
				MapBasedEndpointContext mapCtx = (MapBasedEndpointContext) ctx;
				String reqIdContext = mapCtx.get(OSCoreEndpointContextInfo.OSCORE_CONTEXT_ID);
				String groupIdContext = Utils.toHexString(group_identifier).replace("[", "").replace("]", "");
				String responsePayload = "";

				// Get other party KID
				String yourKID = mapCtx.get(OSCoreEndpointContextInfo.OSCORE_RECIPIENT_ID);

				if (!exchange.advanced().getRequest().getOptions().hasOscore()) {
					// CoAP
					responsePayload = "Response with CoAP.";
				} else if (groupIdContext.equals(reqIdContext)) {
					// Group OSCORE
					responsePayload = "Response from ID " + id + " with Group OSCORE. You are ID " + yourKID;
				} else {
					// OSCORE
					String mySID = mapCtx.get(OSCoreEndpointContextInfo.OSCORE_SENDER_ID);
					responsePayload = "Response from ID " + mySID + " with OSCORE. You are ID " + yourKID;
				}

				if (requestPayload == null || requestPayload.length() == 0) {
					r.setPayload(responsePayload);
				} else {
					r.setPayload(requestPayload.toUpperCase() + ". " + responsePayload);
				}

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

	private final static String bwPayload = "   The work on Constrained RESTful Environments (CoRE) aims at realizing\n"
			+ "   the Representational State Transfer (REST) architecture in a suitable\n"
			+ "   form for the most constrained nodes (such as microcontrollers with\n"
			+ "   limited RAM and ROM [RFC7228]) and networks (such as IPv6 over Low-\n"
			+ "   Power Wireless Personal Area Networks (6LoWPANs) [RFC4944])\n"
			+ "   [RFC7252].  The CoAP protocol is intended to provide RESTful [REST]\n"
			+ "   services not unlike HTTP [RFC7230], while reducing the complexity of\n"
			+ "   implementation as well as the size of packets exchanged in order to\n"
			+ "   make these services useful in a highly constrained network of highly\n" + "   constrained nodes.\n"
			+ "\n" + "   This objective requires restraint in a number of sometimes\n" + "   conflicting ways:\n" + "\n"
			+ "   o  reducing implementation complexity in order to minimize code size,\n" + "\n"
			+ "   o  reducing message sizes in order to minimize the number of\n"
			+ "      fragments needed for each message (to maximize the probability of\n"
			+ "      delivery of the message), the amount of transmission power needed,\n"
			+ "      and the loading of the limited-bandwidth channel,\n" + "\n"
			+ "   o  reducing requirements on the environment such as stable storage,\n"
			+ "      good sources of randomness, or user-interaction capabilities.\n" + "\n"
			+ "   Because CoAP is based on datagram transports such as UDP or Datagram\n"
			+ "   Transport Layer Security (DTLS), the maximum size of resource\n"
			+ "   representations that can be transferred without too much\n"
			+ "   fragmentation is limited.  In addition, not all resource\n"
			+ "   representations will fit into a single link-layer packet of a\n"
			+ "   constrained network, which may cause adaptation layer fragmentation\n"
			+ "   even if IP-layer fragmentation is not required.  Using fragmentation\n"
			+ "   (either at the adaptation layer or at the IP layer) for the transport\n"
			+ "   of larger representations would be possible up to the maximum size of\n"
			+ "   the underlying datagram protocol (such as UDP), but the\n"
			+ "   fragmentation/reassembly process burdens the lower layers with\n"
			+ "   conversation state that is better managed in the application layer.\n" + "\n"
			+ "   The present specification defines a pair of CoAP options to enable\n"
			+ "   block-wise access to resource representations.  The Block options\n"
			+ "   provide a minimal way to transfer larger resource representations in\n"
			+ "   a block-wise fashion.  The overriding objective is to avoid the need\n"
			+ "   for creating conversation state at the server for block-wise GET\n"
			+ "   requests.  (It is impossible to fully avoid creating conversation\n"
			+ "   state for POST/PUT, if the creation/replacement of resources is to be\n"
			+ "   atomic; where that property is not needed, there is no need to create\n"
			+ "   server conversation state in this case, either.)\n" + "\n"
			+ "   Block-wise transfers are realized as combinations of exchanges, each\n"
			+ "   of which is performed according to the CoAP base protocol [RFC7252].\n"
			+ "   Each exchange in such a combination is governed by the specifications\n"
			+ "   in [RFC7252], including the congestion control specifications\n"
			+ "   (Section 4.7 of [RFC7252]) and the security considerations\n"
			+ "   (Section 11 of [RFC7252]; additional security considerations then\n"
			+ "   apply to the transfers as a whole, see Section 7).  The present\n"
			+ "   specification minimizes the constraints it adds to those base\n"
			+ "   exchanges; however, not all variants of using CoAP are very useful\n"
			+ "   inside a block-wise transfer (e.g., using Non-confirmable requests\n"
			+ "   within block-wise transfers outside the use case of Section 2.8 would\n"
			+ "   escalate the overall non-delivery probability).  To be perfectly\n"
			+ "   clear, the present specification also does not remove any of the\n"
			+ "   constraints posed by the base specification it is strictly layered on\n"
			+ "   top of.  For example, back-to-back packets are limited by the\n"
			+ "   congestion control described in Section 4.7 of [RFC7252] (NSTART as a\n"
			+ "   limit for initiating exchanges, PROBING_RATE as a limit for sending\n"
			+ "   with no response); block-wise transfers cannot send/solicit more\n"
			+ "   traffic than a client could be sending to / soliciting from the same\n"
			+ "   server without the block-wise mode.\n" + "\n"
			+ "   In some cases, the present specification will RECOMMEND that a client\n"
			+ "   perform a sequence of block-wise transfers \"without undue delay\".\n"
			+ "   This cannot be phrased as an interoperability requirement, but is an\n"
			+ "   expectation on implementation quality.  Conversely, the expectation\n"
			+ "   is that servers will not have to go out of their way to accommodate\n"
			+ "   clients that take considerable time to finish a block-wise transfer.\n"
			+ "   For example, for a block-wise GET, if the resource changes while this\n"
			+ "   proceeds, the entity-tag (ETag) for a further block obtained may be\n"
			+ "   different.  To avoid this happening all the time for a fast-changing\n"
			+ "   resource, a server MAY try to keep a cache around for a specific\n"
			+ "   client for a short amount of time.  The expectation here is that the\n"
			+ "   lifetime for such a cache can be kept short, on the order of a few\n"
			+ "   expected round-trip times, counting from the previous block\n" + "   transferred.";
}
