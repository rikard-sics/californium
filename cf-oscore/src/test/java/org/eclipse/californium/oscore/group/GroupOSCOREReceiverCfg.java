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

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test receiver using {@link UdpMulticastConnector}.
 */
public class GroupOSCOREReceiverCfg {

	private static final Logger LOGGER = LoggerFactory.getLogger(GroupOSCOREReceiverCfg.class);

	static final boolean replyToNonConfirmable = AppConfigReceiver.getBoolean("replyToNonConfirmable");
	static final boolean useOSCORE = AppConfigReceiver.getBoolean("useOSCORE");
	static final boolean randomUnicastIP = AppConfigReceiver.getBoolean("randomUnicastIP");
	private static boolean ipv4 = AppConfigReceiver.getBoolean("ipv4");
	private static final boolean LOOPBACK = AppConfigReceiver.getBoolean("LOOPBACK");
	static final int listenPort = AppConfigReceiver.getInt("listenPort");

	private final static HashMapCtxDB db = new HashMapCtxDB();

	private static byte[] sid;
	private static byte[] sid_public_key_bytes;
	private static byte[] sid_private_key_bytes;
	private static MultiKey sid_private_key;

	private static final byte[] master_secret = AppConfigReceiver.getHexByteArray("master_secret");
	private static final byte[] master_salt = AppConfigReceiver.getHexByteArray("master_salt");

	private static final byte[] rid1 = AppConfigReceiver.getHexByteArray("rid1");
	private static final byte[] rid1_public_key_bytes = AppConfigReceiver.getHexByteArray("rid1_public_key");
	private static MultiKey rid1_public_key;

	private static final byte[] group_identifier = AppConfigReceiver.getHexByteArray("group_identifier");

	private static final byte[] gm_public_key_bytes = AppConfigReceiver.getHexByteArray("gm_public_key");

	private static final AlgorithmID alg = AppConfigReceiver.getAlg("alg");
	private static final AlgorithmID kdf = AppConfigReceiver.getAlg("kdf");

	private static final AlgorithmID algCountersign = AppConfigReceiver.getAlg("algCountersign");
	private static final AlgorithmID algGroupEnc = AppConfigReceiver.getAlg("algGroupEnc");
	private static final AlgorithmID algKeyAgreement = AppConfigReceiver.getAlg("algKeyAgreement");

	private static final int REPLAY_WINDOW = AppConfigReceiver.getInt("replay_window");

	private static final String uriLocal = AppConfigReceiver.getString("uri_local");

	static final InetAddress multicastIP = AppConfigReceiver.getInetAddress("multicast_ip");

	/* --- OSCORE Security Context information --- */

	private static Random random;

	/**
	 * Main method
	 * 
	 * @param args command line arguments
	 * @throws Exception on setup or message processing failure
	 */
	public static void main(String[] args) throws Exception {
		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		if (AppConfigReceiver.getBoolean("useAltSid")) {
			System.out.println("Starting with alternative sid.");
			sid = new byte[] { (byte) Integer.parseInt(AppConfigReceiver.getString("alt_sid"), 16) };
			sid_public_key_bytes = AppConfigReceiver.getHexByteArray("alt_sid_public_key");
			sid_private_key_bytes = AppConfigReceiver.getHexByteArray("alt_sid_private_key");
		} else {
			System.out.println("Starting with sid.");
			sid = new byte[] { (byte) Integer.parseInt(AppConfigReceiver.getString("sid"), 16) };
			sid_public_key_bytes = AppConfigReceiver.getHexByteArray("sid_public_key");
			sid_private_key_bytes = AppConfigReceiver.getHexByteArray("sid_private_key");
		}
		sid_private_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);
		rid1_public_key = new MultiKey(rid1_public_key_bytes);


		// If OSCORE is being used set the context information
		if (useOSCORE) {

			byte[] gmPublicKey = gm_public_key_bytes;
			GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
					algGroupEnc, algKeyAgreement, gmPublicKey);

			commonCtx.addSenderCtxCcs(sid, sid_private_key);

			commonCtx.addRecipientCtxCcs(rid1, REPLAY_WINDOW, rid1_public_key);

			commonCtx.setResponsesIncludePartialIV(false);
			commonCtx.setPairwiseModeResponses(true);

			OSCoreCtx.DISABLE_REPLAY_CHECKS = false;
			db.addContext(uriLocal, commonCtx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		// Initialize random number generator
		random = new Random();

		Configuration config = Configuration.getStandard();
		CoapServer server = new CoapServer(config);
		createEndpoints(server, listenPort, listenPort, config);
		Endpoint endpoint = server.getEndpoint(listenPort);
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

	private static class HelloWorldResource extends OSCoreResource {

		private int id;
		private int count = 0;

		private HelloWorldResource() {
			// set resource identifier
			super("helloWorld", true); // Changed

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
				// r.setPayload(exchange.getRequestText().toUpperCase() + ". ID:
				// " + id);
				r.setPayload("Hello World!");
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
