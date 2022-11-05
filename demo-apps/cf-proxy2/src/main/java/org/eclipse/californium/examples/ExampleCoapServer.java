/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.File;
import java.io.IOException;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.MyIpResource;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreEndpointContextInfo;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Example CoAP server for proxy demonstration.
 * 
 * {@code coap://localhost:5683/coap-target}
 */
public class ExampleCoapServer {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[] { 0x01 };
	private final static byte[] rid = new byte[0];

	/**
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumDemo3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Proxy Demo-Server";

	public static final String RESOURCE = "/coap-target";

	public static final int DEFAULT_COAP_PORT = 5685;
	public static final int DEFAULT_COAP_SECURE_PORT = 5686;

	// For multicast listening
	private static final Logger LOGGER = LoggerFactory.getLogger(ExampleCoapServer.class);
	private static boolean ipv4 = true;
	private static final boolean LOOPBACK = false;
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;
	static int multicastPort = DEFAULT_COAP_PORT;
	static int unicastPort; // Port to use for unicast

	static Random rand = new Random();
	private static int serverId;

	static {
		CoapConfig.register();
		UdpConfig.register();
		TcpConfig.register();
		DtlsConfig.register();
	}

	/**
	 * Special configuration defaults handler.
	 */
	private static final DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.COAP_PORT, DEFAULT_COAP_PORT);
			config.set(CoapConfig.COAP_SECURE_PORT, DEFAULT_COAP_SECURE_PORT);
		}
	};

	private CoapServer coapServer;

	public ExampleCoapServer(Configuration config, final int port) throws IOException {
		this(CoapEndpoint.builder().setConfiguration(config).setPort(port).build());
	}

	public ExampleCoapServer(CoapEndpoint endpoint) throws IOException {

		String path = RESOURCE;
		if (path.startsWith("/")) {
			path = path.substring(1);
		}

		InetSocketAddress address = endpoint.getAddress();
		final int port = address.getPort();
		final String scheme = endpoint.getUri().getScheme();
		// Create CoAP Server on PORT with a target resource
		coapServer = new CoapServer(endpoint.getConfig());
		// coapServer.addEndpoint(endpoint); //Re-add for unicast support

		// Use a different port for the response to multicast requests
		int responsePort = port + serverId;
		createEndpoints(coapServer, responsePort, multicastPort, endpoint.getConfig());
		coapServer.add(new CoapResource(path) {

			private final AtomicInteger counter = new AtomicInteger();

			@Override
			public void handleGET(CoapExchange exchange) {

				System.out.println("=== Receiving incoming request ===");

				System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
				System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());
				System.out.println("Request URI: " + exchange.advanced().getCurrentRequest().getURI());

				MapBasedEndpointContext mapCtx = (MapBasedEndpointContext) exchange.advanced().getRequest()
						.getSourceContext();
				String reqKid = mapCtx.getString(OSCoreEndpointContextInfo.OSCORE_RECIPIENT_ID);
				System.out.print("Incoming request uses OSCORE: ");
				if (reqKid != null) {
					System.out.println("true");
				} else {
					System.out.println("false");
				}

				System.out.println("=== End Receiving incoming request ===");

				String payload = "Hi! I am the " + scheme + " server on port " + port + ". Request "
						+ counter.incrementAndGet() + " with ID: " + serverId + ".";
				exchange.setMaxAge(15);
				int hash = payload.hashCode();
				DatagramWriter etag = new DatagramWriter(4);
				etag.write(hash, 32);
				exchange.setETag(etag.toByteArray());
				exchange.respond(ResponseCode.CONTENT, payload, MediaTypeRegistry.TEXT_PLAIN);
			}

			@Override
			public void handlePOST(CoapExchange exchange) {
				String message = exchange.advanced().getRequest().getPayloadString();
				String payload = "Hi, " + message + "! I am the " + scheme + " server on port " + port + ". Request "
						+ counter.incrementAndGet() + ".";
				exchange.setMaxAge(1);
				int hash = payload.hashCode();
				DatagramWriter etag = new DatagramWriter(4);
				etag.write(hash, 32);
				exchange.setETag(etag.toByteArray());
				exchange.respond(ResponseCode.CONTENT, payload, MediaTypeRegistry.TEXT_PLAIN);
			}

		});
		coapServer.add(new MyIpResource(MyIpResource.RESOURCE_NAME, true));
		coapServer.start();
		System.out.println("==================================================");
		System.out.println("== Started CoAP server on port " + port);
		System.out.println("== Request: " + endpoint.getUri() + RESOURCE);
		System.out.println("==================================================");
	}

	public static Configuration init() {
		return Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
	}

	public static void main(String arg[]) throws IOException {

		serverId = rand.nextInt(100);
		System.out.println("Generated random server ID: " + serverId);

		try {
			OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, null,
					MAX_UNFRAGMENTED_SIZE);
			db.addContext(uriLocal, ctx);
			OSCoreCoapStackFactory.useAsDefault(db);
		} catch (OSException e) {
			System.err.println("Failed to add OSCORE context: " + e);
			e.printStackTrace();
		}

		Configuration config = init();
		int port;
		if (arg.length > 0) {
			port = Integer.parseInt(arg[0]);
		} else {
			port = config.get(CoapConfig.COAP_PORT);
		}
		new ExampleCoapServer(config, port);
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
	private static void createEndpoints(CoapServer server, int unicastPort, int multicastPort, Configuration config) {
		// UDPConnector udpConnector = new UDPConnector(new
		// InetSocketAddress(unicastPort));
		// udpConnector.setReuseAddress(true);
		// CoapEndpoint coapEndpoint = new
		// CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector).build();

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

