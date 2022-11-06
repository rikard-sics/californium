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
import java.security.Provider;
import java.security.Security;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
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
import org.eclipse.californium.oscore.OSCoreEndpointContextInfo;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.MultiKey;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Example CoAP server for proxy demonstration.
 * 
 * {@code coap://localhost:5683/coap-target}
 */
public class ExampleCoapServer {

	/* --- OSCORE Security Context information (receiver) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature (EdDSA)
	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;

	// Encryption algorithm for when using signatures
	private final static AlgorithmID algSignEnc = AlgorithmID.AES_CCM_16_64_128;

	// Algorithm for key agreement
	private final static AlgorithmID algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };

	private static final int REPLAY_WINDOW = 32;

	private final static byte[] gm_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"A501781A636F6170733A2F2F6D79736974652E6578616D706C652E636F6D026C67726F75706D616E6167657203781A636F6170733A2F2F646F6D61696E2E6578616D706C652E6F7267041AAB9B154F08A101A4010103272006215820CDE3EFD3BC3F99C9C9EE210415C6CBA55061B5046E963B8A58C9143A61166472");

	private static byte[] sid = new byte[] { 0x52 };
	private static byte[] sid_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B");
	private static byte[] sid_private_key_bytes = new byte[] { (byte) 0x85, 0x7E, (byte) 0xB6, 0x1D, 0x3F, 0x6D, 0x70,
			(byte) 0xA2, 0x78, (byte) 0xA3, 0x67, 0x40, (byte) 0xD1, 0x32, (byte) 0xC0, (byte) 0x99, (byte) 0xF6, 0x28,
			(byte) 0x80, (byte) 0xED, 0x49, 0x7E, 0x27, (byte) 0xBD, (byte) 0xFD, 0x46, (byte) 0x85, (byte) 0xFA, 0x1A,
			0x30, 0x4F, 0x26 };
	private static MultiKey sid_private_key;

	private final static byte[] rid1 = new byte[] { 0x25 };
	private final static byte[] rid1_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
	private static MultiKey rid1_public_key;

	private final static byte[] group_identifier = new byte[] { 0x44, 0x61, 0x6c }; // GID

	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	/* --- OSCORE Security Context information --- */

	/**
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumDemo3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Proxy Demo-Server";

	public static final String RESOURCE = "/coap-target";
	public static final String RESOURCE_EMPTY = "/coap-empty";

	public static final int DEFAULT_COAP_PORT = 5685;
	public static final int DEFAULT_COAP_SECURE_PORT = 5686;

	// For multicast listening
	private static final Logger LOGGER = LoggerFactory.getLogger(ExampleCoapServer.class);
	private static boolean ipv4 = true;
	private static final boolean LOOPBACK = false;
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;
	static int multicastPort = DEFAULT_COAP_PORT;
	static int unicastPort; // Port to use for unicast

	static boolean USE_GROUP_OSCORE = true;

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
	private static final DefinitionsProvider DEFAULTS = (config) -> {
		config.set(CoapConfig.COAP_PORT, DEFAULT_COAP_PORT);
		config.set(CoapConfig.COAP_SECURE_PORT, DEFAULT_COAP_SECURE_PORT);
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
				checkContentFormat(exchange, MediaTypeRegistry.TEXT_PLAIN);

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
				checkContentFormat(exchange, MediaTypeRegistry.TEXT_PLAIN);
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
		path = RESOURCE_EMPTY;
		if (path.startsWith("/")) {
			path = path.substring(1);
		}
		coapServer.add(new CoapResource(path) {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT);
			}

		});

		
		coapServer.add(new MyIpResource(MyIpResource.RESOURCE_NAME, true));
		coapServer.start();
		System.out.println("==================================================");
		System.out.println("== Started CoAP server on port " + port);
		System.out.println("== Request: " + endpoint.getUri() + RESOURCE);
		System.out.println("== Request: " + endpoint.getUri() + RESOURCE_EMPTY);
		System.out.println("==================================================");
	}

	public static Configuration init() {
		return Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
	}

	public static void main(String arg[]) throws IOException, OSException {

		serverId = rand.nextInt(100);
		System.out.println("Generated random server ID: " + serverId);

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		// Set sender & receiver keys for countersignatures
		sid_private_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);
		rid1_public_key = new MultiKey(rid1_public_key_bytes);

		// Check command line arguments (flag to use different sid and sid key)
		if (arg.length != 0) {
			System.out.println("Starting with alternative sid 0x77.");
			sid = new byte[] { 0x77 };
			sid_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
					"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820105B8C6A8C88019BF0C354592934130BAA8007399CC2AC3BE845884613D5BA2E");
			sid_private_key_bytes = new byte[] { 0x7B, (byte) 0xF6, 0x2F, 0x76, 0x7E, (byte) 0xD1, (byte) 0xCF, 0x4C,
					0x60, (byte) 0x91, 0x1F, (byte) 0xC4, (byte) 0x9F, (byte) 0xDF, (byte) 0xCC, (byte) 0xB9,
					(byte) 0xBD, 0x47, (byte) 0xCC, 0x7E, (byte) 0x9F, (byte) 0xAF, 0x41, (byte) 0xCB, 0x66, 0x36,
					(byte) 0x9D, 0x5C, (byte) 0x85, 0x08, (byte) 0xB2, 0x39 };
			sid_private_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);
		} else {
			System.out.println("Starting with sid 0x52.");
		}

		// If OSCORE is being used set the context information
		if (USE_GROUP_OSCORE) {

			byte[] gmPublicKey = gm_public_key_bytes;
			GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
					algSignEnc, algKeyAgreement, gmPublicKey);

			commonCtx.addSenderCtxCcs(sid, sid_private_key);

			commonCtx.addRecipientCtxCcs(rid1, REPLAY_WINDOW, rid1_public_key);

			commonCtx.setResponsesIncludePartialIV(true);

			db.addContext(uriLocal, commonCtx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		/*
		 * try { OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid,
		 * rid, kdf, 32, master_salt, null, MAX_UNFRAGMENTED_SIZE);
		 * db.addContext(uriLocal, ctx);
		 * OSCoreCoapStackFactory.useAsDefault(db); } catch (OSException e) {
		 * System.err.println("Failed to add OSCORE context: " + e);
		 * e.printStackTrace(); }
		 */

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

