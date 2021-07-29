/*******************************************************************************
 * Copyright (c) 2020 RISE SICS and others.
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
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 * 
 * Contributors: 
 *    Rikard Höglund (RISE SICS) - testing Group OSCORE messages
 ******************************************************************************/
package org.eclipse.californium.oscore.group;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import java.io.File;
import java.io.IOException;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreEndpointContextInfo;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

/**
 * Performs tests of the following cases that an application may send a
 * Group OSCORE request:
 * 
 * - Unicast Group mode request
 * - Unicast Pairwise mode request
 * - Multicast Group mode request
 * - Multicast Pairwise mode request
 * 
 * 
 */
public class GroupModesTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(GroupModesTest.class);

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

	// Use IPv4
	private static boolean ipv4 = true;
	private static final boolean LOOPBACK = false;

	/**
	 * Time to wait for replies to the multicast request
	 */
	private static final int HANDLER_TIMEOUT = 1000;

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	/**
	 * Multicast address to listen to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	// static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	private static Endpoint serverEndpoint;
	private static Endpoint clientEndpoint;

	private static final String TARGET = "hello";
	private static String SERVER_RESPONSE = "Hello World!";

	// OSCORE context information shared between server and client
	private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static HashMapCtxDB dbServer = new HashMapCtxDB();

	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] context_id = { 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74 };

	// Group OSCORE specific values for the countersignature (ECDSA 256)
	private final static AlgorithmID algCountersign = AlgorithmID.ECDSA_256;

	// Key for the GM
	private static String gmPublicKeyString = "pQF4GmNvYXBzOi8vbXlzaXRlLmV4YW1wbGUuY29tAmxncm91cG1hbmFnZXIDeBpjb2FwczovL2RvbWFpbi5leGFtcGxlLm9yZwQaq5sVTwihAaQDJwEBIAYhWCDN4+/TvD+ZycnuIQQVxsulUGG1BG6WO4pYyRQ6YRZkcg==";
	private static byte[] gmPublicKey = DatatypeConverter.parseBase64Binary(gmPublicKeyString);

	// Keys for client and server (ECDSA full private and public keys)
	private static String clientKeyString = "pgECI1gg2qPzgLjNqAaJWnjh9trtVjX2Gp2mbzyAQLSJt9LD2j8iWCDe8qCLkQ59ZOIwmFVk2oGtfoz4epMe/Fg2nvKQwkQ+XiFYIKb0PXRXX/6hU45EpcXUAQPufU03fkYA+W6gPoiZ+d0YIAEDJg==";
	private static String serverKeyString = "pgECI1ggP2Jr+HhJPSq1U6SebYmOj5EtwhswehlvWwHBFbxJ0ckiWCCukpflkrMHKW6aNaku7GO2ieP3YO5B5/mqGWBIJUEpIyFYIH+jx7yPzktyM/dG/WmygfEk8XYsIFcKgR2TlvKd5+SRIAEDJg==";

	private static final int REPLAY_WINDOW = 32;

	private static String multicastUri;
	private static String unicastUri;

	@Before
	public void init() {
		EndpointManager.clear();
	}

	// Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() throws InterruptedException, OSException, CoseException {
		OSCoreCoapStackFactory.useAsDefault(null); // TODO: Better way?
		clientEndpoint = createClientEndpoint();
		createServer();
	}

	/* --- Client tests follow --- */

	/**
	 * Tests sending a Group OSCORE multicast request using Group Mode.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testMulticastGroupMode() throws Exception {

		// Set up OSCORE context information for client & server
		setClientContext();
		setServerContext(false, true);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(multicastUri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		request.getOptions().setOscore(Bytes.EMPTY);
		// request.getOptions().setOscore(OptionEncoder.set(false,
		// multicastUri));

		// sends a multicast request
		MultiCoapHandler handler = new MultiCoapHandler();
		client.advanced(handler, request);
		while (handler.waitOn(HANDLER_TIMEOUT)) {
			// Wait for responses
		}

		// check the response
		List<CoapResponse> responsesList = handler.getResponses();
		CoapResponse response = responsesList.get(0);

		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());

		// Parse the flag byte group bit (expect zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);
	}

	/**
	 * Tests sending a Group OSCORE multicast request using Pairwise Mode.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testMulticastPairwiseMode() throws Exception {

		// Set up OSCORE context information for client & server
		setClientContext();
		setServerContext(false, true);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(multicastUri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		request.getOptions().setOscore(OptionEncoder.set(true, multicastUri, new byte[] { 0x77 }));

		// sends a multicast request
		MultiCoapHandler handler = new MultiCoapHandler();
		client.advanced(handler, request);
		while (handler.waitOn(HANDLER_TIMEOUT)) {
			// Wait for responses
		}

		// check the response
		List<CoapResponse> responsesList = handler.getResponses();
		CoapResponse response = responsesList.get(0);

		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());

		// Parse the flag byte group bit (expect zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);
	}

	/**
	 * Tests sending a Group OSCORE unicast request using Pairwise Mode.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testUnicastPairwiseMode() throws Exception {

		// Set up OSCORE context information for client & server
		setClientContext();
		setServerContext(false, true);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(unicastUri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		request.getOptions().setOscore(OptionEncoder.set(true, multicastUri, new byte[] { 0x77 }));

		// sends a request
		CoapResponse response = client.advanced(request);

		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());

		// Parse the flag byte group bit (expect zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);
	}

	/**
	 * Tests sending a Group OSCORE unicast request using Group Mode.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testUnicastGroupMode() throws Exception {

		// Set up OSCORE context information for client & server
		setClientContext();
		setServerContext(false, true);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(unicastUri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		request.getOptions().setOscore(OptionEncoder.set(false, multicastUri));

		// sends a request
		CoapResponse response = client.advanced(request);

		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());

		// Parse the flag byte group bit (expect zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);
	}

	private static class MultiCoapHandler implements CoapHandler {

		List<CoapResponse> responsesList = new ArrayList<CoapResponse>();

		private boolean on;

		public List<CoapResponse> getResponses() {
			return responsesList;
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

			System.out.println(Utils.prettyPrint(response));

			responsesList.add(response);
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	}

	/* --- End of client tests --- */

	/**
	 * Creates an endpoint for a client. This endpoint will have the OSCORE
	 * stack factory enabled.
	 * 
	 * @return an endpoint for a client
	 */
	private static CoapEndpoint createClientEndpoint() {
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		builder.setNetworkConfig(config);
		CoapEndpoint clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);
		return clientEndpoint;
	}

	/**
	 * Set OSCORE context information for clients
	 * 
	 * @throws OSException on failure to create the contexts
	 * @throws CoseException on failure to create the contexts
	 */
	public void setClientContext() throws OSException, CoseException {
		// Set up OSCORE context information for request (client)
		byte[] sid = new byte[] { 0x25 };
		byte[] rid1 = new byte[] { 0x77 };
		byte[] rid2 = new byte[] { 0x66 };

		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);

		OneKey clientFullKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(clientKeyString)));
		commonCtx.addSenderCtx(sid, clientFullKey);

		OneKey serverPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(serverKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid1, REPLAY_WINDOW, serverPublicKey);
		commonCtx.addRecipientCtx(rid2, REPLAY_WINDOW, null);

		dbClient.addContext(multicastUri, commonCtx);
	}

	/* Server related code below */

	/**
	 * (Re)sets the OSCORE context information for the server
	 * 
	 * @param responsePartialIV if responses should include a Partial IV
	 * @param pairwiseResponse if responses should be in pairwise mode
	 * 
	 * @throws OSException on failure to create the contexts
	 * @throws CoseException on failure to create the contexts
	 */
	public void setServerContext(boolean responsePartialIV, boolean pairwiseResponse)
			throws OSException, CoseException {
		// Set up OSCORE context information for response (server)

		byte[] sid = new byte[] { 0x77 };
		byte[] rid = new byte[] { 0x25 };

		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);

		OneKey serverFullKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(serverKeyString)));
		commonCtx.addSenderCtx(sid, serverFullKey);

		OneKey clientPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(clientKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, clientPublicKey);

		commonCtx.setResponsesIncludePartialIV(responsePartialIV);
		commonCtx.setPairwiseModeResponses(pairwiseResponse);

		dbServer.addContext("", commonCtx);
	}

	/**
	 * Creates server with resources to test Group OSCORE functionality
	 * 
	 * @throws InterruptedException if resource update task fails
	 * @throws OSException on test failure
	 * @throws CoseException on test failure
	 */
	public static void createServer()
			throws InterruptedException, OSException, CoseException {

		// Create server and multicast configuration
		CoapServer server = new CoapServer();
		NetworkConfig config = NetworkConfig.getStandard();
		createEndpoints(server, CoAP.DEFAULT_COAP_PORT, CoAP.DEFAULT_COAP_PORT, config);
		serverEndpoint = server.getEndpoint(CoAP.DEFAULT_COAP_PORT);

		/** --- Resources for tests follow --- **/

		// Resource for OSCORE test resources
		CoapResource oscore_hello = new CoapResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello/1 resource");
				Response r = new Response(ResponseCode.CONTENT);

				Request request = exchange.advanced().getRequest();
				if (serverChecksCorrect(request)) {
					r.setPayload(SERVER_RESPONSE);
				} else {
					r.setPayload("error: incorrect message from client!");
				}

				exchange.respond(r);
				serverEndpoint.clear();
			}
		};

		// Creating resource hierarchy
		server.add(oscore_hello);

		/** --- End of resources for tests **/

		// Start server
		server.start();
		cleanup.add(server);

		multicastUri = TestTools.getUri(serverEndpoint, TARGET);
		unicastUri = TestTools.getUri(
				new InetSocketAddress(InetAddress.getLoopbackAddress(), serverEndpoint.getAddress().getPort()), TARGET);
	}

	private static boolean serverChecksCorrect(Request request) {

		// Check that request is non-confirmable
		if (request.isConfirmable() == true) {
			return false;
		}

		// Check that request contains an ID Context
		byte[] requestIdContext = null;
		EndpointContext endpointContext = request.getSourceContext();
		if (endpointContext instanceof MapBasedEndpointContext) {
			EndpointContext mapEndpointContext = endpointContext;
			requestIdContext = StringUtil
					.hex2ByteArray(mapEndpointContext.getString(OSCoreEndpointContextInfo.OSCORE_CONTEXT_ID));
		}
		if (!Arrays.equals(requestIdContext, context_id)) {
			return false;
		}

		return true;
	}

	/**
	 * From MulticastTestServer
	 * 
	 * @param server
	 * @param unicastPort
	 * @param multicastPort
	 * @param config
	 */
	private static void createEndpoints(CoapServer server, int unicastPort, int multicastPort, NetworkConfig config) {
		// UDPConnector udpConnector = new UDPConnector(new
		// InetSocketAddress(unicastPort));
		// udpConnector.setReuseAddress(true);
		// CoapEndpoint coapEndpoint = new
		// CoapEndpoint.Builder().setNetworkConfig(config).setConnector(udpConnector).build();

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
			UDPConnector udpConnector = new UDPConnector(new InetSocketAddress(ipv6, unicastPort));
			udpConnector.setReuseAddress(true);
			CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(udpConnector)
					.setCustomCoapStackArgument(dbServer)
					.build();

			builder = new UdpMulticastConnector.Builder().setLocalAddress(CoAP.MULTICAST_IPV6_SITELOCAL, multicastPort)
					.addMulticastGroup(CoAP.MULTICAST_IPV6_SITELOCAL, networkInterface);
			createReceiver(builder, udpConnector);

			/*
			 * https://bugs.openjdk.java.net/browse/JDK-8210493 link-local
			 * multicast is broken
			 */
			builder = new UdpMulticastConnector.Builder().setLocalAddress(CoAP.MULTICAST_IPV6_LINKLOCAL, multicastPort)
					.addMulticastGroup(CoAP.MULTICAST_IPV6_LINKLOCAL, networkInterface);
			createReceiver(builder, udpConnector);

			server.addEndpoint(coapEndpoint);
			LOGGER.info("IPv6 - multicast");
		}

		if (ipv4 && NetworkInterfacesUtil.isAnyIpv4()) {
			Inet4Address ipv4 = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
			LOGGER.info("Multicast: IPv4 Network Address: {}", StringUtil.toString(ipv4));
			UDPConnector udpConnector = new UDPConnector(new InetSocketAddress(ipv4, unicastPort));
			udpConnector.setReuseAddress(true);
			CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(udpConnector)
					.setCustomCoapStackArgument(dbServer)
					.build();

			builder = new UdpMulticastConnector.Builder().setLocalAddress(CoAP.MULTICAST_IPV4, multicastPort)
					.addMulticastGroup(CoAP.MULTICAST_IPV4, networkInterface);
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
				new InetSocketAddress(InetAddress.getLoopbackAddress(), unicastPort));
		udpConnector.setReuseAddress(true);
		CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(udpConnector)
				.setCustomCoapStackArgument(dbServer)
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
