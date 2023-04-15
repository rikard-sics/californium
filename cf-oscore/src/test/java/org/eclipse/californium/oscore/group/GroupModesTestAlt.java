/*******************************************************************************
 * Copyright (c) 2023 RISE SICS and others.
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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Base64;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreEndpointContextInfo;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import com.upokecenter.cbor.CBORObject;

/**
 * Performs tests of the following cases that an application may send a Group
 * OSCORE request:
 * 
 * - Unicast Group mode request - Unicast Pairwise mode request - Multicast
 * Group mode request - Multicast Pairwise mode request
 * 
 * 
 */
public class GroupModesTestAlt {

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

	/**
	 * Define CoAP network rule for JUnit tests
	 */
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	/**
	 * Thread cleanup rule
	 */
	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	/**
	 * Test name logging rule
	 */
	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	/**
	 * Multicast address to listen to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	private Endpoint serverEndpoint;

	private static final String TARGET = "hello";
	private static String SERVER_RESPONSE_PAIRWISE_REQUEST = "Pairwise request received!";
	private static String SERVER_RESPONSE_GROUP_REQUEST = "Group mode request received!";

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

	private byte[] clientSenderId = new byte[] { 0x44 };

	// Group OSCORE specific values for the countersignature (ECDSA 256)
	private final static AlgorithmID algCountersign = AlgorithmID.ECDSA_256;

	// Key for the GM
	private static String gmPublicKeyString = "pQF4GmNvYXBzOi8vbXlzaXRlLmV4YW1wbGUuY29tAmxncm91cG1hbmFnZXIDeBpjb2FwczovL2RvbWFpbi5leGFtcGxlLm9yZwQaq5sVTwihAaQDJwEBIAYhWCDN4+/TvD+ZycnuIQQVxsulUGG1BG6WO4pYyRQ6YRZkcg==";
	private static byte[] gmPublicKey;

	// Keys for client and server (ECDSA full private and public keys)
	private static String clientKeyString = "pgECI1gg2qPzgLjNqAaJWnjh9trtVjX2Gp2mbzyAQLSJt9LD2j8iWCDe8qCLkQ59ZOIwmFVk2oGtfoz4epMe/Fg2nvKQwkQ+XiFYIKb0PXRXX/6hU45EpcXUAQPufU03fkYA+W6gPoiZ+d0YIAEDJg==";
	private static String serverKeyString = "pgECI1ggP2Jr+HhJPSq1U6SebYmOj5EtwhswehlvWwHBFbxJ0ckiWCCukpflkrMHKW6aNaku7GO2ieP3YO5B5/mqGWBIJUEpIyFYIH+jx7yPzktyM/dG/WmygfEk8XYsIFcKgR2TlvKd5+SRIAEDJg==";

	private static final int REPLAY_WINDOW = 32;

	private String multicastUri;
	private String unicastUri;
	private static CoapServer server;

	/**
	 * Initialize parameters before test
	 * 
	 * @throws IOException on initialization failure
	 */
	@Before
	public void init() throws IOException {
		EndpointManager.clear();
		dbClient.purge();
		dbServer.purge();

		gmPublicKey = Base64.decode(gmPublicKeyString);
	}

	/**
	 * Use the OSCORE stack factory
	 */
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(null); // TODO: Better way?
	}

	/**
	 * Shut down the server after a test is finished
	 */
	@After
	public void shutdownServer() {
		server.destroy();
	}

	/* --- Client tests follow --- */

	/**
	 * Tests sending a Group OSCORE multicast request using Group Mode.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testMulticastGroupMode() throws Exception {

		createServer(false, true); // No PIV and pairwise response

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		builder.setConfiguration(config);
		CoapEndpoint clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);

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
		CoapResponse response = client.advanced(request);

		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE_GROUP_REQUEST, response.advanced().getPayloadString());

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

		createServer(false, true); // No PIV and pairwise response

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		builder.setConfiguration(config);
		CoapEndpoint clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(multicastUri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		request.getOptions().setOscore(OptionEncoder.set(true, multicastUri, new byte[] { 0x77 }));

		// sends a multicast request
		CoapResponse response = client.advanced(request);

		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE_PAIRWISE_REQUEST, response.advanced().getPayloadString());

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

		createServer(false, true); // No PIV and pairwise response

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		builder.setConfiguration(config);
		CoapEndpoint clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);

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
		assertEquals(SERVER_RESPONSE_PAIRWISE_REQUEST, response.advanced().getPayloadString());

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

		createServer(false, true); // No PIV and pairwise response

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		builder.setConfiguration(config);
		CoapEndpoint clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);

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
		assertEquals(SERVER_RESPONSE_GROUP_REQUEST, response.advanced().getPayloadString());

		// Parse the flag byte group bit (expect zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);
	}

	/* --- End of client tests --- */

	/**
	 * Set OSCORE context information for clients
	 * 
	 * @throws OSException on failure to create the contexts
	 * @throws CoseException on failure to create the contexts
	 * @throws IOException on test failure
	 */
	public void setClientContext() throws OSException, CoseException, IOException {
		// Set up OSCORE context information for request (client)

		byte[] sid = clientSenderId;
		byte[] rid1 = new byte[] { 0x77 };
		byte[] rid2 = new byte[] { 0x66 };

		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);

		OneKey clientFullKey = new OneKey(CBORObject.DecodeFromBytes(Base64.decode(clientKeyString)));
		commonCtx.addSenderCtx(sid, clientFullKey);

		OneKey serverPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.decode(serverKeyString))).PublicKey();
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
	 * @throws IOException on test failure
	 */
	public void setServerContext(boolean responsePartialIV, boolean pairwiseResponse)
			throws OSException, CoseException, IOException {
		// Set up OSCORE context information for response (server)

		byte[] sid = new byte[] { 0x77 };
		byte[] rid = clientSenderId;

		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);

		OneKey serverFullKey = new OneKey(CBORObject.DecodeFromBytes(Base64.decode(serverKeyString)));
		commonCtx.addSenderCtx(sid, serverFullKey);

		OneKey clientPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.decode(clientKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, clientPublicKey);

		commonCtx.setResponsesIncludePartialIV(responsePartialIV);
		commonCtx.setPairwiseModeResponses(pairwiseResponse);

		dbServer.addContext("", commonCtx);
	}

	/**
	 * Creates server with resources to test Group OSCORE functionality
	 * 
	 * @param responsePartialIV if responses should include a Partial IV
	 * @param pairwiseResponse if responses should be in pairwise mode
	 * 
	 * @throws OSException on test failure
	 * @throws CoseException on test failure
	 * @throws IOException on test failure
	 */
	public void createServer(boolean responsePartialIV, boolean pairwiseResponse)
			throws OSException, CoseException, IOException {

		setServerContext(responsePartialIV, pairwiseResponse);

		// Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCustomCoapStackArgument(dbServer);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		cleanup.add(serverEndpoint);

		/** --- Resources for tests follow --- **/

		// Resource for OSCORE test resources
		CoapResource oscore_hello = new CoapResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello/1 resource");
				Response r = new Response(ResponseCode.CONTENT);

				// Determine if the request used group or pairwise mode. The
				// cryptographic context ID contains the OSCORE option value.
				byte[] requestOscoreOption = exchange.advanced().getCryptographicContextID();
				boolean requestUsedPairwise = (requestOscoreOption[0] & 0x20) == 0;

				Request request = exchange.advanced().getRequest();
				if (!serverChecksCorrect(request)) {
					r.setPayload("error: incorrect message from client!");
				} else if (requestUsedPairwise) {
					r.setPayload(SERVER_RESPONSE_PAIRWISE_REQUEST);
				} else {
					r.setPayload(SERVER_RESPONSE_GROUP_REQUEST);
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

}
