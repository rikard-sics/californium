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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
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
 * Performs tests of Group OSCORE message exchanges between a Group OSCORE
 * server and client
 * 
 */
public class GroupOSCoreServerClientTest {

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

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private Endpoint serverEndpoint;
	// private static String serverHostAdd =
	// TestTools.LOCALHOST_EPHEMERAL.getAddress().getHostAddress();
	private static String clientHostAdd = TestTools.LOCALHOST_EPHEMERAL.getAddress().getHostAddress();

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
	private static byte[] gmPublicKey;

	// Keys for client and server (ECDSA full private and public keys)
	private static String clientKeyString = "pgECI1gg2qPzgLjNqAaJWnjh9trtVjX2Gp2mbzyAQLSJt9LD2j8iWCDe8qCLkQ59ZOIwmFVk2oGtfoz4epMe/Fg2nvKQwkQ+XiFYIKb0PXRXX/6hU45EpcXUAQPufU03fkYA+W6gPoiZ+d0YIAEDJg==";
	private static String serverKeyString = "pgECI1ggP2Jr+HhJPSq1U6SebYmOj5EtwhswehlvWwHBFbxJ0ckiWCCukpflkrMHKW6aNaku7GO2ieP3YO5B5/mqGWBIJUEpIyFYIH+jx7yPzktyM/dG/WmygfEk8XYsIFcKgR2TlvKd5+SRIAEDJg==";

	private static final int REPLAY_WINDOW = 32;

	static Random rand;
	private String uri;

	CoapServer server;

	@Before
	public void init() throws IOException {
		gmPublicKey = Base64.decode(gmPublicKeyString);
		EndpointManager.clear();
	}

	// Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(null); // TODO: Better way?
		rand = new Random();
	}

	@After
	public void after() {
		if (null != server) {
			server.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}

	/* --- Client tests follow --- */


	/**
	 * Tests working OSCORE non-confirmable request and response.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testNonConfirmable() throws Exception {

		createServer(false); // No PIV in responses

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(uri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		byte[] token = Bytes.createBytes(rand, 8);
		request.setToken(token);
		request.getOptions().setOscore(Bytes.EMPTY);

		// send a request
		CoapResponse response = client.advanced(request);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());
		assertArrayEquals(token, response.advanced().getTokenBytes());

		// Parse the flag byte group bit (expect non-zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertTrue(groupModeBit != 0);
	}

	/**
	 * Tests OSCORE non-confirmable request where the decryption fails and the
	 * response indicates this.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testDecryptionFail() throws Exception {

		createServer(false); // No PIV in responses

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		// Modify sender key to be incorrect
		GroupSenderCtx clientCtx = (GroupSenderCtx) dbClient.getContext(uri);
		clientCtx.setSenderKey(Bytes.createBytes(rand, 16));

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(uri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		byte[] token = Bytes.createBytes(rand, 8);
		request.setToken(token);
		request.getOptions().setOscore(Bytes.EMPTY);

		// send a request
		CoapResponse response = client.advanced(request);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals("Decryption failed", response.advanced().getPayloadString());
		assertArrayEquals(token, response.advanced().getTokenBytes());

		// No OSCORE option in response
		assertFalse(response.getOptions().hasOscore());
	}

	/**
	 * Tests OSCORE non-confirmable request where the signature verification
	 * fails and the response indicates this.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testSignatureVerificationFail() throws Exception {

		createServer(false); // No PIV in responses

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		// Modify sender private key to be incorrect
		GroupSenderCtx clientCtx = (GroupSenderCtx) dbClient.getContext(uri);
		clientCtx.ownPrivateKey = OneKey.generateKey(algCountersign);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(uri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		byte[] token = Bytes.createBytes(rand, 8);
		request.setToken(token);
		request.getOptions().setOscore(Bytes.EMPTY);

		// send a request
		CoapResponse response = client.advanced(request);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals("Countersignature verification failed", response.advanced().getPayloadString());
		assertArrayEquals(token, response.advanced().getTokenBytes());

		// No OSCORE option in response
		assertFalse(response.getOptions().hasOscore());
	}

	/**
	 * Tests working OSCORE non-confirmable request where the recipient server
	 * does not yet have a recipient context for that RID and dynamically
	 * generates it.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testDynamicRequestContextDerivation() throws Exception {

		createServer(false); // No PIV in responses

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Remove all server recipient contexts
		GroupRecipientCtx serverRecipientCtx = (GroupRecipientCtx) dbServer.getContext(new byte[] { 0x25 }, context_id);
		GroupCtx commonCtx = serverRecipientCtx.commonCtx;
		dbServer.removeContext(serverRecipientCtx);

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(uri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		byte[] token = Bytes.createBytes(rand, 8);
		request.setToken(token);
		request.getOptions().setOscore(Bytes.EMPTY);

		// First send a request without adding the public key of the client to
		// the server group context

		// send a request
		CoapResponse response = client.advanced(request);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals("Security context not found", response.advanced().getPayloadString());
		assertArrayEquals(token, response.advanced().getTokenBytes());

		// No OSCORE option in response
		assertFalse(response.getOptions().hasOscore());

		// Send a second request first adding the public key of the client to
		// the server group context. Now it should work successfully.

		Request request2 = Request.newGet();
		request2.setType(Type.NON);
		byte[] secondToken = Bytes.createBytes(rand, 8);
		request2.setToken(secondToken);
		request2.getOptions().setOscore(Bytes.EMPTY);

		OneKey clientPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(clientKeyString))).PublicKey();
		commonCtx.addPublicKeyForRID(new byte[] { 0x25 }, clientPublicKey);

		response = client.advanced(request2);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());
		assertArrayEquals(secondToken, response.advanced().getTokenBytes());

		// Parse the flag byte group bit (expect non-zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertTrue(groupModeBit != 0);
	}

	/**
	 * Tests working OSCORE non-confirmable request where the client does not
	 * have a recipient context for the RID in the response and dynamically
	 * generates it.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testDynamicResponseContextDerivation() throws Exception {

		createServer(false); // No PIV in responses

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		// Retrive common context
		GroupRecipientCtx clientRecipientCtx1 = (GroupRecipientCtx) dbClient.getContext(new byte[] { 0x77 },
				context_id);
		GroupRecipientCtx clientRecipientCtx2 = (GroupRecipientCtx) dbClient.getContext(new byte[] { 0x66 },
				context_id);
		GroupCtx commonCtx = clientRecipientCtx2.commonCtx;

		// Remove all client recipient contexts
		// dbClient.removeContext(clientRecipientCtx1);
		dbClient.removeContext(clientRecipientCtx2);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		client.setURI(uri);

		// Send a request first adding the public key of the server to
		// the client group context.

		OneKey serverPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(serverKeyString))).PublicKey();
		commonCtx.addPublicKeyForRID(new byte[] { 0x77 }, serverPublicKey);

		// create request
		Request request = Request.newGet();
		request.setType(Type.NON);
		byte[] token = Bytes.createBytes(rand, 8);
		request.setToken(token);
		request.setMID(rand.nextInt(1000));
		request.getOptions().setOscore(Bytes.EMPTY);

		CoapResponse response = client.advanced(request);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());
		assertArrayEquals(token, response.advanced().getTokenBytes());

		// Parse the flag byte group bit (expect non-zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertTrue(groupModeBit != 0);
	}

	/**
	 * Tests working OSCORE non-confirmable request and pairwise response.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testPairwiseResponse() throws Exception {

		createServer(false, true); // No PIV, but pairwise resp.

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(uri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		byte[] token = Bytes.createBytes(rand, 8);
		request.setToken(token);
		request.getOptions().setOscore(Bytes.EMPTY);

		// send a request
		CoapResponse response = client.advanced(request);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());
		assertArrayEquals(token, response.advanced().getTokenBytes());

		// Parse the flag byte group bit (expect zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);
	}

	/**
	 * Tests working OSCORE non-confirmable pairwise request and group response.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testPairwiseRequest() throws Exception {

		createServer(false, false); // No PIV, no pairwise resp.

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Add also the recipient context for RID 0x77
		GroupRecipientCtx clientRecipientCtx2 = (GroupRecipientCtx) dbClient.getContext(new byte[] { 0x66 },
				context_id);
		GroupCtx commonCtx = clientRecipientCtx2.commonCtx;
		byte[] rid1 = new byte[] { 0x77 };
		OneKey serverPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.decode(serverKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid1, REPLAY_WINDOW, serverPublicKey);
		dbClient.addContext(uri, commonCtx);

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(uri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		byte[] token = Bytes.createBytes(rand, 8);
		request.setToken(token);

		// Enable pairwise requests by setting the OSCORE option
		request.getOptions().setOscore(OptionEncoder.set(true, uri, new byte[] { 0x77 }));

		// send a request
		CoapResponse response = client.advanced(request);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());
		assertArrayEquals(token, response.advanced().getTokenBytes());

		// Parse the flag byte group bit (expect non-zero value)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertTrue(groupModeBit != 0);
	}

	/**
	 * Tests OSCORE request replayed message.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testRequestReplay() throws Exception {

		createServer(false); // No PIV in responses

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		// create request
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);

		client.setURI(uri);
		Request request = Request.newGet();
		request.setType(Type.NON);
		byte[] token = Bytes.createBytes(rand, 8);
		request.setToken(token);
		request.getOptions().setOscore(Bytes.EMPTY);

		// send first request
		CoapResponse response = client.advanced(request);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());
		assertArrayEquals(token, response.advanced().getTokenBytes());

		// send second (replayed) request

		GroupSenderCtx clientCtx = (GroupSenderCtx) dbClient.getContext(uri);
		clientCtx.setSenderSeq(0); // Reset sender seq.

		Request request2 = Request.newGet();
		request2.setType(Type.NON);
		byte[] secondToken = Bytes.createBytes(rand, 8);
		request2.setToken(secondToken);
		request2.getOptions().setOscore(Bytes.EMPTY);

		response = client.advanced(request2);
		System.out.println("client sent request");
		System.out.println(Utils.prettyPrint(response));

		// receive response and check
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals("Replay detected", response.advanced().getPayloadString());
		assertArrayEquals(secondToken, response.advanced().getTokenBytes());
	}

	/**
	 * Tests working OSCORE non-confirmable request and response. The server
	 * includes PIV in responses.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testResponsePIV() throws Exception {

		createServer(true); // Include PIV in responses

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		int responseCount = 0;
		int sendCount = 3;

		// send requests
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		client.setURI(uri);
		for (int i = 0; i < sendCount; i++) {

			Request request = Request.newGet();
			request.setType(Type.NON);
			byte[] token = Bytes.createBytes(rand, 8);
			request.setToken(token);
			request.getOptions().setOscore(Bytes.EMPTY);

			// send a request
			CoapResponse response = client.advanced(request);
			System.out.println("client sent request");
			System.out.println(Utils.prettyPrint(response));

			// receive response and check
			assertNotNull("Client received no response", response);
			System.out.println("client received response");
			assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());
			assertArrayEquals(token, response.advanced().getTokenBytes());

			// Extract PIV from option and check
			byte[] partialIV = Arrays.copyOfRange(response.getOptions().getOscore(), 1, 2);
			assertEquals(responseCount, partialIV[0]);

			responseCount++;

		}
	}

	/**
	 * Tests working multiple OSCORE non-confirmable request and response.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testMultipleNonConfirmable() throws Exception {

		createServer(false); // No PIV in responses

		// Set up OSCORE context information for request (client)
		setClientContext();

		// Create client endpoint with OSCORE context DB
		CoapEndpoint clientEndpoint = createClientEndpoint();
		cleanup.add(clientEndpoint);

		int responseCount = 0;
		int sendCount = 10;

		// send requests
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		client.setURI(uri);
		for (int i = 0; i < sendCount; i++) {
			Request request = Request.newGet();
			request.setType(Type.NON);
			byte[] token = Bytes.createBytes(rand, 8);
			request.setToken(token);
			request.getOptions().setOscore(Bytes.EMPTY);

			// send a request
			CoapResponse response = client.advanced(request);
			System.out.println("client sent request");
			System.out.println(Utils.prettyPrint(response));

			// receive response and check
			assertNotNull("Client received no response", response);
			System.out.println("client received response");
			assertEquals(SERVER_RESPONSE, response.advanced().getPayloadString());
			assertArrayEquals(token, response.advanced().getTokenBytes());
			responseCount++;
		}
		assertEquals(sendCount, responseCount);
	}



	/* --- End of client tests --- */

	/**
	 * Creates an endpoint for a client. This endpoint will have the OSCORE CoAP
	 * stack factory enabled.
	 * 
	 * @return an endpoint for a client
	 */
	private CoapEndpoint createClientEndpoint() {
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		builder.setConfiguration(config);
		CoapEndpoint clientEndpoint = builder.build();
		return clientEndpoint;
	}

	/**
	 * Set OSCORE context information for clients
	 * 
	 * @throws OSException on failure to create the contexts
	 * @throws CoseException on failure to create the contexts
	 * @throws IOException on failure to decode GM public key
	 */
	public void setClientContext() throws OSException, CoseException, IOException {
		// Set up OSCORE context information for request (client)
		byte[] sid = new byte[] { 0x25 };
		byte[] rid2 = new byte[] { 0x66 };

		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);

		OneKey clientFullKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(clientKeyString)));
		commonCtx.addSenderCtx(sid, clientFullKey);

		commonCtx.addRecipientCtx(rid2, REPLAY_WINDOW, null);

		dbClient.addContext(uri, commonCtx);
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
	 * @throws IOException on failure to decode GM public key
	 */
	public void setServerContext(boolean responsePartialIV, boolean pairwiseResponse)
			throws OSException, CoseException, IOException {
		// Set up OSCORE context information for response (server)

		byte[] sid = new byte[] { 0x77 };
		byte[] rid = new byte[] { 0x25 };

		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);

		OneKey serverFullKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(serverKeyString)));
		commonCtx.addSenderCtx(sid, serverFullKey);

		OneKey clientPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(clientKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, clientPublicKey);

		commonCtx.setResponsesIncludePartialIV(responsePartialIV);
		commonCtx.setPairwiseModeResponses(pairwiseResponse);

		dbServer.addContext(clientHostAdd, commonCtx);
	}

	public void createServer(boolean responsePartialIV) throws OSException, CoseException, IOException {
		createServer(responsePartialIV, false);
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
		// Do not create server if it is already running
		if (serverEndpoint != null) {
			// TODO: Check if this ever happens
			return;
		}

		// Do not create server if it is already running
		if (serverEndpoint != null) {
			// TODO: Check if this ever happens
			return;
		}

		setServerContext(responsePartialIV, pairwiseResponse);

		// Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCustomCoapStackArgument(dbServer);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);

		/** --- Resources for tests follow --- **/

		// Resource for OSCORE test resources
		CoapResource oscore_hello = new CoapResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello/1 resource");
				Response r = new Response(ResponseCode.CONTENT);

				if (serverChecksCorrect(exchange.advanced().getRequest())) {
					r.setPayload(SERVER_RESPONSE);
				} else {
					r.setPayload("error: incorrect message from client!");
				}

				exchange.respond(r);
			}
		};

		// Creating resource hierarchy
		server.add(oscore_hello);

		/** --- End of resources for tests **/

		// Start server
		server.start();
		cleanup.add(server);

		uri = TestTools.getUri(serverEndpoint, TARGET);
	}

	private boolean serverChecksCorrect(Request request) {
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
