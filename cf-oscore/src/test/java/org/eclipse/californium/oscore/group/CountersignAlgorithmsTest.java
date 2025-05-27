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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import java.io.File;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
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
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;

import org.eclipse.californium.elements.util.Bytes;
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

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Tests for the various supported countersignature algorithms.
 * 
 */
public class CountersignAlgorithmsTest {

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

	// Key for the GM
	private static String gmPublicKeyString = "pQF4GmNvYXBzOi8vbXlzaXRlLmV4YW1wbGUuY29tAmxncm91cG1hbmFnZXIDeBpjb2FwczovL2RvbWFpbi5leGFtcGxlLm9yZwQaq5sVTwihAaQDJwEBIAYhWCDN4+/TvD+ZycnuIQQVxsulUGG1BG6WO4pYyRQ6YRZkcg==";
	private static byte[] gmPublicKey;

	// Keys for client and server
	private static String clientKeyEcdsa256 = "pgECI1gg2qPzgLjNqAaJWnjh9trtVjX2Gp2mbzyAQLSJt9LD2j8iWCDe8qCLkQ59ZOIwmFVk2oGtfoz4epMe/Fg2nvKQwkQ+XiFYIKb0PXRXX/6hU45EpcXUAQPufU03fkYA+W6gPoiZ+d0YIAEDJg==";
	private static String serverKeyEcdsa256 = "pgECI1ggP2Jr+HhJPSq1U6SebYmOj5EtwhswehlvWwHBFbxJ0ckiWCCukpflkrMHKW6aNaku7GO2ieP3YO5B5/mqGWBIJUEpIyFYIH+jx7yPzktyM/dG/WmygfEk8XYsIFcKgR2TlvKd5+SRIAEDJg==";

	private static String clientKeyEcdsa384 = "pgECI1gwAgWQ/4ImiShAyxPkB1oHXBMjLGwT8Q9TceZR0YdqHD5bDCl1h/DXF7QQfHO0zHQGIlgwx5Ei3+jFF6bf0QhwPHWfkuEuKuPuhbCKu0H6wodkuRr9hmy+etxGcHG0Fe7d5sS6IVgwhAbXRh6uZ1ITLwANrdNZLzsutA+e7GtYaB/nZyOGEIIidf5XTsZlUnzohQ0a0RR0IAIDOCI=";
	private static String serverKeyEcdsa384 = "pgECI1gwCU6mMkLEntqbcBF3Z0PIZCHkh7BKHnZA9MDTgqi8IYum1XhFkFRoe4H08m2FnscfIlgw4RYp7n03HcEBY9qKFDzu7DrnckO0y2YBhr+B6+//+yWaiNSdGtW4lxqEKR9sCtO+IVgwKmhLrzB1fsFwlJU6QpVuYDd0uQ84nlw3okPYmh/CFzj6wYIKioWIXpMHJSyknJm0IAIDOCI=";

	private static String clientKeyEcdsa512 = "pgECI1hCAaPhhBunYrVPQaxxaeTaMJOjV2kwOTJD1gmiKVtpYiBzKT0AHU9SNVbjFw/yYCcpNWRi+iNoC/bAl5bMwgeWGZORIlhCAfzlMRLiFxpDA5ZyczICw/5ddmM092KBN9mMrnEnyI4sNMKKboycNrglKCB0McCrji2vWmNuBjaLh29erOLk4OTQIVhCAYbbcMVRG1hyvWEAjjrzCgK0zULHo39ySL8lp3o9v4imEUZfFqqWeAAX/WTObIXZaDtEgRdjgNdJgpFXlNjUqg1/IAMDOCM=";
	private static String serverKeyEcdsa512 = "pgECI1hCAWsXMKqbF9Pwtvdf4MTzMv+NUAPucIIR/U6zb86WLVuda80AxMPxcNf5mvunJGRL+iVYqgr1RpDKogbKNV344JtHIlhCASMotepilEexK0KczPfZ6AUJ2VWTRFSNhNJjd1Mx8W5d6s8IcrvonBTk0lcJFLOdbTBtTX6sjVivWxpgjBtaraDTIVhCAACUoZprayAaiOZxZZ8lUznHWeglGJ6poL73e7K9eBOh3IzzlD6IYlz/mjvRFfOAtPj1nJbwAAvNHxOYDg5kZje6IAMDOCM=";

	private static String clientKeyEddsa = "pQMnAQEgBiFYIHfsNYwdNE5B7g6HuDg9I6IJms05vfmJzkW1Loh0YzibI1gghX62HT9tcKJ4o2dA0TLAmfYogO1Jfie9/UaF+howTyY=";
	private static String serverKeyEddsa = "pQMnAQEgBiFYIAaekSuDljrMWUG2NUaGfewQbluQUfLuFPO8XMlhrNQ6I1ggZHFNQaJAth2NgjUCcXqwiMn0r2/JhEVT5K1MQsxzUjk=";

	private static final int REPLAY_WINDOW = 32;

	static Random rand;
	private String uri;

	/**
	 * Initialize GM public key before tests
	 * 
	 * @throws IOException on setup failure
	 */
	@Before
	public void init() throws IOException {
		gmPublicKey = StringUtil.base64ToByteArray(gmPublicKeyString);
		EndpointManager.clear();
	}

	/**
	 * Use the OSCORE stack factory
	 */
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(null); // TODO: Better way?
		rand = new Random();
	}

	/* --- Client tests follow --- */

	/**
	 * Test countersignature using ECDSA P-256
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testECDSA256() throws Exception {

		String serverKeyString = serverKeyEcdsa256;
		String clientKeyString = clientKeyEcdsa256;

		OneKey serverKey = new OneKey(CBORObject.DecodeFromBytes(StringUtil.base64ToByteArray(serverKeyString)));
		OneKey clientKey = new OneKey(CBORObject.DecodeFromBytes(StringUtil.base64ToByteArray(clientKeyString)));

		// Check the properties of the decoded keys

		// Algorithm
		assertEquals(AlgorithmID.ECDSA_256.AsCBOR(), serverKey.get(KeyKeys.Algorithm));
		assertEquals(AlgorithmID.ECDSA_256.AsCBOR(), clientKey.get(KeyKeys.Algorithm));

		// Key type
		assertEquals(KeyKeys.KeyType_EC2, serverKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_EC2, clientKey.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.EC2_P256, serverKey.get(KeyKeys.EC2_Curve));
		assertEquals(KeyKeys.EC2_P256, clientKey.get(KeyKeys.EC2_Curve));

		sendRequest(AlgorithmID.ECDSA_256, clientKey, serverKey);
	}

	/**
	 * Test countersignature using ECDSA P-384
	 * 
	 * @throws Exception on test failure
	 */

	@Test
	public void testECDSA384() throws Exception {

		String serverKeyString = clientKeyEcdsa384;
		String clientKeyString = serverKeyEcdsa384;

		OneKey serverKey = new OneKey(CBORObject.DecodeFromBytes(StringUtil.base64ToByteArray(serverKeyString)));
		OneKey clientKey = new OneKey(CBORObject.DecodeFromBytes(StringUtil.base64ToByteArray(clientKeyString)));

		// Check the properties of the decoded keys

		// Algorithm
		assertEquals(AlgorithmID.ECDSA_384.AsCBOR(), serverKey.get(KeyKeys.Algorithm));
		assertEquals(AlgorithmID.ECDSA_384.AsCBOR(), clientKey.get(KeyKeys.Algorithm));

		// Key type
		assertEquals(KeyKeys.KeyType_EC2, serverKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_EC2, clientKey.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.EC2_P384, serverKey.get(KeyKeys.EC2_Curve));
		assertEquals(KeyKeys.EC2_P384, clientKey.get(KeyKeys.EC2_Curve));

		sendRequest(AlgorithmID.ECDSA_384, clientKey, serverKey);
	}

	/**
	 * Test countersignature using ECDSA P-512
	 * 
	 * @throws Exception on test failure
	 */

	@Test
	public void testECDSA512() throws Exception {

		String serverKeyString = clientKeyEcdsa512;
		String clientKeyString = serverKeyEcdsa512;

		OneKey serverKey = new OneKey(CBORObject.DecodeFromBytes(StringUtil.base64ToByteArray(serverKeyString)));
		OneKey clientKey = new OneKey(CBORObject.DecodeFromBytes(StringUtil.base64ToByteArray(clientKeyString)));

		// Check the properties of the decoded keys

		// Algorithm
		assertEquals(AlgorithmID.ECDSA_512.AsCBOR(), serverKey.get(KeyKeys.Algorithm));
		assertEquals(AlgorithmID.ECDSA_512.AsCBOR(), clientKey.get(KeyKeys.Algorithm));

		// Key type
		assertEquals(KeyKeys.KeyType_EC2, serverKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_EC2, clientKey.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.EC2_P521, serverKey.get(KeyKeys.EC2_Curve));
		assertEquals(KeyKeys.EC2_P521, clientKey.get(KeyKeys.EC2_Curve));

		sendRequest(AlgorithmID.ECDSA_512, clientKey, serverKey);
	}

	/**
	 * Test countersignature using EdDSA Ed25519
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testEDDSA() throws Exception {
		// Install EdDSA cryptographic provider
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		String serverKeyString = clientKeyEddsa;
		String clientKeyString = serverKeyEddsa;

		OneKey serverKey = new OneKey(CBORObject.DecodeFromBytes(StringUtil.base64ToByteArray(serverKeyString)));
		OneKey clientKey = new OneKey(CBORObject.DecodeFromBytes(StringUtil.base64ToByteArray(clientKeyString)));

		// Check the properties of the decoded keys

		// Algorithm
		assertEquals(AlgorithmID.EDDSA.AsCBOR(), serverKey.get(KeyKeys.Algorithm));
		assertEquals(AlgorithmID.EDDSA.AsCBOR(), clientKey.get(KeyKeys.Algorithm));

		// Key type
		assertEquals(KeyKeys.KeyType_OKP, serverKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_OKP, clientKey.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.OKP_Ed25519, serverKey.get(KeyKeys.OKP_Curve));
		assertEquals(KeyKeys.OKP_Ed25519, clientKey.get(KeyKeys.OKP_Curve));

		sendRequest(AlgorithmID.EDDSA, clientKey, serverKey);
	}

	private void sendRequest(AlgorithmID algCountersign, OneKey clientKey, OneKey serverKey) throws Exception {

		createServer(algCountersign, clientKey, serverKey);

		// Set up OSCORE context information for request (client)
		setClientContext(algCountersign, clientKey, serverKey);

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

		// Parse the flag byte group bit (response is pairwise)
		byte flagByte = response.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);
	}

	/* --- End of client tests --- */

	/**
	 * Set OSCORE context information for clients
	 * 
	 * @param algCountersign the countersignature algorithm
	 * @param clientKey the client signature key to use
	 * @param serverKey the server signature key to use
	 * 
	 * @throws OSException on failure to create the contexts
	 */
	public void setClientContext(AlgorithmID algCountersign, OneKey clientKey, OneKey serverKey) throws OSException {
		// Set up OSCORE context information for request (client)
		byte[] sid = new byte[] { 0x25 };
		byte[] rid1 = new byte[] { 0x77 };

		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);

		OneKey clientFullKey = clientKey;
		commonCtx.addSenderCtx(sid, clientFullKey);

		OneKey serverPublicKey = serverKey.PublicKey();
		commonCtx.addRecipientCtx(rid1, REPLAY_WINDOW, serverPublicKey);

		dbClient.addContext(uri, commonCtx);
	}

	/* Server related code below */

	/**
	 * (Re)sets the OSCORE context information for the server
	 * 
	 * @param algCountersign the countersignature algorithm
	 * @param clientKey the client signature key to use
	 * @param serverKey the server signature key to use
	 * 
	 * @throws OSException on failure to create the contexts
	 */
	public void setServerContext(AlgorithmID algCountersign, OneKey clientKey, OneKey serverKey) throws OSException {
		// Set up OSCORE context information for response (server)

		byte[] sid = new byte[] { 0x77 };
		byte[] rid = new byte[] { 0x25 };

		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);

		OneKey serverFullKey = serverKey;
		commonCtx.addSenderCtx(sid, serverFullKey);

		OneKey clientPublicKey = clientKey.PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, clientPublicKey);

		// Response pairwise so both group and pairwise mode are tested
		commonCtx.setPairwiseModeResponses(true);

		dbServer.addContext(clientHostAdd, commonCtx);
	}

	/**
	 * Creates server with resources to test Group OSCORE functionality
	 * 
	 * @param algCountersign the countersignature algorithm
	 * @param clientKey the client signature key to use
	 * @param serverKey the server signature key to use
	 * 
	 * @throws OSException on test failure
	 */
	public void createServer(AlgorithmID algCountersign, OneKey clientKey, OneKey serverKey) throws OSException {
		// Do not create server if it is already running
		if (serverEndpoint != null) {
			// TODO: Check if this ever happens
			return;
		}

		setServerContext(algCountersign, clientKey, serverKey);

		// Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCustomCoapStackArgument(dbServer);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();
		CoapServer server = new CoapServer();
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
