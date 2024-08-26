/*******************************************************************************
 * Copyright (c) 2024 RISE SICS and others.
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
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.IOException;
import java.util.Arrays;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

/**
 * Class that implements test of functionality for re-derivation of contexts
 * using the KUDOS procedure as detailed in:
 * https://datatracker.ietf.org/doc/draft-ietf-core-oscore-key-update/
 *
 * This can for instance be used when one device has lost power and information
 * about the mutable parts of a context (e.g. sequence number) but retains
 * information about static parts (e.g. master secret)
 * 
 */
public class KudosTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private CoapServer server;
	private Endpoint serverEndpoint;

	private static String SERVER_RESPONSE = "Hello World!";

	private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static HashMapCtxDB dbServer = new HashMapCtxDB();
	private final static String hello1 = "/hello";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };
	private final static byte[] context_id = { 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	private static int SEGMENT_LENGTH = ContextRederivation.SEGMENT_LENGTH;

	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}

	// Use the OSCORE stack factory with the client context DB
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(dbClient);
	}

	@After
	public void after() {
		if (null != server) {
			server.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}

	/**
	 * Tests the decoding of the OSCORE option for the parts relevant to KUDOS.
	 */
	@Test
	public void testKudosOscoreOptionDecoding() throws CoapOSException {

		byte[] oscoreOption = StringUtil.hex2ByteArray("9A0115B3030A0B0C070001020304050607AA");
		byte[] correctKid = new byte[] { (byte) 0xAA };
		int correctSenderSequenceNumber = 5555;
		byte[] correctIdContext = new byte[] { (byte) 0x0A, 0x0B, 0x0C };
		byte[] correctNonce = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		int correctH = 1;
		int correctK = 1;
		int correctN = 2;

		int correctM = correctNonce.length - 1;
		int correctX = 7;
		int correctD = 1;

		int correctP = 0;
		int correctB = 0;
		int correctZ = 0;

		int correctY = 0;
		int correctW = 0;
		byte[] correctOldNonce = null;
		int correctOldNonceLength = 0;

		OscoreOptionDecoder decoder = new OscoreOptionDecoder(oscoreOption);
		byte[] idContext = decoder.getIdContext();
		byte[] kid = decoder.getKid();
		int senderSequenceNumber = decoder.getSequenceNumber();
		byte[] nonce = decoder.getNonce();
		int h = decoder.getH();
		int k = decoder.getK();
		int n = decoder.getN();

		int m = decoder.getM();
		int d = decoder.getD();
		int x = decoder.getX();
		int nonceLength = decoder.getNonceLength();

		int p = decoder.getP();
		int b = decoder.getB();
		int z = decoder.getZ();

		int y = decoder.getY();
		int w = decoder.getW();
		byte[] oldNonce = decoder.getOldNonce();
		int oldNonceLength = decoder.getOldNonceLength();

		assertArrayEquals("Decoded ID Context incorrect", correctIdContext, idContext);
		assertArrayEquals("Decoded KID incorrect", correctKid, kid);
		assertArrayEquals("Decoded KUDOS nonce incorrect", correctNonce, nonce);
		assertEquals("Decoded SSN incorrect", correctSenderSequenceNumber, senderSequenceNumber);

		assertEquals("Decoded H flag bit incorrect", correctH, h);
		assertEquals("Decoded K flag bit incorrect", correctK, k);
		assertEquals("Decoded N flag bits incorrect", correctN, n);

		assertEquals("Decoded nonce length incorrect", correctNonce.length, nonceLength);

		// KUDOS related flags
		assertEquals("Decoded M value incorrect", correctM, m);
		assertEquals("Decoded D value incorrect", correctD, d);
		assertEquals("Decoded X value incorrect", correctX, x);

		assertEquals("Decoded P value incorrect", correctP, p);
		assertEquals("Decoded B value incorrect", correctB, b);
		assertEquals("Decoded Z value incorrect", correctZ, z);

		assertEquals("Decoded Y value incorrect", correctY, y);
		assertEquals("Decoded W value incorrect", correctW, w);
		assertEquals("Decoded old_nonce value incorrect", correctOldNonce, oldNonce);
		assertEquals("Decoded old_nonce length incorrect", correctOldNonceLength, oldNonceLength);
	}

	/**
	 * Tests the decoding of the OSCORE option for the parts relevant to KUDOS.
	 * With old_nonce.
	 */
	@Test
	public void testKudosOscoreOptionDecoding2() throws CoapOSException {

		byte[] oscoreOption = StringUtil.hex2ByteArray("9A0115B3030A0B0C47000102030405060707AABBCCDDEEFF1122AA");
		byte[] correctKid = new byte[] { (byte) 0xAA };
		int correctSenderSequenceNumber = 5555;
		byte[] correctIdContext = new byte[] { (byte) 0x0A, 0x0B, 0x0C };
		byte[] correctNonce = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
		int correctH = 1;
		int correctK = 1;
		int correctN = 2;

		int correctM = correctNonce.length - 1;
		int correctX = 0b01000000 | 7;
		int correctD = 1;

		int correctP = 0;
		int correctB = 0;
		int correctZ = 1;

		int correctY = 7;
		byte[] correctOldNonce = new byte[] { (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE,
				(byte) 0xFF, 0x11, 0x22 };
		int correctW = correctOldNonce.length - 1;
		int correctOldNonceLength = 8;

		OscoreOptionDecoder decoder = new OscoreOptionDecoder(oscoreOption);
		byte[] idContext = decoder.getIdContext();
		byte[] kid = decoder.getKid();
		int senderSequenceNumber = decoder.getSequenceNumber();
		byte[] nonce = decoder.getNonce();
		int h = decoder.getH();
		int k = decoder.getK();
		int n = decoder.getN();

		int m = decoder.getM();
		int d = decoder.getD();
		int x = decoder.getX();
		int nonceLength = decoder.getNonceLength();

		int p = decoder.getP();
		int b = decoder.getB();
		int z = decoder.getZ();

		int y = decoder.getY();
		int w = decoder.getW();
		byte[] oldNonce = decoder.getOldNonce();
		int oldNonceLength = decoder.getOldNonceLength();

		assertArrayEquals("Decoded ID Context incorrect", correctIdContext, idContext);
		assertArrayEquals("Decoded KID incorrect", correctKid, kid);
		assertArrayEquals("Decoded KUDOS nonce incorrect", correctNonce, nonce);
		assertEquals("Decoded SSN incorrect", correctSenderSequenceNumber, senderSequenceNumber);

		assertEquals("Decoded H flag bit incorrect", correctH, h);
		assertEquals("Decoded K flag bit incorrect", correctK, k);
		assertEquals("Decoded N flag bits incorrect", correctN, n);

		assertEquals("Decoded nonce length incorrect", correctNonce.length, nonceLength);

		// KUDOS related flags
		assertEquals("Decoded M value incorrect", correctM, m);
		assertEquals("Decoded D value incorrect", correctD, d);
		assertEquals("Decoded X value incorrect", correctX, x);

		assertEquals("Decoded P value incorrect", correctP, p);
		assertEquals("Decoded B value incorrect", correctB, b);
		assertEquals("Decoded Z value incorrect", correctZ, z);

		assertEquals("Decoded Y value incorrect", correctY, y);
		assertEquals("Decoded W value incorrect", correctW, w);
		assertArrayEquals("Decoded old_nonce value incorrect", correctOldNonce, oldNonce);
		assertEquals("Decoded old_nonce length incorrect", correctOldNonceLength, oldNonceLength);
	}

	/**
	 * Tests the encoding of the OSCORE option for the parts relevant to KUDOS.
	 */
	@Test
	public void testKudosOscoreOptionEncoding() throws CoapOSException {

		// Test encoding
		byte[] correctOption = StringUtil.hex2ByteArray("9A0115B3030A0B0C070001020304050607AA");
		byte[] kid = new byte[] { (byte) 0xAA };
		int senderSequenceNumber = 5555;
		byte[] idContext = new byte[] { (byte) 0x0A, 0x0B, 0x0C };
		byte[] nonce = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

		OscoreOptionEncoder encoder = new OscoreOptionEncoder();
		encoder.setIdContext(idContext);
		encoder.setKid(kid);
		encoder.setPartialIV(senderSequenceNumber);
		encoder.setNonce(nonce);
		byte[] encodedOption = encoder.getBytes();

		assertArrayEquals("Encoded option incorrect", correctOption, encodedOption);

	}

	/**
	 * Test the KUDOS comb function
	 * 
	 */
	@Test
	public void testKudosComb() throws CoapOSException {

		byte[] X1 = StringUtil.hex2ByteArray("07");
		byte[] X2 = StringUtil.hex2ByteArray("07");
		byte[] N1 = StringUtil.hex2ByteArray("018a278f7faab55a");
		byte[] N2 = StringUtil.hex2ByteArray("25a8991cd700ac01");

		byte[] correctX = StringUtil.hex2ByteArray("41074107");
		byte[] correctN = StringUtil.hex2ByteArray("48018a278f7faab55a4825a8991cd700ac01");

		byte[] X = KudosRederivation.comb(X1, X2);
		byte[] N = KudosRederivation.comb(N1, N2);

		assertArrayEquals("X value incorrect", correctX, X);
		assertArrayEquals("N value incorrect", correctN, N);

	}

	/**
	 * Test context re-derivation followed by a normal message exchange. This
	 * test simulates a client losing the mutable parts of the OSCORE context,
	 * and then explicitly initiating the context re-derivation procedure.
	 * 
	 * Note that the asserts in this test check things regarding request #2 and
	 * response #2 as request #1 and response #1 are taken care of in the OSCORE
	 * library code (so the application does not need to worry about them).
	 * 
	 * @throws OSException
	 * @throws ConnectorException
	 * @throws IOException
	 * @throws CoseException
	 * @throws InterruptedException
	 */
	@Test
	@Ignore
	public void testClientInitiatedRederivation()
			throws OSException, ConnectorException, IOException, CoseException, InterruptedException {
		
		// Create a server that will not initiate the context re-derivation
		// procedure. (But perform the procedure if the client initiates.)
		createServer(false);

		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null, MAX_UNFRAGMENTED_SIZE);
		String serverUri = serverEndpoint.getUri().toASCIIString();

		// Enable context re-derivation functionality (in general)
		ctx.setContextRederivationEnabled(true);
		// Explicitly initiate the context re-derivation procedure
		ctx.setContextRederivationPhase(PHASE.CLIENT_INITIATE);

		dbClient.addContext(serverUri, ctx);

		CoapClient client = new CoapClient(serverUri + hello1);
		Request request = new Request(Code.GET);
		request.getOptions().setOscore(Bytes.EMPTY);
		RequestTestObserver requestTestObserver = new RequestTestObserver();
		request.addMessageObserver(requestTestObserver);
		CoapResponse resp = client.advanced(request);
		System.out.println((Utils.prettyPrint(resp)));

		OSCoreCtx currCtx = dbClient.getContext(serverUri);
		assertEquals(ContextRederivation.PHASE.INACTIVE, currCtx.getContextRederivationPhase()); // Phase
		assertFalse(currCtx.getIncludeContextId()); // Do not include Context ID

		// Length of Context ID in context (R2 || R3)
		int contextIdLen = currCtx.getIdContext().length;
		assertEquals(3 * SEGMENT_LENGTH, contextIdLen);
		// Check length of Context ID in the request (R2 || R3)
		assertEquals(3 * SEGMENT_LENGTH, requestTestObserver.requestIdContext.length);

		// Check R2 value derived by server using its key with received one
		// The R2 value is composed of S2 || HMAC(K_HMAC, S2).
		OSCoreCtx serverCtx = dbServer.getContext(sid);
		byte[] srvContextRederivationKey = serverCtx.getContextRederivationKey();
		byte[] contextS2 = Arrays.copyOfRange(currCtx.getIdContext(), 0, SEGMENT_LENGTH);
		byte[] hmacOutput = OSCoreCtx.deriveKey(srvContextRederivationKey, srvContextRederivationKey, SEGMENT_LENGTH,
				"SHA256", contextS2);
		byte[] messageHmacValue = Arrays.copyOfRange(currCtx.getIdContext(), SEGMENT_LENGTH, SEGMENT_LENGTH * 2);
		assertArrayEquals(hmacOutput, messageHmacValue);

		// Empty OSCORE option in response
		assertArrayEquals(Bytes.EMPTY, resp.getOptions().getOscore());

		assertEquals(ResponseCode.CONTENT, resp.getCode());
		assertEquals(SERVER_RESPONSE, resp.getResponseText());

		// 2nd request for testing
		request = new Request(Code.GET);
		request.getOptions().setOscore(Bytes.EMPTY);
		resp = client.advanced(request);
		System.out.println((Utils.prettyPrint(resp)));

		assertEquals(ResponseCode.CONTENT, resp.getCode());
		assertEquals(SERVER_RESPONSE, resp.getResponseText());

		request = new Request(Code.GET);
		request.getOptions().setOscore(Bytes.EMPTY);
		resp = client.advanced(request);
		System.out.println((Utils.prettyPrint(resp)));

		client.shutdown();
	}

	/**
	 * Test context re-derivation followed by a normal message exchange. This
	 * test simulates a server losing the mutable parts of the OSCORE context.
	 * When a request from the client arrives this will initiate the context
	 * re-derivation procedure. Note that the client does not explicitly
	 * initiate the procedure before the request as it still has the context
	 * information. It does not know the server has lost this information.
	 * 
	 * Note that the asserts in this test check things regarding request #1 &
	 * response #1 and also response #2 as request #1. This is because in this
	 * case the client does not initially know that a context re-derivation
	 * procedure will take place. So the application code ends up explicitly
	 * sending both request #1 and request #2.
	 * 
	 * @throws OSException
	 * @throws ConnectorException
	 * @throws IOException
	 * @throws CoseException
	 * @throws InterruptedException
	 */
	@Test
	@Ignore
	public void testServerInitiatedRederivation()
			throws OSException, ConnectorException, IOException, CoseException, InterruptedException {

		// Create a server that will initiate the context re-derivation (on
		// reception of a request)
		createServer(true);

		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id, MAX_UNFRAGMENTED_SIZE);
		// Enable context re-derivation functionality (for client)
		ctx.setContextRederivationEnabled(true);
		String serverUri = serverEndpoint.getUri().toASCIIString();
		dbClient.addContext(serverUri, ctx);

		// Create first request (for request #1 and response #1 exchange)
		CoapClient client = new CoapClient(serverUri + hello1);
		Request request = new Request(Code.GET);
		request.getOptions().setOscore(Bytes.EMPTY);
		RequestTestObserver requestTestObserver = new RequestTestObserver();
		request.addMessageObserver(requestTestObserver);
		CoapResponse resp = client.advanced(request);
		System.out.println((Utils.prettyPrint(resp)));

		OSCoreCtx currCtx = dbClient.getContext(serverUri);
		assertEquals(ContextRederivation.PHASE.CLIENT_PHASE_2, currCtx.getContextRederivationPhase()); // Phase
		assertFalse(currCtx.getIncludeContextId()); // Do not include Context ID

		// Length of Context ID in context (R2 || ID1)
		int contextIdLen = currCtx.getIdContext().length;
		assertEquals(3 * SEGMENT_LENGTH, contextIdLen);
		// Check length of Context ID in the request (ID1)
		assertEquals(1 * SEGMENT_LENGTH, requestTestObserver.requestIdContext.length);

		// Check R2 value derived by server using its key with received one
		// The R2 value is composed of S2 || HMAC(K_HMAC, S2).
		OSCoreCtx serverCtx = dbServer.getContext(sid);
		byte[] srvContextRederivationKey = serverCtx.getContextRederivationKey();
		byte[] contextS2 = Arrays.copyOfRange(currCtx.getIdContext(), 0, SEGMENT_LENGTH);
		byte[] hmacOutput = OSCoreCtx.deriveKey(srvContextRederivationKey, srvContextRederivationKey, SEGMENT_LENGTH,
				"SHA256", contextS2);
		byte[] messageHmacValue = Arrays.copyOfRange(currCtx.getIdContext(), SEGMENT_LENGTH, SEGMENT_LENGTH * 2);

		// Ensure that the ID Context in the OSCORE option in this response
		// (response #1) is a CBOR byte string
		byte[] respOscoreOpt = resp.getOptions().getOscore();
		byte[] respIdContext = Arrays.copyOfRange(respOscoreOpt, 2, respOscoreOpt.length);
		byte[] respIdContextDecoded = CBORObject.DecodeFromBytes(respIdContext).GetByteString();
		// Check its length (R2)
		assertEquals(2 * SEGMENT_LENGTH, respIdContextDecoded.length);

		// The OSCORE option in the response should include the correct R2 value
		byte[] contextR2 = Bytes.concatenate(contextS2, hmacOutput);
		byte[] oscoreOptionR2 = respIdContextDecoded;
		assertArrayEquals(contextR2, oscoreOptionR2);
		assertArrayEquals(hmacOutput, messageHmacValue);

		// The response should be a 4.01
		assertEquals(ResponseCode.UNAUTHORIZED, resp.getCode());

		// 2nd request (for request #2 and response #2 exchange)
		request = new Request(Code.GET);
		request.getOptions().setOscore(Bytes.EMPTY);
		requestTestObserver = new RequestTestObserver();
		request.addMessageObserver(requestTestObserver);
		resp = client.advanced(request);
		System.out.println((Utils.prettyPrint(resp)));

		currCtx = dbClient.getContext(serverUri);
		assertEquals(ContextRederivation.PHASE.INACTIVE, currCtx.getContextRederivationPhase()); // Phase
		assertFalse(currCtx.getIncludeContextId()); // Do not include Context ID

		// Length of Context ID in context (R2 || R3)
		contextIdLen = currCtx.getIdContext().length;
		assertEquals(3 * SEGMENT_LENGTH, contextIdLen);
		// Check length of Context ID in the request (R2 || R3)
		assertEquals(3 * SEGMENT_LENGTH, requestTestObserver.requestIdContext.length);

		// Check R2 value derived by server using its key with received one
		// The R2 value is composed of S2 || HMAC(K_HMAC, S2).
		serverCtx = dbServer.getContext(sid);
		srvContextRederivationKey = serverCtx.getContextRederivationKey();
		contextS2 = Arrays.copyOfRange(currCtx.getIdContext(), 0, SEGMENT_LENGTH);
		hmacOutput = OSCoreCtx.deriveKey(srvContextRederivationKey, srvContextRederivationKey, SEGMENT_LENGTH, "SHA256",
				contextS2);
		messageHmacValue = Arrays.copyOfRange(currCtx.getIdContext(), SEGMENT_LENGTH, SEGMENT_LENGTH * 2);
		assertArrayEquals(hmacOutput, messageHmacValue);

		// Empty OSCORE option in response
		assertArrayEquals(Bytes.EMPTY, resp.getOptions().getOscore());

		assertEquals(ResponseCode.CONTENT, resp.getCode());
		assertEquals(SERVER_RESPONSE, resp.getResponseText());

		client.shutdown();
	}

	/**
	 * Message observer that will save the ID Context used in the outgoing
	 * request from the client for comparison.
	 *
	 */
	private static class RequestTestObserver extends MessageObserverAdapter {

		public byte[] requestIdContext;

		@Override
		public void onContextEstablished(EndpointContext endpointContext) {
			requestIdContext = StringUtil
					.hex2ByteArray(endpointContext.getString(OSCoreEndpointContextInfo.OSCORE_CONTEXT_ID));
		}
	}

	/**
	 * Creates server with resources for test
	 * 
	 * @param initiateRederivation if the server will initiate the context
	 *            re-derivation procedure
	 * 
	 * @throws InterruptedException if resource update task fails
	 * @throws OSException
	 */
	public void createServer(boolean initiateRederivation) throws InterruptedException, OSException {

		// Purge any old existing values from the server context database
		dbServer.purge();

		//Do not create server if it is already running
		if(server != null) {
			return;
		}

		byte[] contextId = null;
		if (initiateRederivation) {
			contextId = context_id;
		}

		//Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, contextId, MAX_UNFRAGMENTED_SIZE);
		String clientUri = "coap://" + TestTools.LOCALHOST_EPHEMERAL.getAddress().getHostAddress();

		// Enable context re-derivation functionality in general
		ctx.setContextRederivationEnabled(true);

		// If the server is to initiate the context re-derivation procedure, set
		// accordingly in the context
		if (initiateRederivation) {
			ctx.setContextRederivationPhase(PHASE.SERVER_INITIATE);
		}

		dbServer.addContext(clientUri, ctx);

		//Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCustomCoapStackArgument(dbServer);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);

		/** --- Resources for tests follow --- **/

		//Create Hello World-resource
		OSCoreResource hello = new OSCoreResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload(SERVER_RESPONSE);
				exchange.respond(r);
			}
		};
		
		//Creating resource hierarchy
		server.add(hello);

		/** --- End of resources for tests **/

		//Start server
		server.start();
	}
}
