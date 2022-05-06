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
 *    Rikard Höglund (RISE SICS)
 ******************************************************************************/
package org.eclipse.californium.oscore.group;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Base64;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.RequestEncryptor;
import org.eclipse.californium.oscore.ResponseEncryptor;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import org.junit.Assert;

public class GroupEncryptorTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

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

	/**
	 * @throws OSException if encryption fails
	 * @throws CoseException on test failure
	 * @throws IOException on test failure
	 */
	@Test
	@Ignore // TODO: Recalculate
	public void testRequestEncryptorGroupMode() throws OSException, CoseException, IOException {
		// Set up OSCORE context
		byte[] sid = new byte[] { 0x00 };
		int seq = 20;

		// Create client context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);
		OneKey clientFullKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(clientKeyString)));
		commonCtx.addSenderCtx(sid, clientFullKey);

		commonCtx.senderCtx.setSenderSeq(seq);

		// Create request message from raw byte array
		byte[] requestBytes = new byte[] { 0x44, 0x01, 0x71, (byte) 0xc3, 0x00, 0x00, (byte) 0xb9, 0x32, 0x39, 0x6c,
				0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, (byte) 0x83, 0x74, 0x76, 0x31 };

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(requestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}
		Assert.assertNotNull(r);

		// Set the context in the context database
		HashMapCtxDB db = new HashMapCtxDB();
		db.addContext(r.getURI(), commonCtx);

		// Encrypt the request message
		Request encrypted = RequestEncryptor.encrypt(db, r);

		// Check the OSCORE option value
		byte[] predictedOSCoreOption = { 0x39, 0x14, 0x08, 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74, 0x00 };
		byte[] requestOption = encrypted.getOptions().getOscore();
		assertArrayEquals(predictedOSCoreOption, requestOption);

		// Check that the group bit is set
		byte flagByte = encrypted.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertTrue(groupModeBit != 0);

		// Check the OSCORE request payload (ciphertext excluding signature)
		byte[] predictedOSCorePayload = { 0x1F, (byte) 0x88, (byte) 0xD2, (byte) 0x99, 0x6D, (byte) 0xE8, (byte) 0xF5,
				0x03, (byte) 0xCB, 0x49, 0x2A, 0x38, (byte) 0xED };
		byte[] requestPayload = Arrays.copyOfRange(encrypted.getPayload(), 0,
				encrypted.getPayload().length - commonCtx.getCountersignatureLen());
		assertArrayEquals(predictedOSCorePayload, requestPayload);

		// Check the signature (TODO)
		assertEquals(77, encrypted.getPayload().length);

		// Serialize the request message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedBytes = serializer.getByteArray(encrypted);

		encryptedBytes = Arrays.copyOfRange(encryptedBytes, 0,
				encryptedBytes.length - commonCtx.getCountersignatureLen());

		// Check the whole OSCORE request excluding signature
		byte[] predictedOSCoreBytes = { (byte) 0x44, (byte) 0x02, (byte) 0x71, (byte) 0xC3, (byte) 0x00, (byte) 0x00,
				(byte) 0xB9, (byte) 0x32, (byte) 0x39, (byte) 0x6C, (byte) 0x6F, (byte) 0x63, (byte) 0x61, (byte) 0x6C,
				(byte) 0x68, (byte) 0x6F, (byte) 0x73, (byte) 0x74, (byte) 0x6C, (byte) 0x39, (byte) 0x14, (byte) 0x08,
				(byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74,
				(byte) 0x00, (byte) 0xFF, (byte) 0x1F, (byte) 0x88, (byte) 0xD2, (byte) 0x99, (byte) 0x6D, (byte) 0xE8,
				(byte) 0xF5, (byte) 0x03, (byte) 0xCB, (byte) 0x49, (byte) 0x2A, (byte) 0x38, (byte) 0xED };

		assertArrayEquals(predictedOSCoreBytes, encryptedBytes);

	}

	/**
	 *
	 * @throws OSException if encryption fails
	 * @throws CoseException on test failure
	 * @throws IOException on test failure
	 */
	@Test
	@Ignore // TODO: Recalculate
	public void testRequestEncryptorPairwiseMode() throws OSException, CoseException, IOException {
		// Set up OSCORE context
		byte[] sid = new byte[] { 0x00 };
		byte[] rid = new byte[] { 0x01 };
		int seq = 20;

		// Create client context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);
		OneKey clientFullKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(clientKeyString)));
		commonCtx.addSenderCtx(sid, clientFullKey);

		commonCtx.senderCtx.setSenderSeq(seq);

		// Create server context
		OneKey serverPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(serverKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, serverPublicKey);

		// Create request message from raw byte array
		byte[] requestBytes = new byte[] { 0x44, 0x01, 0x71, (byte) 0xc3, 0x00, 0x00, (byte) 0xb9, 0x32, 0x39, 0x6c,
				0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, (byte) 0x83, 0x74, 0x76, 0x31 };

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(requestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}
		Assert.assertNotNull(r);

		String uri = r.getURI();

		// Set the OSCORE option to indicate pairwise mode
		r.getOptions().setOscore(OptionEncoder.set(true, uri, rid));

		// Set the context in the context database
		HashMapCtxDB db = new HashMapCtxDB();
		db.addContext(uri, commonCtx);

		// Encrypt the request message
		Request encrypted = RequestEncryptor.encrypt(db, r);

		// Check the OSCORE option value
		byte[] predictedOSCoreOption = { 0x19, 0x14, 0x08, 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74, 0x00 };
		byte[] requestOption = encrypted.getOptions().getOscore();
		assertArrayEquals(predictedOSCoreOption, requestOption);

		// Check that the group bit is not set
		byte flagByte = encrypted.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);

		// Check the OSCORE request payload (no signature is included)
		byte[] predictedOSCorePayload = { (byte) 0xA8, (byte) 0xB9, (byte) 0xED, (byte) 0x2B, (byte) 0xBD, (byte) 0xD3,
				(byte) 0xAC, (byte) 0x15, (byte) 0x47, (byte) 0xA6, (byte) 0x97, (byte) 0x70, (byte) 0x02 };
		byte[] requestPayload = encrypted.getPayload();
		assertArrayEquals(predictedOSCorePayload, requestPayload);

		// Serialize the request message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedBytes = serializer.getByteArray(encrypted);

		// Check the whole OSCORE request
		byte[] predictedOSCoreBytes = { (byte) 0x44, (byte) 0x02, (byte) 0x71, (byte) 0xC3, (byte) 0x00, (byte) 0x00,
				(byte) 0xB9, (byte) 0x32, (byte) 0x39, (byte) 0x6C, (byte) 0x6F, (byte) 0x63, (byte) 0x61, (byte) 0x6C,
				(byte) 0x68, (byte) 0x6F, (byte) 0x73, (byte) 0x74, (byte) 0x6C, (byte) 0x19, (byte) 0x14, (byte) 0x08,
				(byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74,
				(byte) 0x00, (byte) 0xFF, (byte) 0xA8, (byte) 0xB9, (byte) 0xED, (byte) 0x2B, (byte) 0xBD, (byte) 0xD3,
				(byte) 0xAC, (byte) 0x15, (byte) 0x47, (byte) 0xA6, (byte) 0x97, (byte) 0x70, (byte) 0x02 };
		assertArrayEquals(predictedOSCoreBytes, encryptedBytes);
	}

	@Test
	@Ignore // TODO: Recalculate
	public void testResponseEncryptorGroupMode() throws OSException, CoseException, IOException {
		// Set up OSCORE context
		byte[] master_salt = new byte[] { (byte) 0x9e, 0x7c, (byte) 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
		byte[] sid = new byte[] { 0x11 };
		int seq = 20;

		// Create server context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign,
				gmPublicKey);

		OneKey serverFullKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(serverKeyString)));
		commonCtx.addSenderCtx(sid, serverFullKey);

		GroupSenderCtx senderCtx = commonCtx.senderCtx;
		senderCtx.setSenderSeq(seq);
		senderCtx.setResponsesIncludePartialIV(false);

		// Create response message from raw byte array
		byte[] responseBytes = new byte[] { 0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, (byte) 0xff, 0x48, 0x65,
				0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(responseBytes);

		Response r = null;
		if (mess instanceof Response) {
			r = (Response) mess;
		}

		// Encrypt the response message
		boolean newPartialIV = false;
		boolean outerBlockwise = false;
		byte[] requestOscoreOption = new byte[] { 0x39, 0x14, 0x08, 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74,
				0x00 };
		Response encrypted = ResponseEncryptor.encrypt(null, r, senderCtx, newPartialIV, outerBlockwise, seq,
				requestOscoreOption);

		// Check the OSCORE option value
		byte[] predictedOSCoreOption = { 0x28, 0x11 };
		byte[] responseOption = encrypted.getOptions().getOscore();
		assertArrayEquals(predictedOSCoreOption, responseOption);

		// Check that the group bit is set
		byte flagByte = encrypted.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertTrue(groupModeBit != 0);

		// Check the OSCORE response payload (ciphertext excluding signature)
		byte[] predictedOSCorePayload = { (byte) 0x70, (byte) 0xBB, (byte) 0xCD, (byte) 0x26, (byte) 0x09, (byte) 0xA8,
				(byte) 0x9C, (byte) 0xAD, (byte) 0x4E, (byte) 0x24, (byte) 0x13, (byte) 0x59, (byte) 0x4F, (byte) 0x01,
				(byte) 0x14, (byte) 0x95, (byte) 0x7B, (byte) 0x85, (byte) 0xA9, (byte) 0x97, (byte) 0x37,
				(byte) 0xF1 };
		byte[] responsePayload = Arrays.copyOfRange(encrypted.getPayload(), 0,
				encrypted.getPayload().length - commonCtx.getCountersignatureLen());
		assertArrayEquals(predictedOSCorePayload, responsePayload);

		// Check the signature (TODO)
		assertEquals(86, encrypted.getPayload().length);

		// Serialize the response message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedBytes = serializer.getByteArray(encrypted);
		encryptedBytes = Arrays.copyOfRange(encryptedBytes, 0,
				encryptedBytes.length - commonCtx.getCountersignatureLen());

		// Check the whole OSCORE response excluding signature
		byte[] predictedOSCoreBytes = { (byte) 0x64, (byte) 0x44, (byte) 0x5D, (byte) 0x1F, (byte) 0x00, (byte) 0x00,
				(byte) 0x39, (byte) 0x74, (byte) 0x92, (byte) 0x28, (byte) 0x11, (byte) 0xFF, (byte) 0x70, (byte) 0xBB,
				(byte) 0xCD, (byte) 0x26, (byte) 0x09, (byte) 0xA8, (byte) 0x9C, (byte) 0xAD, (byte) 0x4E, (byte) 0x24,
				(byte) 0x13, (byte) 0x59, (byte) 0x4F, (byte) 0x01, (byte) 0x14, (byte) 0x95, (byte) 0x7B, (byte) 0x85,
				(byte) 0xA9, (byte) 0x97, (byte) 0x37, (byte) 0xF1 };
		assertArrayEquals(predictedOSCoreBytes, encryptedBytes);
	}

	@Test
	@Ignore // TODO: Recalculate
	public void testResponseEncryptorPairwiseMode() throws OSException, CoseException, IOException {
		// Set up OSCORE context
		// test vector OSCORE draft Appendix C.1.2
		byte[] master_salt = new byte[] { (byte) 0x9e, 0x7c, (byte) 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
		byte[] sid = new byte[] { 0x11 };
		byte[] rid = new byte[] { 0x22 };
		int seq = 20;

		// Create server context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign, gmPublicKey);
		OneKey serverFullKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(serverKeyString)));
		commonCtx.addSenderCtx(sid, serverFullKey);

		GroupSenderCtx senderCtx = commonCtx.senderCtx;
		senderCtx.setSenderSeq(seq);
		senderCtx.setResponsesIncludePartialIV(false);
		commonCtx.setPairwiseModeResponses(true);

		// Create client context
		OneKey clientPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(Base64.decode(clientKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, clientPublicKey);

		// Create response message from raw byte array
		byte[] responseBytes = new byte[] { 0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, (byte) 0xff, 0x48, 0x65,
				0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(responseBytes);

		Response r = null;
		if (mess instanceof Response) {
			r = (Response) mess;
		}

		// Set the context in the context database
		HashMapCtxDB db = new HashMapCtxDB();
		db.addContext(uri, commonCtx);

		// Encrypt the response message
		boolean newPartialIV = false;
		boolean outerBlockwise = false;
		byte[] requestOscoreOption = new byte[] { 0x39, 0x14, 0x08, 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74,
				0x22 };
		Response encrypted = ResponseEncryptor.encrypt(db, r, senderCtx, newPartialIV, outerBlockwise, seq,
				requestOscoreOption);

		// Check the OSCORE option value
		byte[] predictedOSCoreOption = { 0x08, 0x11 };
		byte[] responseOption = encrypted.getOptions().getOscore();
		assertArrayEquals(predictedOSCoreOption, responseOption);

		// Check that the group bit is not set
		byte flagByte = encrypted.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);

		// Check the OSCORE response payload (no signature)
		byte[] predictedOSCorePayload = new byte[] { (byte) 0x90, (byte) 0x51, (byte) 0xE4, (byte) 0x9A, (byte) 0xE0,
				(byte) 0x12, (byte) 0x7B, (byte) 0x61, (byte) 0xE9, (byte) 0x85, (byte) 0x91, (byte) 0x4A, (byte) 0x1D,
				(byte) 0x54, (byte) 0xAC, (byte) 0x9D, (byte) 0x53, (byte) 0x19, (byte) 0x53, (byte) 0xB8, (byte) 0xC5,
				(byte) 0x29 };
		byte[] responsePayload = encrypted.getPayload();
		assertArrayEquals(predictedOSCorePayload, responsePayload);

		// Serialize the response message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedBytes = serializer.getByteArray(encrypted);

		// Check the whole OSCORE response
		byte[] predictedOSCoreBytes = { (byte) 0x64, (byte) 0x44, (byte) 0x5D, (byte) 0x1F, (byte) 0x00, (byte) 0x00,
				(byte) 0x39, (byte) 0x74, (byte) 0x92, (byte) 0x08, (byte) 0x11, (byte) 0xFF, (byte) 0x90, (byte) 0x51,
				(byte) 0xE4, (byte) 0x9A, (byte) 0xE0, (byte) 0x12, (byte) 0x7B, (byte) 0x61, (byte) 0xE9, (byte) 0x85,
				(byte) 0x91, (byte) 0x4A, (byte) 0x1D, (byte) 0x54, (byte) 0xAC, (byte) 0x9D, (byte) 0x53, (byte) 0x19,
				(byte) 0x53, (byte) 0xB8, (byte) 0xC5, (byte) 0x29 };

		assertArrayEquals(predictedOSCoreBytes, encryptedBytes);
	}

}
