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

import java.net.InetSocketAddress;
import java.util.Random;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.UdpEndpointContext;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.oscore.ByteId;
import org.eclipse.californium.oscore.CoapOSException;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.RequestDecryptor;
import org.eclipse.californium.oscore.ResponseDecryptor;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

public class GroupDecryptorTest {

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

	// Keys for client and server (ECDSA full private and public keys)
	private static String clientKeyString = "pgECI1gg2qPzgLjNqAaJWnjh9trtVjX2Gp2mbzyAQLSJt9LD2j8iWCDe8qCLkQ59ZOIwmFVk2oGtfoz4epMe/Fg2nvKQwkQ+XiFYIKb0PXRXX/6hU45EpcXUAQPufU03fkYA+W6gPoiZ+d0YIAEDJg==";
	private static String serverKeyString = "pgECI1ggP2Jr+HhJPSq1U6SebYmOj5EtwhswehlvWwHBFbxJ0ckiWCCukpflkrMHKW6aNaku7GO2ieP3YO5B5/mqGWBIJUEpIyFYIH+jx7yPzktyM/dG/WmygfEk8XYsIFcKgR2TlvKd5+SRIAEDJg==";

	private static final int REPLAY_WINDOW = 32;

	static Random rand;

	@Before
	public void init() {
		EndpointManager.clear();
	}

	// Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(null); // TODO: Better way?
		rand = new Random();
	}

	@Test
	public void testRequestDecryptorGroupMode() throws OSException, CoseException {
		// Set up OSCORE context
		byte[] rid = new byte[] { 0x00 };
		int seq = 20;

		// Create client context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign);
		OneKey clientPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(clientKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, clientPublicKey);
		GroupRecipientCtx recipientCtx = commonCtx.recipientCtxMap.get(new ByteId(rid));

		// Create the encrypted request message from raw byte array
		byte[] encryptedRequestBytes = new byte[] { (byte) 0x44, (byte) 0x02, (byte) 0x71, (byte) 0xC3, (byte) 0x00,
				(byte) 0x00, (byte) 0xB9, (byte) 0x32, (byte) 0x39, (byte) 0x6C, (byte) 0x6F, (byte) 0x63, (byte) 0x61,
				(byte) 0x6C, (byte) 0x68, (byte) 0x6F, (byte) 0x73, (byte) 0x74, (byte) 0x6C, (byte) 0x39, (byte) 0x14,
				(byte) 0x08, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x74, (byte) 0x65, (byte) 0x73,
				(byte) 0x74, (byte) 0x00, (byte) 0xFF, (byte) 0x1F, (byte) 0x88, (byte) 0xD2, (byte) 0x99, (byte) 0x6D,
				(byte) 0xE8, (byte) 0xF5, (byte) 0x03, (byte) 0xCB, (byte) 0x49, (byte) 0x2A, (byte) 0x38, (byte) 0xED,
				(byte) 0x35, (byte) 0xE3, (byte) 0x94, (byte) 0xD6, (byte) 0xA9, (byte) 0xE9, (byte) 0x5D, (byte) 0xDC,
				(byte) 0x05, (byte) 0x35, (byte) 0x6A, (byte) 0x30, (byte) 0xA1, (byte) 0x00, (byte) 0xA2, (byte) 0xEC,
				(byte) 0x3B, (byte) 0x2F, (byte) 0x9C, (byte) 0x51, (byte) 0xA6, (byte) 0x51, (byte) 0x1B, (byte) 0x97,
				(byte) 0x96, (byte) 0x84, (byte) 0x94, (byte) 0x9F, (byte) 0x5A, (byte) 0x88, (byte) 0x67, (byte) 0x97,
				(byte) 0x28, (byte) 0x16, (byte) 0xF9, (byte) 0x12, (byte) 0x19, (byte) 0x9F, (byte) 0x0D, (byte) 0x38,
				(byte) 0x7C, (byte) 0xE5, (byte) 0x0E, (byte) 0xAB, (byte) 0x9C, (byte) 0xF1, (byte) 0x9D, (byte) 0x08,
				(byte) 0x97, (byte) 0xFE, (byte) 0x69, (byte) 0xE9, (byte) 0x63, (byte) 0x0A, (byte) 0xB8, (byte) 0x40,
				(byte) 0x4C, (byte) 0x2F, (byte) 0x62, (byte) 0xAA, (byte) 0x43, (byte) 0xB9, (byte) 0xC0,
				(byte) 0x67 };

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(encryptedRequestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}

		// Check that the group bit is set
		byte flagByte = r.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertTrue(groupModeBit != 0);

		// Set up some state information simulating an incoming request
		OSCoreCtxDB db = new HashMapCtxDB();
		recipientCtx.setReceiverSeq(seq - 1);
		db.addContext(recipientCtx);
		r.setSourceContext(new UdpEndpointContext(new InetSocketAddress(0)));

		// Decrypt the request message
		Request decrypted = RequestDecryptor.decrypt(db, r, recipientCtx);
		decrypted.getOptions().removeOscore();

		// Serialize the request message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(decrypted);

		// Check the whole decrypted request
		byte[] predictedBytes = { 0x44, 0x01, 0x71, (byte) 0xc3, 0x00, 0x00, (byte) 0xb9, 0x32, 0x39, 0x6c, 0x6f, 0x63,
				0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, (byte) 0x83, 0x74, 0x76, 0x31 };

		assertArrayEquals(predictedBytes, decryptedBytes);

	}

	@Test
	public void testResponseDecryptorPairwiseMode() throws OSException, CoseException {
		// Set up OSCORE context
		// test vector OSCORE draft Appendix C.1.2
		byte[] master_salt = new byte[] { (byte) 0x9e, 0x7c, (byte) 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
		byte[] sid = new byte[] { 0x22 };
		byte[] rid = new byte[] { 0x11 };
		int seq = 20;

		// Create server context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign);
		OneKey serverFullKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(serverKeyString)));
		commonCtx.addSenderCtx(sid, serverFullKey);

		// Create client context
		OneKey clientPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(clientKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, clientPublicKey);
		GroupRecipientCtx recipientCtx = commonCtx.recipientCtxMap.get(new ByteId(rid));

		// Create the encrypted response message from raw byte array
		byte[] encryptedResponseBytes = new byte[] { (byte) 0x64, (byte) 0x44, (byte) 0x5D, (byte) 0x1F, (byte) 0x00,
				(byte) 0x00, (byte) 0x39, (byte) 0x74, (byte) 0x92, (byte) 0x08, (byte) 0x11, (byte) 0xFF, (byte) 0x90,
				(byte) 0x51, (byte) 0xE4, (byte) 0x9A, (byte) 0xE0, (byte) 0x12, (byte) 0x7B, (byte) 0x61, (byte) 0xE9,
				(byte) 0x85, (byte) 0x91, (byte) 0x4A, (byte) 0x1D, (byte) 0x54, (byte) 0xAC, (byte) 0x9D, (byte) 0x53,
				(byte) 0x19, (byte) 0x53, (byte) 0xB8, (byte) 0xC5, (byte) 0x29 };

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(encryptedResponseBytes);

		Response r = null;
		if (mess instanceof Response) {
			r = (Response) mess;
		}

		// Check that the group bit is not set
		byte flagByte = r.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);

		// Set up some state information simulating the original outgoing
		// request
		OSCoreCtxDB db = new HashMapCtxDB();
		db.addContext(r.getToken(), recipientCtx);
		db.addSeqByToken(r.getToken(), seq);
		db.addContext("localhost", commonCtx);

		// Decrypt the response message
		Response decrypted = ResponseDecryptor.decrypt(db, r);
		decrypted.getOptions().removeOscore();

		// Check the decrypted response payload
		String predictedPayload = "Hello World!";

		assertEquals(predictedPayload, decrypted.getPayloadString());

		// Serialize the response message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(decrypted);

		// Check the whole decrypted response
		byte[] predictedBytes = { 0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, (byte) 0xff, 0x48, 0x65, 0x6c, 0x6c,
				0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };

		assertArrayEquals(predictedBytes, decryptedBytes);

	}

	@Test
	public void testResponseDecryptorGroupMode() throws OSException, CoseException {
		// Set up OSCORE context
		byte[] master_salt = new byte[] { (byte) 0x9e, 0x7c, (byte) 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
		byte[] rid = new byte[] { 0x11 };
		byte[] requestKID = new byte[] { 0x00 };
		int seq = 20;

		// Create client context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign);
		commonCtx.addSenderCtx(requestKID, null);

		OneKey serverPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(serverKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, serverPublicKey);
		GroupRecipientCtx recipientCtx = commonCtx.recipientCtxMap.get(new ByteId(rid));

		// Create the encrypted response message from raw byte array
		byte[] encryptedResponseBytes = new byte[] { (byte) 0x64, (byte) 0x44, (byte) 0x5D, (byte) 0x1F, (byte) 0x00,
				(byte) 0x00, (byte) 0x39, (byte) 0x74, (byte) 0x92, (byte) 0x28, (byte) 0x11, (byte) 0xFF, (byte) 0x70,
				(byte) 0xBB, (byte) 0xCD, (byte) 0x26, (byte) 0x09, (byte) 0xA8, (byte) 0x9C, (byte) 0xAD, (byte) 0x4E,
				(byte) 0x24, (byte) 0x13, (byte) 0x59, (byte) 0x4F, (byte) 0x01, (byte) 0x14, (byte) 0x95, (byte) 0x7B,
				(byte) 0x85, (byte) 0xA9, (byte) 0x97, (byte) 0x37, (byte) 0xF1, (byte) 0x7D, (byte) 0x6F, (byte) 0x41,
				(byte) 0x04, (byte) 0xC1, (byte) 0x93, (byte) 0xF5, (byte) 0x89, (byte) 0x76, (byte) 0x5C, (byte) 0xEF,
				(byte) 0x3C, (byte) 0xFD, (byte) 0x21, (byte) 0xF8, (byte) 0x12, (byte) 0x6C, (byte) 0x51, (byte) 0x48,
				(byte) 0x5B, (byte) 0xAD, (byte) 0xF5, (byte) 0xC3, (byte) 0x93, (byte) 0x15, (byte) 0xD2, (byte) 0x3F,
				(byte) 0x94, (byte) 0xC6, (byte) 0xA3, (byte) 0xD8, (byte) 0x8D, (byte) 0x84, (byte) 0x3B, (byte) 0x6E,
				(byte) 0xEA, (byte) 0x41, (byte) 0x4C, (byte) 0x80, (byte) 0x1B, (byte) 0xEC, (byte) 0x90, (byte) 0x1B,
				(byte) 0x18, (byte) 0x9A, (byte) 0x11, (byte) 0xB1, (byte) 0xB5, (byte) 0x99, (byte) 0x19, (byte) 0x5F,
				(byte) 0xF0, (byte) 0xE7, (byte) 0x6F, (byte) 0x06, (byte) 0x49, (byte) 0x0A, (byte) 0x26, (byte) 0x1B,
				(byte) 0x81, (byte) 0x9F, (byte) 0xA4, (byte) 0xC4, (byte) 0x67 };

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(encryptedResponseBytes);

		Response r = null;
		if (mess instanceof Response) {
			r = (Response) mess;
		}

		// Check that the group bit is set
		byte flagByte = r.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertTrue(groupModeBit != 0);

		// Set up some state information simulating the original outgoing
		// request
		OSCoreCtxDB db = new HashMapCtxDB();
		db.addContext(r.getToken(), recipientCtx);
		db.addSeqByToken(r.getToken(), seq);
		db.addContext("", commonCtx);
		r.setSourceContext(new UdpEndpointContext(new InetSocketAddress(0)));

		// Decrypt the response message
		Response decrypted = ResponseDecryptor.decrypt(db, r);
		decrypted.getOptions().removeOscore();

		// Check the decrypted response payload
		String predictedPayload = "Hello World!";

		assertEquals(predictedPayload, decrypted.getPayloadString());

		// Serialize the response message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(decrypted);

		// Check the whole decrypted response
		byte[] predictedBytes = { 0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, (byte) 0xff, 0x48, 0x65, 0x6c, 0x6c,
				0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };

		assertArrayEquals(predictedBytes, decryptedBytes);

	}

	/**
	 *
	 * @throws OSException if encryption fails
	 * @throws CoseException on test failure
	 */
	@Test
	public void testRequestDecryptorPairwiseMode() throws OSException, CoseException {
		// Set up OSCORE context
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[] { 0x00 };

		// Create client context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign);
		OneKey clientFullKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(clientKeyString)));
		commonCtx.addSenderCtx(sid, clientFullKey);

		// Create server context
		OneKey serverPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(serverKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, serverPublicKey);
		GroupRecipientCtx recipientCtx = commonCtx.recipientCtxMap.get(new ByteId(rid));

		// Create request message from raw byte array
		byte[] encryptedRequestBytes = new byte[] { (byte) 0x44, (byte) 0x02, (byte) 0x71, (byte) 0xC3, (byte) 0x00,
				(byte) 0x00, (byte) 0xB9, (byte) 0x32, (byte) 0x39, (byte) 0x6C, (byte) 0x6F, (byte) 0x63, (byte) 0x61,
				(byte) 0x6C, (byte) 0x68, (byte) 0x6F, (byte) 0x73, (byte) 0x74, (byte) 0x6C, (byte) 0x19, (byte) 0x14,
				(byte) 0x08, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x74, (byte) 0x65, (byte) 0x73,
				(byte) 0x74, (byte) 0x00, (byte) 0xFF, (byte) 0xA8, (byte) 0xB9, (byte) 0xED, (byte) 0x2B, (byte) 0xBD,
				(byte) 0xD3, (byte) 0xAC, (byte) 0x15, (byte) 0x47, (byte) 0xA6, (byte) 0x97, (byte) 0x70,
				(byte) 0x02 };

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(encryptedRequestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}
		String uri = r.getURI();

		// Check that the group bit is not set
		byte flagByte = r.getOptions().getOscore()[0];
		int groupModeBit = flagByte & 0x20;
		assertEquals(0, groupModeBit);

		// Set the context in the context database
		HashMapCtxDB db = new HashMapCtxDB();
		db.addContext(uri, commonCtx);

		// Decrypt the request message
		Request decrypted = RequestDecryptor.decrypt(db, r, recipientCtx);

		// Check the decrypted request URI
		String predictedURI = "coap://localhost/tv1";
		assertEquals(predictedURI, decrypted.getURI());

		// Serialize the request message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(decrypted);

		// Check the whole decrypted request
		byte[] predictedBytes = { 0x44, (byte) 0x01, (byte) 0x71, (byte) 0xC3, (byte) 0x00, (byte) 0x00, (byte) 0xB9,
				(byte) 0x32, (byte) 0x39, (byte) 0x6C, (byte) 0x6F, (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x68,
				(byte) 0x6F, (byte) 0x73, (byte) 0x74, (byte) 0x6C, (byte) 0x19, (byte) 0x14, (byte) 0x08, (byte) 0x74,
				(byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x00,
				(byte) 0x23, (byte) 0x74, (byte) 0x76, (byte) 0x31 };
		assertArrayEquals(predictedBytes, decryptedBytes);

	}

	@Rule
	public ExpectedException exceptionRule = ExpectedException.none();

	/**
	 * Wrong par countersign key
	 * 
	 * @throws OSException if encryption fails
	 * @throws CoseException on test failure
	 */
	@Test
	public void testRequestDecryptorPairwiseModeFail() throws OSException, CoseException {
		exceptionRule.expect(CoapOSException.class);
		exceptionRule.expectMessage("Decryption failed");

		// Set up OSCORE context
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[] { 0x00 };

		// Create client context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, algCountersign);
		OneKey clientFullKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(clientKeyString)));
		commonCtx.addSenderCtx(sid, clientFullKey);

		// Create server context
		OneKey serverPublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(serverKeyString))).PublicKey();
		commonCtx.addRecipientCtx(rid, REPLAY_WINDOW, serverPublicKey);
		GroupRecipientCtx recipientCtx = commonCtx.recipientCtxMap.get(new ByteId(rid));

		// Create request message from raw byte array
		byte[] encryptedRequestBytes = new byte[] { (byte) 0x44, (byte) 0x02, (byte) 0x71, (byte) 0xC3, (byte) 0x00,
				(byte) 0x00, (byte) 0xB9, (byte) 0x32, (byte) 0x39, (byte) 0x6C, (byte) 0x6F, (byte) 0x63, (byte) 0x61,
				(byte) 0x6C, (byte) 0x68, (byte) 0x6F, (byte) 0x73, (byte) 0x74, (byte) 0x6C, (byte) 0x19, (byte) 0x14,
				(byte) 0x08, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x74, (byte) 0x65, (byte) 0x73,
				(byte) 0x74, (byte) 0x00, (byte) 0xFF, (byte) 0xA8, (byte) 0xB9, (byte) 0xED, (byte) 0x2B, (byte) 0xBD,
				(byte) 0xD3, (byte) 0xAC, (byte) 0x15, (byte) 0x47, (byte) 0xA6, (byte) 0x97, (byte) 0x70,
				(byte) 0x02 };

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(encryptedRequestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}
		String uri = r.getURI();

		// Set the context in the context database
		HashMapCtxDB db = new HashMapCtxDB();
		db.addContext(uri, commonCtx);

		// Set an incorrect par countersign key
		commonCtx.parCountersignKey = new int[] { 10 };

		// Decrypt the request message
		RequestDecryptor.decrypt(db, r, recipientCtx);
	}


}
