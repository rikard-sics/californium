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
package org.eclipse.californium.oscore.group.interop;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.UdpEndpointContext;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.RequestDecryptor;
import org.eclipse.californium.oscore.RequestEncryptor;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.GroupRecipientCtx;
import org.eclipse.californium.oscore.group.GroupSenderCtx;
import org.eclipse.californium.oscore.group.OneKeyDecoder;
import org.eclipse.californium.oscore.group.SharedSecretCalculation;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

/**
 * Tests key derivation for Group OSCORE for both ECDSA_256 and EdDSA
 * countersignature algorithms. The AEAD algorithm used is the default
 * AES-CCM-16-64-128 and the HKDF algorithm the default HKDF SHA-256.
 * 
 * Using test vectors defined for the IETF 108 Hackathon Group OSCORE
 * interoperability tests.
 * 
 * See: https://github.com/ace-wg/Hackathon-108/blob/master/GroupKeys.md
 * 
 */
public class GroupKeyDerivationInteropJimTests {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	// OSCORE context information database
	private final static HashMapCtxDB db = new HashMapCtxDB();

	// Define AEAD and HKDF algorithms
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Imagined multicast addresses for recipient groups
	private static String groupEcdsa = "groupEcdsa";
	private static String groupEddsa = "groupEddsa";

	/* --- Context parameters for ECDSA 256 --- */

	// My entity #1
	static byte[] sid = InteropParametersOld2.RIKARD_ENTITY_1_KID;
	// Jim entity #2
	static byte[] rid1 = InteropParametersOld2.JIM_ENTITY_2_KID;
	// Jim entity #3
	static byte[] rid2 = InteropParametersOld2.JIM_ENTITY_3_KID;

	private final static byte[] master_secret = InteropParametersOld2.MASTER_SECRET_ECDSA;
	private final static byte[] master_salt = InteropParametersOld2.MASTER_SALT_ECDSA;
	private final static byte[] context_id = InteropParametersOld2.GROUP_ID_ECDSA;

	// My entity #1
	private static String senderFullKeyEcdsa256 = InteropParametersOld2.RIKARD_ENTITY_1_KEY_ECDSA;

	// Jim entity #2 (only public part is added to context)
	private static String recipient1PublicKeyEcdsa256 = InteropParametersOld2.JIM_ENTITY_2_KEY_ECDSA;

	// Jim entity #3 (only public part is added to context)
	private static String recipient2PublicKeyEcdsa256 = InteropParametersOld2.JIM_ENTITY_3_KEY_ECDSA;

	/* --- End Context parameters for ECDSA 256 --- */

	/* --- Context parameters for EdDSA FIXME: Add --- */

	private static String senderFullKeyEddsa = "{1: 1, 2: h'01', -4: h'397CEB5A8D21D74A9258C20C33FC45AB152B02CF479B2E3081285F77454CF347', -2: h'CE616F28426EF24EDB51DBCEF7A23305F886F657959D4DF889DDFC0255042159', -1: 6}";
	private static String recipient1PublicKeyEddsa = "{1: 1, 2: h'', -4: h'70559B9EECDC578D5FC2CA37F9969630029F1592AFF3306392AB15546C6A184A', -2: h'2668BA6CA302F14E952228DA1250A890C143FDBA4DAED27246188B9E42C94B6D', -1: 6}";
	private static String recipient2PublicKeyEddsa = "{1: 1, 2: h'AA', -4: h'E550CD532B881D52AD75CE7B91171063E568F2531FBDFB32EE01D1910BCF810F', -2: h'5394E43633CDAC96F05120EA9F21307C9355A1B66B60A834B53E9BF60B1FB7DF', -1: 6}";

	/* --- End Context parameters for EdDSA --- */

	private static final int REPLAY_WINDOW = 32;

	// The contexts generated for use in the tests
	private static GroupSenderCtx senderCtxEcdsa;
	private static GroupSenderCtx senderCtxEddsa;

	private static GroupRecipientCtx recipient1CtxEcdsa;
	private static GroupRecipientCtx recipient2CtxEcdsa;

	private static GroupRecipientCtx recipient1CtxEddsa;
	private static GroupRecipientCtx recipient2CtxEddsa;

	/* --- Tests follow --- */

	@Test
	public void testEDDSAKeys() throws Exception {
		deriveContexts();
		// Install EdDSA cryptographic provider
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		OneKey senderKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(senderFullKeyEddsa));
		OneKey recipient1Key = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient1PublicKeyEddsa));
		OneKey recipient2Key = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient2PublicKeyEddsa));

		// Check the properties of the decoded keys

		// Key ID is set
		assertNotNull(senderKey.get(KeyKeys.KeyId));
		assertNotNull(recipient1Key.get(KeyKeys.KeyId));
		assertNotNull(recipient2Key.get(KeyKeys.KeyId));

		// Key type
		assertEquals(KeyKeys.KeyType_OKP, senderKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_OKP, recipient1Key.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_OKP, recipient2Key.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.OKP_Ed25519, senderKey.get(KeyKeys.OKP_Curve));
		assertEquals(KeyKeys.OKP_Ed25519, recipient1Key.get(KeyKeys.OKP_Curve));
		assertEquals(KeyKeys.OKP_Ed25519, recipient2Key.get(KeyKeys.OKP_Curve));

		// Attempt to sign using the key to see that it works
		// TODO
	}

	/**
	 * Create a message based on Jim Test 1 Entity 1 data.
	 * 
	 * @throws OSException on failure
	 */
	@Test
	public void testMessage1Creation() throws OSException {
		String destinationUri = "coap://127.0.0.1/test";

		GroupCtx groupCtxJim = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.ECDSA_256, null);
		OneKey senderFullKey = OneKeyDecoder.parseDiagnostic(InteropParametersOld2.JIM_ENTITY_1_KEY_ECDSA);
		groupCtxJim.addSenderCtx(InteropParametersOld2.JIM_ENTITY_1_KID, senderFullKey);
		db.addContext(destinationUri, groupCtxJim);

		// create request
		// CoapClient client = new CoapClient();
		// client.setTimeout((long) 250);
		// client.setURI(destinationUri);

		GroupSenderCtx senderCtxJim = (GroupSenderCtx) db.getContext(destinationUri);
		senderCtxJim.setSenderSeq(1);

		Request request = Request.newGet();
		request.setType(Type.NON);
		request.getOptions().setOscore(Bytes.EMPTY);
		request.setURI(destinationUri);

		// encrypt
		Request encrypted = RequestEncryptor.encrypt(db, request);

		System.out.println(encrypted);

		System.out.println("Common IV: " + Utils.bytesToHex(senderCtxJim.getCommonIV()));
		System.out.println("Sender Key: " + Utils.bytesToHex(senderCtxJim.getSenderKey()));

		System.out.println("Payload: " + Utils.bytesToHex(encrypted.getPayload()));

	}

	/**
	 * Create a message based on Jim Test 1 Entity 1 data. From Jims message
	 * bytes
	 * 
	 * @throws OSException on failure
	 */
	@Test
	public void testMessage1CreationAlt() throws OSException {
		// String destinationUri = "coap://127.0.0.1/test";

		GroupCtx groupCtxJim = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.ECDSA_256, null);
		OneKey senderFullKey = OneKeyDecoder.parseDiagnostic(InteropParametersOld2.JIM_ENTITY_1_KEY_ECDSA);
		groupCtxJim.addSenderCtx(InteropParametersOld2.JIM_ENTITY_1_KID, senderFullKey);

		// Jim message bytes:
		// 4001ffffb1610162

		// create request
		// CoapClient client = new CoapClient();
		// client.setTimeout((long) 250);
		// client.setURI(destinationUri);


		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(Utils.hexToBytes("4001ffffb1610162"));

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}
		Assert.assertNotNull(r);
		r.getOptions().setOscore(Bytes.EMPTY);

		db.addContext(r.getURI(), groupCtxJim);
		GroupSenderCtx senderCtxJim = (GroupSenderCtx) db.getContext(r.getURI());
		senderCtxJim.setSenderSeq(1);

		// Request request = Request.newGet();
		// request.setType(Type.NON);
		// request.getOptions().setOscore(Bytes.EMPTY);
		// request.setURI(destinationUri);



		// encrypt
		Request encrypted = RequestEncryptor.encrypt(db, r);

		System.out.println(encrypted);
		
		System.out.println("Common IV: " + Utils.bytesToHex(senderCtxJim.getCommonIV()));
		System.out.println("Sender Key: " + Utils.bytesToHex(senderCtxJim.getSenderKey()));

		System.out.println("Payload: " + Utils.bytesToHex(encrypted.getPayload()));

	}

	@Test
	@Ignore // TODO: Recalculate
	public void testMessage1Reception() throws OSException {

		// --- Try decryption ---
		String destinationUri = "coap://127.0.0.1/test";

		GroupCtx groupCtxJim = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.ECDSA_256, null);
		OneKey senderFullKey = OneKeyDecoder.parseDiagnostic(InteropParametersOld2.RIKARD_ENTITY_2_KEY_ECDSA);
		groupCtxJim.addSenderCtx(InteropParametersOld2.RIKARD_ENTITY_2_KID, senderFullKey);
		groupCtxJim.addRecipientCtx(InteropParametersOld2.JIM_ENTITY_1_KID, REPLAY_WINDOW,
				OneKeyDecoder.parseDiagnostic(InteropParametersOld2.JIM_ENTITY_1_KEY_ECDSA).PublicKey());
		db.addContext(destinationUri, groupCtxJim);
		GroupRecipientCtx recipientCtx = (GroupRecipientCtx) db.getContext(InteropParametersOld2.JIM_ENTITY_1_KID,
				context_id);

		// Create request message from raw byte array
		byte[] requestBytes = Utils.hexToBytes(
				"4002FFFF973901030A0B0CE1FFF0A0FBE1AE80E924C90E04427DCC73DA94008ECD54DB98DA4FF171F823C5EBD46C78BDC79CD8D919E6CC25F29069260E71539EF76AE90A58EEFFBBC20CEE0A12D1334418349225CDE8164EF08E");

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(requestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}

		// Set up some state information simulating an incoming request
		OSCoreCtxDB db = new HashMapCtxDB();
		// FIXME: //recipientCtx.setReceiverSeq(seq - 1);
		db.addContext(recipientCtx);
		Assert.assertNotNull(r);
		r.setSourceContext(new UdpEndpointContext(new InetSocketAddress(0)));

		System.out.println("Common IV: " + Utils.bytesToHex(recipientCtx.getCommonIV()));
		System.out.println("Recipient Key: " + Utils.bytesToHex(recipientCtx.getRecipientKey()));

		// Decrypt the request message
		Request decrypted = RequestDecryptor.decrypt(db, r, recipientCtx);
		decrypted.getOptions().removeOscore();

		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedBytes = serializer.getByteArray(decrypted);

		System.out.println("Decrypted: " + Utils.bytesToHex(encryptedBytes));
	}

	@Test
	public void testSharedSecretECDSA()
			throws OSException, CoseException, NoSuchAlgorithmException, InvalidKeyException {

		GroupCtx groupCtxJim = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.ECDSA_256, null);

		OneKey senderFullKey = OneKeyDecoder.parseDiagnostic(InteropParametersOld2.JIM_ENTITY_1_KEY_ECDSA);
		groupCtxJim.addSenderCtx(InteropParametersOld2.JIM_ENTITY_1_KID, senderFullKey);

		groupCtxJim.addRecipientCtx(InteropParametersOld2.JIM_ENTITY_2_KID, REPLAY_WINDOW,
				OneKeyDecoder.parseDiagnostic(InteropParametersOld2.JIM_ENTITY_2_KEY_ECDSA).PublicKey());

		OneKey recipient2PublicKey = OneKeyDecoder.parseDiagnostic(InteropParametersOld2.JIM_ENTITY_3_KEY_ECDSA).PublicKey();
		groupCtxJim.addRecipientCtx(InteropParametersOld2.JIM_ENTITY_3_KID, REPLAY_WINDOW,
				recipient2PublicKey);

		db.addContext(groupEcdsa, groupCtxJim);

		GroupSenderCtx senderCtx = (GroupSenderCtx) db.getContext(groupEcdsa);
		GroupRecipientCtx recipientCtx = (GroupRecipientCtx) db.getContext(InteropParametersOld2.JIM_ENTITY_3_KID,
				context_id);

		assertNotNull(senderCtx);
		assertNotNull(recipientCtx);

		System.out.println("Sender Key 1->3: " + hexPrintDash(senderCtx.getSenderKey()));
		System.out.println("Recipient Key 1->3: " + hexPrintDash(recipientCtx.getRecipientKey()));

		byte[] pairwiseSenderKey = senderCtx.getPairwiseSenderKey(InteropParametersOld2.JIM_ENTITY_3_KID);
		byte[] pairwiseRecipientKey = recipientCtx.getPairwiseRecipientKey();

		assertNotNull(pairwiseSenderKey);
		assertNotNull(pairwiseRecipientKey);

		System.out.println("Pairwise Sender Key 1->3: " + hexPrintDash(pairwiseSenderKey));
		System.out.println("Pairwise Recipient Key 1->3: " + hexPrintDash(pairwiseRecipientKey));

		// Shared secret
		ECPublicKey recipientPubKey = (ECPublicKey) recipient2PublicKey.AsPublicKey();
		ECPrivateKey senderPrivKey = (ECPrivateKey) senderFullKey.AsPrivateKey();
		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(senderPrivKey);
		keyAgreement.doPhase(recipientPubKey, true);
		byte[] sharedSecret = keyAgreement.generateSecret();

		System.out.println("Shared Secret 1->3: " + hexPrintDash(sharedSecret).toUpperCase());

	}

	@Test
	@Ignore
	public void testECDSA256Keys() throws Exception {
		deriveContexts();

		OneKey senderKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(senderFullKeyEcdsa256));
		OneKey recipient1Key = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient1PublicKeyEcdsa256));
		OneKey recipient2Key = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient2PublicKeyEcdsa256));

		// Check the properties of the decoded keys

		// Key ID is set
		assertNotNull(senderKey.get(KeyKeys.KeyId));
		assertNotNull(recipient1Key.get(KeyKeys.KeyId));
		assertNotNull(recipient2Key.get(KeyKeys.KeyId));

		// Key type
		assertEquals(KeyKeys.KeyType_EC2, senderKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_EC2, recipient1Key.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_EC2, recipient2Key.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.EC2_P256, senderKey.get(KeyKeys.EC2_Curve));
		assertEquals(KeyKeys.EC2_P256, recipient1Key.get(KeyKeys.EC2_Curve));
		assertEquals(KeyKeys.EC2_P256, recipient2Key.get(KeyKeys.EC2_Curve));

		// Attempt to sign using the key to see that it works
		// TODO
	}

	@Test
	public void testContextsAlgCountersign() throws OSException, CoseException {
		deriveContexts();

		// Check that the contexts use the correct countersignature algorithms

		assertEquals(AlgorithmID.ECDSA_256, senderCtxEcdsa.getAlgSign());
		assertEquals(AlgorithmID.ECDSA_256, recipient1CtxEcdsa.getAlgSign());
		assertEquals(AlgorithmID.ECDSA_256, recipient2CtxEcdsa.getAlgSign());

		assertEquals(AlgorithmID.EDDSA, senderCtxEddsa.getAlgSign());
		assertEquals(AlgorithmID.EDDSA, recipient1CtxEddsa.getAlgSign());
		assertEquals(AlgorithmID.EDDSA, recipient2CtxEddsa.getAlgSign());
	}

	@Test
	@Ignore
	public void testSenderKeys() throws OSException, CoseException {

		deriveContexts();

		// Check that sender keys match in both contexts
		assertArrayEquals(senderCtxEcdsa.getSenderKey(), senderCtxEddsa.getSenderKey());

		// Check that they match expected value
		byte[] expectedSenderKey = Utils.hexToBytes("8901226f92a6f3e90feb36a9e6b277f8");
		assertArrayEquals(expectedSenderKey, senderCtxEcdsa.getSenderKey());
	}

	@Test
	@Ignore
	public void testRecipientKeys() throws OSException, CoseException {

		deriveContexts();

		// Check that recipient keys match in both contexts
		assertArrayEquals(recipient1CtxEcdsa.getRecipientKey(), recipient1CtxEddsa.getRecipientKey());
		assertArrayEquals(recipient2CtxEcdsa.getRecipientKey(), recipient2CtxEddsa.getRecipientKey());

		// Check that they match expected value
		byte[] expectedRecipient1Key = Utils.hexToBytes("E9BB12DE9ED96975D78CEBF59A5F87E7");
		assertArrayEquals(expectedRecipient1Key, recipient1CtxEcdsa.getRecipientKey());

		byte[] expectedRecipient2Key = Utils.hexToBytes("EB999F5EE8F06813B346E937723BDEF4");
		assertArrayEquals(expectedRecipient2Key, recipient2CtxEcdsa.getRecipientKey());
	}

	@Test
	@Ignore
	public void testPairwiseRecipientKeys() throws OSException, CoseException {

		deriveContexts();

		byte[] recipient1EcdsaPairwiseKey = recipient1CtxEcdsa.getPairwiseRecipientKey();
		byte[] recipient2EcdsaPairwiseKey = recipient2CtxEcdsa.getPairwiseRecipientKey();

		byte[] recipient1EddsaPairwiseKey = recipient1CtxEddsa.getPairwiseRecipientKey();
		byte[] recipient2EddsaPairwiseKey = recipient2CtxEddsa.getPairwiseRecipientKey();

		// Pairwise recipient keys are different depending on algorithm
		assertFalse(Arrays.equals(recipient1EcdsaPairwiseKey, recipient1EddsaPairwiseKey));
		assertFalse(Arrays.equals(recipient2EcdsaPairwiseKey, recipient2EddsaPairwiseKey));

		// And different from each other for the same algorithm
		assertFalse(Arrays.equals(recipient1EcdsaPairwiseKey, recipient2EcdsaPairwiseKey));
		assertFalse(Arrays.equals(recipient1EddsaPairwiseKey, recipient2EddsaPairwiseKey));

		// Check that they match expected value
		assertArrayEquals(Utils.hexToBytes("eb2eeb87fb26eafcbbc6a251f221bc59"), recipient1EcdsaPairwiseKey);
		assertArrayEquals(Utils.hexToBytes("b0cf5cc0fe46b0ab09250207c9662657"), recipient2EcdsaPairwiseKey);

		assertArrayEquals(Utils.hexToBytes("bc3fd193c1c29166c6136384eca7f0ac"), recipient1EddsaPairwiseKey);
		assertArrayEquals(Utils.hexToBytes("3bb7d53ae94c0eb33b6c1d3075c9b9bb"), recipient2EddsaPairwiseKey);

	}

	@Test
	@Ignore
	public void testPairwiseSenderKeys() throws OSException, CoseException {

		deriveContexts();

		byte[] senderEcdsaPairwiseKey1 = senderCtxEcdsa.getPairwiseSenderKey(rid1);
		byte[] senderEcdsaPairwiseKey2 = senderCtxEcdsa.getPairwiseSenderKey(rid2);

		byte[] senderEddsaPairwiseKey1 = senderCtxEddsa.getPairwiseSenderKey(rid1);
		byte[] senderEddsaPairwiseKey2 = senderCtxEddsa.getPairwiseSenderKey(rid2);

		// Pairwise sender keys are different depending on algorithm
		assertFalse(Arrays.equals(senderEcdsaPairwiseKey1, senderEddsaPairwiseKey1));
		assertFalse(Arrays.equals(senderEcdsaPairwiseKey2, senderEddsaPairwiseKey2));

		// And different from each other for the same algorithm
		assertFalse(Arrays.equals(senderEcdsaPairwiseKey1, senderEcdsaPairwiseKey2));
		assertFalse(Arrays.equals(senderEddsaPairwiseKey1, senderEddsaPairwiseKey2));

		// Check that they match expected value
		assertArrayEquals(Utils.hexToBytes("523ced595ac2c7bf17a95ef4f0cf236f"), senderEcdsaPairwiseKey1);
		assertArrayEquals(Utils.hexToBytes("4a321b7a96aa16ed951c19b2a0ea12b7"), senderEcdsaPairwiseKey2);

		assertArrayEquals(Utils.hexToBytes("1bbbf01e002ef1fc96aef602a8a591c5"), senderEddsaPairwiseKey1);
		assertArrayEquals(Utils.hexToBytes("f5051fe0a7c65f8823a6f44ed885cfb8"), senderEddsaPairwiseKey2);

	}

	@Test
	@Ignore
	public void testSharedSecretsEddsa() throws CoseException, OSException {

		deriveContexts();

		// Check that recipient keys match in both contexts
		byte[] sharedSecret1 = SharedSecretCalculation.calculateSharedSecret(recipient1CtxEddsa.getPublicKey(),
				senderCtxEddsa.getPrivateKey());
		byte[] sharedSecret2 = SharedSecretCalculation.calculateSharedSecret(recipient2CtxEddsa.getPublicKey(),
				senderCtxEddsa.getPrivateKey());

		// Check that they do not match each other
		assertFalse(Arrays.equals(sharedSecret1, sharedSecret2));

		// Check that they match expected value
		assertArrayEquals(Utils.hexToBytes("608c1d7ac18064375c228c9c4d75533ec98940baf71010ee94ecd6f509c4ad32"),
				sharedSecret1);
		assertArrayEquals(Utils.hexToBytes("ee8302d90f8f9da618312479cb77fc2f45e6bff8622b4600d9016580332a545c"),
				sharedSecret2);
	}

	@Test
	@Ignore
	public void testSharedSecretsEcdsa()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, OSException {

		deriveContexts();

		ECPublicKey recipientPubKey = (ECPublicKey) recipient1CtxEcdsa.getPublicKey().AsPublicKey();
		ECPrivateKey senderPrivKey = (ECPrivateKey) senderCtxEcdsa.getPrivateKey().AsPrivateKey();
		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(senderPrivKey);
		keyAgreement.doPhase(recipientPubKey, true);
		byte[] sharedSecret1 = keyAgreement.generateSecret();

		recipientPubKey = (ECPublicKey) recipient2CtxEcdsa.getPublicKey().AsPublicKey();
		senderPrivKey = (ECPrivateKey) senderCtxEcdsa.getPrivateKey().AsPrivateKey();
		keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(senderPrivKey);
		keyAgreement.doPhase(recipientPubKey, true);
		byte[] sharedSecret2 = keyAgreement.generateSecret();

		// Check that they do not match each other
		assertFalse(Arrays.equals(sharedSecret1, sharedSecret2));

		// Check that they match expected value
		assertArrayEquals(Utils.hexToBytes("b58f9fae3080f7eee5de9685cb286f57c4bb31e858171c60ca86856185b44e64"),
				sharedSecret1);
		assertArrayEquals(Utils.hexToBytes("34fdaf5d3035f4067475cbfbc05a2e7d8a743c65569567a17a9ad8f89809b715"),
				sharedSecret2);
	}

	/* --- End of tests --- */

	/**
	 * Derives OSCORE context information for tests
	 *
	 * @throws OSException on failure to create the contexts
	 * @throws CoseException on failure to create the contexts
	 */
	public static void deriveContexts() throws OSException, CoseException {

		// Create context using ECDSA_256

		GroupCtx groupCtxEcdsa = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.ECDSA_256, null);

		OneKey senderFullKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(senderFullKeyEcdsa256));
		groupCtxEcdsa.addSenderCtx(sid, senderFullKey);

		OneKey recipient1PublicKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient1PublicKeyEcdsa256))
				.PublicKey();
		OneKey recipient2PublicKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient2PublicKeyEcdsa256))
				.PublicKey();
		groupCtxEcdsa.addRecipientCtx(rid1, REPLAY_WINDOW, recipient1PublicKey);
		groupCtxEcdsa.addRecipientCtx(rid2, REPLAY_WINDOW, recipient2PublicKey);

		db.addContext(groupEcdsa, groupCtxEcdsa);

		// Save the generated sender and recipient contexts

		senderCtxEcdsa = (GroupSenderCtx) db.getContext(groupEcdsa);
		recipient1CtxEcdsa = (GroupRecipientCtx) db.getContext(rid1, context_id);
		recipient2CtxEcdsa = (GroupRecipientCtx) db.getContext(rid2, context_id);

		// Clear existing contexts
		// db.purge();

		// Create context using EdDSA

		// Install EdDSA cryptographic provider
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		GroupCtx groupCtxEddsa = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.EDDSA, null);

		senderFullKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(senderFullKeyEddsa));
		groupCtxEddsa.addSenderCtx(sid, senderFullKey);

		recipient1PublicKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient1PublicKeyEddsa)).PublicKey();
		recipient2PublicKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient2PublicKeyEddsa)).PublicKey();
		groupCtxEddsa.addRecipientCtx(rid1, REPLAY_WINDOW, recipient1PublicKey);
		groupCtxEddsa.addRecipientCtx(rid2, REPLAY_WINDOW, recipient2PublicKey);

		db.addContext(groupEddsa, groupCtxEddsa);

		// Save the generated sender and recipient contexts

		senderCtxEddsa = (GroupSenderCtx) db.getContext(groupEddsa);
		recipient1CtxEddsa = (GroupRecipientCtx) db.getContext(rid1, context_id);
		recipient2CtxEddsa = (GroupRecipientCtx) db.getContext(rid2, context_id);

	}

	private static String hexPrintDash(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X-", b));
		}
		return sb.toString();
	}
}
