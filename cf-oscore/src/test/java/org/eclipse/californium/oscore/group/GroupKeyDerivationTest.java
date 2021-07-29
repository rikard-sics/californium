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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

/**
 * Tests key derivation for Group OSCORE for both ECDSA_256 and EdDSA
 * countersignature algorithms. The AEAD algorithm used is the default
 * AES-CCM-16-64-128 and the HKDF algorithm the default HKDF SHA-256.
 * 
 * 
 */
public class GroupKeyDerivationTest {

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

	// Define context information (based on OSCORE RFC section C.3.2. Server)
	static byte[] sid = new byte[] { 0x01 };
	static byte[] rid1 = Bytes.EMPTY;
	static byte[] rid2 = new byte[] { (byte) 0xAA };

	private final static byte[] master_secret = Utils.hexToBytes("0102030405060708090a0b0c0d0e0f10");
	private final static byte[] master_salt = Utils.hexToBytes("9e7ca92223786340");
	private final static byte[] context_id = Utils.hexToBytes("37cbf3210017a2d3");

	// Key for the GM
	private static String gmPublicKeyString = "pQF4GmNvYXBzOi8vbXlzaXRlLmV4YW1wbGUuY29tAmxncm91cG1hbmFnZXIDeBpjb2FwczovL2RvbWFpbi5leGFtcGxlLm9yZwQaq5sVTwihAaQDJwEBIAYhWCDN4+/TvD+ZycnuIQQVxsulUGG1BG6WO4pYyRQ6YRZkcg==";
	private static byte[] gmPublicKey = DatatypeConverter.parseBase64Binary(gmPublicKeyString);

	// Keys for sender and recipients
	private static String senderFullKeyEcdsa256 = "pgECI1gglNzgRMuHlfN2GkwWR4NdyWHxtOLRb2MS91r01cs9U40iWCAZbxTFset0hvgSSr5uXDkA8XW1yDxdTu73tsjbHZZwIiFYIPK3Cfi/BEfAQ4AflFK1LHPTDDAjAGZliQ0TJsQWcDbAIAEDJg==";
	private static String recipient1PublicKeyEcdsa256 = "pQECIlggOAOKygJds3bh3MY/dNuDmsrNO+jq2f3HRi49ZgOdDichWCB4RLBsbGo77cB6XmhKXAtwLIAh9WEBUr5AmArevy4OPCABAyY=";
	private static String recipient2PublicKeyEcdsa256 = "pQECIlggbRsiRXIzfKMwqaRAAdM3hEqA7qeWoAp8TdMcgVfliTwhWCDaWB1vDk8Bii9v1uMir8n5yDhXN4oo/Hyy+byOYbtOZyABAyY=";

	private static String senderFullKeyEddsa = "pQEBI1ggCwKEpeSlukUHdJUa6vkpcDubFYILFN9zu5DY6o3ELzchWCDpn2kGBGzWxKj5DcvGsBstq8HmxiftUxLGVnJMC/hvViAGAyc=";
	private static String recipient1PublicKeyEddsa = "pAEBIVggwXKmLgPAR/kJhGQiXNWLFPMtYcBIpDmnNwR8HW6npMIgBgMn";
	private static String recipient2PublicKeyEddsa = "pAEBIVggNlUzBhfpSxm0deeqpAb+Sf2zNLpnz242nnT4/IyzrMwgBgMn";

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
		// Install EdDSA cryptographic provider
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

		OneKey senderKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(senderFullKeyEddsa)));
		OneKey recipient1Key = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(recipient1PublicKeyEddsa)));
		OneKey recipient2Key = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(recipient2PublicKeyEddsa)));

		// Check the properties of the decoded keys

		// Algorithm
		assertEquals(AlgorithmID.EDDSA.AsCBOR(), senderKey.get(KeyKeys.Algorithm));
		assertEquals(AlgorithmID.EDDSA.AsCBOR(), recipient1Key.get(KeyKeys.Algorithm));
		assertEquals(AlgorithmID.EDDSA.AsCBOR(), recipient2Key.get(KeyKeys.Algorithm));

		// Key type
		assertEquals(KeyKeys.KeyType_OKP, senderKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_OKP, recipient1Key.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_OKP, recipient2Key.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.OKP_Ed25519, senderKey.get(KeyKeys.OKP_Curve));
		assertEquals(KeyKeys.OKP_Ed25519, recipient1Key.get(KeyKeys.OKP_Curve));
		assertEquals(KeyKeys.OKP_Ed25519, recipient2Key.get(KeyKeys.OKP_Curve));
	}

	@Test
	public void testECDSA256Keys() throws Exception {

		OneKey senderKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(senderFullKeyEcdsa256)));
		OneKey recipient1Key = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(recipient1PublicKeyEcdsa256)));
		OneKey recipient2Key = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(recipient2PublicKeyEcdsa256)));

		// Check the properties of the decoded keys

		// Algorithm
		assertEquals(AlgorithmID.ECDSA_256.AsCBOR(), senderKey.get(KeyKeys.Algorithm));
		assertEquals(AlgorithmID.ECDSA_256.AsCBOR(), recipient1Key.get(KeyKeys.Algorithm));
		assertEquals(AlgorithmID.ECDSA_256.AsCBOR(), recipient2Key.get(KeyKeys.Algorithm));

		// Key type
		assertEquals(KeyKeys.KeyType_EC2, senderKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_EC2, recipient1Key.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_EC2, recipient2Key.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.EC2_P256, senderKey.get(KeyKeys.EC2_Curve));
		assertEquals(KeyKeys.EC2_P256, recipient1Key.get(KeyKeys.EC2_Curve));
		assertEquals(KeyKeys.EC2_P256, recipient2Key.get(KeyKeys.EC2_Curve));
	}

	@Test
	public void testContextsAlgCountersign() throws OSException {
		// Check that the contexts use the correct countersignature algorithms

		assertEquals(AlgorithmID.ECDSA_256, senderCtxEcdsa.getAlgCountersign());
		assertEquals(AlgorithmID.ECDSA_256, recipient1CtxEcdsa.getAlgCountersign());
		assertEquals(AlgorithmID.ECDSA_256, recipient2CtxEcdsa.getAlgCountersign());

		assertEquals(AlgorithmID.EDDSA, senderCtxEddsa.getAlgCountersign());
		assertEquals(AlgorithmID.EDDSA, recipient1CtxEddsa.getAlgCountersign());
		assertEquals(AlgorithmID.EDDSA, recipient2CtxEddsa.getAlgCountersign());
	}

	@Test
	public void testSenderKeys() throws OSException {
		// Check that sender keys match in both contexts
		assertArrayEquals(senderCtxEcdsa.getSenderKey(), senderCtxEddsa.getSenderKey());

		// Check that they match expected value
		byte[] expectedSenderKey = Utils.hexToBytes("e39a0c7c77b43f03b4b39ab9a268699f");
		assertArrayEquals(expectedSenderKey, senderCtxEcdsa.getSenderKey());
	}

	@Test
	public void testRecipientKeys() throws OSException {
		// Check that recipient keys match in both contexts
		assertArrayEquals(recipient1CtxEcdsa.getRecipientKey(), recipient1CtxEddsa.getRecipientKey());
		assertArrayEquals(recipient2CtxEcdsa.getRecipientKey(), recipient2CtxEddsa.getRecipientKey());

		// Check that they match expected value
		byte[] expectedRecipient1Key = Utils.hexToBytes("af2a1300a5e95788b356336eeecd2b92");
		assertArrayEquals(expectedRecipient1Key, recipient1CtxEcdsa.getRecipientKey());

		byte[] expectedRecipient2Key = Utils.hexToBytes("4d9eabdba0f97f044fc0ee5313b1ebc6");
		assertArrayEquals(expectedRecipient2Key, recipient2CtxEcdsa.getRecipientKey());
	}

	@Test
	@Ignore // FIXME
	public void testPairwiseRecipientKeys() throws OSException {
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
		assertArrayEquals(Utils.hexToBytes("47f5d0e5b5f960d32d71ee84251b5b1f"), recipient1EcdsaPairwiseKey);
		assertArrayEquals(Utils.hexToBytes("062497fcf47ea88ac39891892641bc87"), recipient2EcdsaPairwiseKey);

		assertArrayEquals(Utils.hexToBytes("951c4800a1d0cb9af8877dea5b3199b4"), recipient1EddsaPairwiseKey);
		assertArrayEquals(Utils.hexToBytes("81f67a9c7d618c1799b888f7cdf5da94"), recipient2EddsaPairwiseKey);

	}

	@Test
	@Ignore // FIXME
	public void testPairwiseSenderKeys() throws OSException {
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
		assertArrayEquals(Utils.hexToBytes("6df92ed2d895a01d7d3d7e9c630db854"), senderEcdsaPairwiseKey1);
		assertArrayEquals(Utils.hexToBytes("9c860e8c416dfd32b6ffc2e17a668a2d"), senderEcdsaPairwiseKey2);

		assertArrayEquals(Utils.hexToBytes("77a2c9e704800930c1b2f5a80cb271d8"), senderEddsaPairwiseKey1);
		assertArrayEquals(Utils.hexToBytes("c7e00b6631bbed519e359bc6a441c82d"), senderEddsaPairwiseKey2);

	}

	@Test
	public void testSharedSecretsEddsa() throws CoseException {
		// Check that recipient keys match in both contexts
		byte[] sharedSecret1 = SharedSecretCalculation.calculateSharedSecret(recipient1CtxEddsa.getPublicKey(),
				senderCtxEddsa.getPrivateKey());
		byte[] sharedSecret2 = SharedSecretCalculation.calculateSharedSecret(recipient2CtxEddsa.getPublicKey(),
				senderCtxEddsa.getPrivateKey());

		// Check that they do not match each other
		assertFalse(Arrays.equals(sharedSecret1, sharedSecret2));

		// Check that they match expected value
		assertArrayEquals(Utils.hexToBytes("fc299b3abaa8e013d3958a3ecc64522c0ba1bfa0979309d9b962280206e5a65d"),
				sharedSecret1);
		assertArrayEquals(Utils.hexToBytes("c59c68a927ac138d4b02fa3974da972e42aa2992ba2f74ab7832962d0923d050"),
				sharedSecret2);
	}

	@Test
	public void testSharedSecretsEcdsa()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, IllegalStateException {

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
		assertArrayEquals(Utils.hexToBytes("86b62ef1516335e1c317c3b66d01228499b2ac3b8f4ec43f5b3139f72c910663"),
				sharedSecret1);
		assertArrayEquals(Utils.hexToBytes("71b47902d696fc825cd809282c42529689ab1c9028a11c5a5f989f14e4a2688c"),
				sharedSecret2);
	}

	/* --- End of tests --- */

	/**
	 * Derives OSCORE context information for tests
	 *
	 * @throws OSException on failure to create the contexts
	 * @throws CoseException on failure to create the contexts
	 */
	@BeforeClass
	public static void deriveContexts() throws OSException, CoseException {

		// Create context using ECDSA_256

		GroupCtx groupCtxEcdsa = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.ECDSA_256,
				gmPublicKey);

		OneKey senderFullKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(senderFullKeyEcdsa256)));
		groupCtxEcdsa.addSenderCtx(sid, senderFullKey);

		OneKey recipient1PublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(recipient1PublicKeyEcdsa256)));
		OneKey recipient2PublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(recipient2PublicKeyEcdsa256)));
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
		Security.insertProviderAt(EdDSA, 0);

		GroupCtx groupCtxEddsa = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.EDDSA,
				gmPublicKey);

		senderFullKey = new OneKey(CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(senderFullKeyEddsa)));
		groupCtxEddsa.addSenderCtx(sid, senderFullKey);

		recipient1PublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(recipient1PublicKeyEddsa)));
		recipient2PublicKey = new OneKey(
				CBORObject.DecodeFromBytes(DatatypeConverter.parseBase64Binary(recipient2PublicKeyEddsa)));
		groupCtxEddsa.addRecipientCtx(rid1, REPLAY_WINDOW, recipient1PublicKey);
		groupCtxEddsa.addRecipientCtx(rid2, REPLAY_WINDOW, recipient2PublicKey);

		db.addContext(groupEddsa, groupCtxEddsa);

		// Save the generated sender and recipient contexts

		senderCtxEddsa = (GroupSenderCtx) db.getContext(groupEddsa);
		recipient1CtxEddsa = (GroupRecipientCtx) db.getContext(rid1, context_id);
		recipient2CtxEddsa = (GroupRecipientCtx) db.getContext(rid2, context_id);

	}

}
