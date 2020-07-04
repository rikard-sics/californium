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
public class GroupKeyDerivationInteropTest {

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

	// Define context information. These are based on values from Group OSCORE
	// interop test spec:
	// https://github.com/EricssonResearch/Multicast-OSCOAP/blob/41c8b0c58a762e2ae9b800bed244b25ae96a4278/test-spec1.md
	static byte[] sid = new byte[] { (byte) 0xA1 };
	static byte[] rid1 = new byte[] { (byte) 0xB2 };
	static byte[] rid2 = new byte[] { (byte) 0xB3 };

	private final static byte[] master_secret = Utils.hexToBytes("102030405060708090a0b0c0d0e0f001");
	private final static byte[] master_salt = Utils.hexToBytes("e9c79a2232873604");
	private final static byte[] context_id = Utils.hexToBytes("73bc3f1200712a3d");

	// Keys for sender and recipients
	// https://github.com/EricssonResearch/Multicast-OSCOAP/blob/wip/test-spec2.html
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
	public void testContextsAlgCountersign() {
		// Check that the contexts use the correct countersignature algorithms

		assertEquals(AlgorithmID.ECDSA_256, senderCtxEcdsa.getAlgSign());
		assertEquals(AlgorithmID.ECDSA_256, recipient1CtxEcdsa.getAlgSign());
		assertEquals(AlgorithmID.ECDSA_256, recipient2CtxEcdsa.getAlgSign());

		assertEquals(AlgorithmID.EDDSA, senderCtxEddsa.getAlgSign());
		assertEquals(AlgorithmID.EDDSA, recipient1CtxEddsa.getAlgSign());
		assertEquals(AlgorithmID.EDDSA, recipient2CtxEddsa.getAlgSign());
	}

	@Test
	public void testSenderKeys() throws OSException {
		// Check that sender keys match in both contexts
		assertArrayEquals(senderCtxEcdsa.getSenderKey(), senderCtxEddsa.getSenderKey());

		// Check that they match expected value
		byte[] expectedSenderKey = Utils.hexToBytes("57892057B3A8181989F42C23C3DE2F40");
		assertArrayEquals(expectedSenderKey, senderCtxEcdsa.getSenderKey());
	}

	@Test
	public void testRecipientKeys() throws OSException {
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

	@Test
	public void testDiagnosticKeyDecoding() {

		// ECDSA_256
		OneKey ecdsaKey = parseDiagnosticOneKeyAlt(
				"{1: 2, -1: 1, -2: h’E2A7DC0C5D23831A4F52FBFF759EF01A6B3A7D58694774D6E8505B31A351D6C4’, -3: h’F8CA44FEDC6C322D0946FC69AE7482CD066AD11F34AA5F5C63F4EADB320FD941’, -4: h’469C76F26B8D9F286449F42566AB8B8BA1B3A8DC6E711A1E2A6B548DBE2A1578’}");

		// Algorithm
		assertEquals(AlgorithmID.ECDSA_256.AsCBOR(), ecdsaKey.get(KeyKeys.Algorithm));

		// Key type
		assertEquals(KeyKeys.KeyType_EC2, ecdsaKey.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.EC2_P256, ecdsaKey.get(KeyKeys.EC2_Curve));

		// EDDSA
		OneKey eddsaKey = parseDiagnosticOneKeyAlt(
				"{1: 1, -1: 6, -2: h’2A279191227491C92E9C5AEDCF72F5C73E78E19C7E77172B4FEFCE09018AEFD4’, -4: h’D744189028C8F2652EBBF3576B4CB740926B25DA087043E978AE570AAD333495’}");

		// Algorithm
		assertEquals(AlgorithmID.EDDSA.AsCBOR(), eddsaKey.get(KeyKeys.Algorithm));

		// Key type
		assertEquals(KeyKeys.KeyType_OKP, eddsaKey.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.OKP_Ed25519, eddsaKey.get(KeyKeys.OKP_Curve));


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

		GroupCtx groupCtxEcdsa = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.ECDSA_256, null);

		OneKey senderFullKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(senderFullKeyEcdsa256));
		groupCtxEcdsa.addSenderCtx(sid, senderFullKey);

		OneKey recipient1PublicKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient1PublicKeyEcdsa256));
		OneKey recipient2PublicKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient2PublicKeyEcdsa256));
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

		recipient1PublicKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient1PublicKeyEddsa));
		recipient2PublicKey = new OneKey(OneKeyDecoder.parseDiagnosticToCbor(recipient2PublicKeyEddsa));
		groupCtxEddsa.addRecipientCtx(rid1, REPLAY_WINDOW, recipient1PublicKey);
		groupCtxEddsa.addRecipientCtx(rid2, REPLAY_WINDOW, recipient2PublicKey);

		db.addContext(groupEddsa, groupCtxEddsa);

		// Save the generated sender and recipient contexts

		senderCtxEddsa = (GroupSenderCtx) db.getContext(groupEddsa);
		recipient1CtxEddsa = (GroupRecipientCtx) db.getContext(rid1, context_id);
		recipient2CtxEddsa = (GroupRecipientCtx) db.getContext(rid2, context_id);

	}

	/**
	 * Parse a string representing a COSE OneKey in diagnostic notation. This
	 * method first builds a CBOR Object from the values in the string. A COSE
	 * OneKey is then created from that CBOR Object.
	 * 
	 * @param keyString string representing a OneKey in diagnostic notation
	 * @return a OneKey object built from the string
	 */
	public static OneKey parseDiagnosticOneKeyAlt(String keyString) {
		OneKey test = null;
		try {
			test = OneKey.generateKey(AlgorithmID.EDDSA);
		} catch (CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(test.AsCBOR().ToJSONString());
		CBORObject test2;
		CBORObject test3 = CBORObject.FromJSONString(test.AsCBOR().ToJSONString());
		System.out.println(test3.ToJSONString());

		// Convert to lower case
		keyString = keyString.toLowerCase();

		// Remove { and } characters
		keyString = keyString.replace("{", "");
		keyString = keyString.replace("}", "");
		// Remove spaces
		keyString = keyString.replace(" ", "");

		// Split the string into sections at the , and : character
		String[] segments = keyString.split("[,:]");

		//
		for (int i = 0; i < segments.length; i++) {
			System.out.println(segments[i]);
		}

		// Build CBOR Object from the segments
		CBORObject keyCbor = CBORObject.NewMap();

		for (int i = 0; i < segments.length; i += 2) {
			int key = Integer.parseInt(segments[i]);
			String value = segments[i + 1];

			// Handle byte array values
			if (value.length() >= 2 && value.substring(0, 2).equals("h’")) {
				String arrayString = value.replace("h’", "").replace("’", "");
				byte[] array = Utils.hexToBytes(arrayString);
				keyCbor.Add(key, array);
			} else {
				// Handle integer values
				int valueInt = Integer.parseInt(value);
				keyCbor.Add(key, valueInt);
			}
		}

		// {1: 1, -1: 6, -2:
		// h’4C5E5A898AFC77D9C90773D9B4F5E7B378605753F9BA9E8A62488C64E1A524B0’,
		// -4:
		// h’C9AFCF6610BAB69A7E72B78B6D364BE86F12CF293523DA51433B09A799FF0F62’}</li>

		System.out.println("WWWW " + keyCbor.ToJSONString());
		System.out.println("WWWW2 " + keyCbor);
		System.out.println(
				"{1: 1, -1: 6, -2: h’4C5E5A898AFC77D9C90773D9B4F5E7B378605753F9BA9E8A62488C64E1A524B0’, -4: h’C9AFCF6610BAB69A7E72B78B6D364BE86F12CF293523DA51433B09A799FF0F62’}</li>");

		// Set the algorithm if missing (which it sometimes is) TODO: Needed?
		boolean addAlgorithm = true;
		if (addAlgorithm && keyCbor.get(KeyKeys.Algorithm.AsCBOR()) == null) {
			
			System.out.println("AlgorithmID in diagnostic string is null, setting it.");

			CBORObject ec2Curve = keyCbor.get(KeyKeys.EC2_Curve.AsCBOR());
			CBORObject okpCurve = keyCbor.get(KeyKeys.OKP_Curve.AsCBOR());

			// Checks and sets the algorithm by looking at the curve used
			if (ec2Curve == KeyKeys.EC2_P256) {
				// ECDSA 256
				keyCbor.set(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_256.AsCBOR());
			} else if (ec2Curve == KeyKeys.EC2_P256) {
				// ECDSA 384
				keyCbor.set(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_384.AsCBOR());
			} else if (ec2Curve == KeyKeys.EC2_P256) {
				// ECDSA 512
				keyCbor.set(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_512.AsCBOR());
			} else if (okpCurve == KeyKeys.OKP_Ed25519) {
				// EDDSA
				keyCbor.set(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.EDDSA.AsCBOR());
			}
		}

		// Create a COSE key from CBOR Object
		OneKey key = null;
		try {
			key = new OneKey(keyCbor);
		} catch (CoseException e) {
			System.err.println("Error: Failed to decode COSE OneKey from diagnostic notation.");
			e.printStackTrace();
		}

		System.out.println("WWWW3 " + key.AsCBOR().ToJSONString());
		System.out.println("WWWW4 " + key.AsCBOR());
		System.out.println("KeyType " + key.get(KeyKeys.KeyType));
		System.out.println("Algorithm " + key.get(KeyKeys.Algorithm));
		
		return key;
	}

	/**
	 * Parse a string representing a COSE OneKey in diagnostic notation. This
	 * method first converts it to a JSON string and then decodes it to a CBOR
	 * Object using built in methods. A COSE OneKey is then created from that
	 * CBOR Object.
	 * 
	 * @param keyString string representing a OneKey in diagnostic notation
	 * @return a OneKey object built from the string
	 */
	@Deprecated
	private OneKey parseDiagnosticOneKey(String keyString) {
		// OneKey test = OneKey.generateKey(AlgorithmID.EDDSA);
		// System.out.println(test.AsCBOR().ToJSONString());
		// CBORObject test2;
		// CBORObject test3 =
		// CBORObject.FromJSONString(test.AsCBOR().ToJSONString());
		// System.out.println(test3.ToJSONString());

		// Convert to lower case
		keyString = keyString.toLowerCase();

		// Remove { and } characters
		keyString = keyString.replace("{", "");
		keyString = keyString.replace("}", "");
		// Remove spaces
		keyString = keyString.replace(" ", "");

		// Split the string into sections at the , and : character
		String[] segments = keyString.split("[,:]");

		// Change every even element to have quotes around it
		for (int i = 0; i < segments.length; i += 2) {
			segments[i] = "\"" + segments[i] + "\"";
		}

		// Convert byte arrays to Base64
		for (int i = 0; i < segments.length; i++) {

			if (segments[i].length() >= 2 && segments[i].substring(0, 2).equals("h’")) {
				// Remove h’ and ’
				String arrayString = segments[i].replace("h’", "").replace("’", "");

				// Convert to base64
				byte[] array = Utils.hexToBytes(arrayString);
				String arrayBase64 = DatatypeConverter.printBase64Binary(array);

				// Change it to base64url encoding
				arrayBase64 = arrayBase64.replace("+", "-");
				arrayBase64 = arrayBase64.replace("/", "_");

				// Remove padding
				arrayBase64 = arrayBase64.replace("=", "");

				segments[i] = "\"" + arrayBase64 + "\"";
			}
		}

		// Reassemble everything into a string
		StringBuilder jsonString = new StringBuilder();
		jsonString.append("{");
		for (int i = 0; i < segments.length; i++) {
			jsonString.append(segments[i]);

			if (i % 2 == 0) {
				jsonString.append(":");
			} else if (i % 2 != 0 && i != segments.length - 1) {
				jsonString.append(",");
			}
		}
		jsonString.append("}");

		// Parse the JSON string into a CBOR Object
		CBORObject keyCbor = CBORObject.FromJSONString(jsonString.toString());
		System.out.println("TPYE" + keyCbor.getType());

		System.out.println("WWWW " + keyCbor.ToJSONString());
		System.out.println("WWWW2 " + keyCbor);

		// Set the key type if missing (which it sometimes is)
		if (keyCbor.get(KeyKeys.KeyType.AsCBOR()) == null) {
			// Checks and sets the key type for ECDSA
			CBORObject ec2Curve = keyCbor.get(KeyKeys.EC2_Curve.AsCBOR());

			System.out.println("ec2Curve" + ec2Curve);

			if (ec2Curve == KeyKeys.EC2_P256 || ec2Curve == KeyKeys.EC2_P384 || ec2Curve == KeyKeys.EC2_P521) {
				System.out.println("HELLo1");
				keyCbor.set(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
			}

			// Checks and sets the key type for EDDSA
			CBORObject okpCurve = keyCbor.get(KeyKeys.OKP_Curve.AsCBOR());
			if (okpCurve == KeyKeys.OKP_Ed25519) {
				System.out.println("HELLo2");
				keyCbor.set(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
			}
		}



		// Create a COSE key from CBOR Object
		OneKey key = null;
		try {
			key = new OneKey(keyCbor);
		} catch (CoseException e) {
			System.err.println("Error: Failed to decode COSE OneKey from diagnostic notation.");
			e.printStackTrace();
		}

		return key;
	}

}
