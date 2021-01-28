/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
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
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.EncryptCommon;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.junit.Assert;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

public class UtilTest {

	/**
	 * Test computing a hash using SHA256.
	 * 
	 * See test vectors: https://www.di-mgt.com.au/sha_testvectors.html
	 * 
	 * @throws NoSuchAlgorithmException on test failure
	 */
	@Test
	public void testComputerHashSha256() throws NoSuchAlgorithmException {
		byte[] data = new byte[] { 0x61, 0x62, 0x63 };
		byte[] hash = Util.computeHash(data, "SHA-256");
		byte[] expected = Utils.hexToBytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

		Assert.assertArrayEquals(expected, hash);
	}

	/**
	 * Test computing a hash using SHA512.
	 * 
	 * See test vectors: https://www.di-mgt.com.au/sha_testvectors.html
	 * 
	 * @throws NoSuchAlgorithmException on test failure
	 */
	@Test
	public void testComputerHashSha512() throws NoSuchAlgorithmException {
		byte[] data = new byte[] { 0x61, 0x62, 0x63 };
		byte[] hash = Util.computeHash(data, "SHA-512");
		byte[] expected = Utils.hexToBytes(
				"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

		Assert.assertArrayEquals(expected, hash);
	}

	/**
	 * Test building a CBOR sequence and then parsing it with built in CBOR
	 * methods.
	 * 
	 * @throws IOException on test failure
	 * 
	 */
	@Test
	public void testBuildCBORSequence() throws IOException {
		// Build a list of CBOR objects with 4 elements
		List<CBORObject> objectListIn = new ArrayList<CBORObject>();
		objectListIn.add(CBORObject.FromObject(true));
		objectListIn.add(CBORObject.FromObject(100));
		objectListIn.add(CBORObject.FromObject(new byte[] { 0x01 }));
		objectListIn.add(CBORObject.FromObject("hello"));

		// Create the bytes of the sequence
		byte[] sequence = Util.buildCBORSequence(objectListIn);

		// Parse the sequence bytes with CBOR
		InputStream sequenceStream = new ByteArrayInputStream(sequence);
		CBORObject[] objectArrayOut = CBORObject.ReadSequence(sequenceStream);
		List<CBORObject> objectListOut = Arrays.asList(objectArrayOut);
		// objectListOut.set(1, CBORObject.FromObject(200));

		// Compare the result with the original input
		Assert.assertEquals(objectListIn.size(), objectListOut.size());
		for (int i = 0; i < objectListIn.size(); i++) {
			Assert.assertTrue(objectListOut.contains(objectListIn.get(i)));
		}
	}

	/**
	 * Test encoding to bstr_identifier.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#section-4.3
	 */
	@Test
	public void testEncodeToBstrIdentifier() {
		byte[] input1Bytes = new byte[] { (byte) 0x59, (byte) 0xe9 };
		CBORObject input1 = CBORObject.FromObject(input1Bytes);
		CBORObject expected1 = CBORObject.FromObject(input1Bytes);

		CBORObject output1 = Util.encodeToBstrIdentifier(input1);
		Assert.assertEquals(CBORType.ByteString, output1.getType());
		Assert.assertArrayEquals(expected1.GetByteString(), output1.GetByteString());

		// Second test

		byte[] input2Bytes = new byte[] { (byte) 0x2a };
		CBORObject input2 = CBORObject.FromObject(input2Bytes);
		CBORObject expected2 = CBORObject.FromObject(18);

		CBORObject output2 = Util.encodeToBstrIdentifier(input2);
		Assert.assertEquals(CBORType.Integer, output2.getType());
		Assert.assertEquals(expected2.AsInt32(), output2.AsInt32());
	}

	/**
	 * Test decoding from bstr_identifier.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#section-4.3
	 */
	@Test
	public void testDecodeFromBstrIdentifier() {
		byte[] input1Bytes = new byte[] { (byte) 0x59, (byte) 0xe9 };
		CBORObject input1 = CBORObject.FromObject(input1Bytes);
		CBORObject expected1 = CBORObject.FromObject(input1Bytes);

		CBORObject output1 = Util.decodeFromBstrIdentifier(input1);
		Assert.assertEquals(CBORType.ByteString, output1.getType());
		Assert.assertArrayEquals(expected1.GetByteString(), output1.GetByteString());

		// Second test

		CBORObject input2 = CBORObject.FromObject(18);
		byte[] expected2Bytes = new byte[] { (byte) 0x2a };
		CBORObject expected2 = CBORObject.FromObject(expected2Bytes);

		CBORObject output2 = Util.decodeFromBstrIdentifier(input2);
		Assert.assertEquals(CBORType.ByteString, output2.getType());
		Assert.assertArrayEquals(expected2.GetByteString(), output2.GetByteString());
	}

	/**
	 * Test a signature computation and verification with EdDSA Ed25519.
	 * 
	 * @throws CoseException on test failure
	 */
	@Test
	public void testComputeVerifySignatureEd25519() throws CoseException {
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		// Set up needed parameters
		String keyStringEd25519 = "pQMnAQEgBiFYIDzQyFH694a7CcXQasH9RcqnmwQAy2FIX97dGGGy+bpSI1gg5aAfgdGCH2/2KFsQH5lXtDc8JUn1a+OkF0zOG6lIWXQ=";
		OneKey keyPair = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(keyStringEd25519)));

		byte[] payloadToSign = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0,
				(byte) 0x5c };
		byte[] externalData = new byte[] { (byte) 0xef, (byte) 0xde, (byte) 0xac, (byte) 0x75, (byte) 0x0f,
				(byte) 0xc5 };
		byte[] kid = new byte[] { (byte) 0x01 };
		CBORObject idCredX = CBORObject.NewMap();
		idCredX.Add(KeyKeys.KeyId, kid);

		// Sign
		byte[] mySignature = Util.computeSignature(idCredX, externalData, payloadToSign, keyPair);

		byte[] expectedSignature = Utils.hexToBytes(
				"7cee3b39da704ce5fd77052235d9f28b7e4d747abfad9e57293be923249406c0f115c1cf6aab5d893ba9b75c0c3b6274f6d8a9340a306ee2571dfe929c377e09");
		Assert.assertArrayEquals(expectedSignature, mySignature);

		// Try verifying the signature
		boolean verified = Util.verifySignature(mySignature, idCredX, externalData, payloadToSign, keyPair);
		Assert.assertTrue(verified);
	}


	/**
	 * Test a signature computation and verification with ECDSA_256.
	 * 
	 * @throws CoseException on signing or verification failure
	 */
	@Test
	public void testComputeVerifySignatureEcdsa256() throws CoseException {

		// Set up needed parameters
		String keyStringEcdsa256 = "pgMmAQIgASFYIPWSTdB9SCF/+CGXpy7gty8qipdR30t6HgdFGQo8ViiAIlggXvJCtXVXBJwmjMa4YdRbcdgjpXqM57S2CZENPrUGQnMjWCDXCb+hy1ybUu18KTAJMvjsmXch4W3Hd7Rw7mTF3ocbLQ==";
		OneKey keyPair = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(keyStringEcdsa256)));

		byte[] payloadToSign = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0,
				(byte) 0x5c };
		byte[] externalData = new byte[] { (byte) 0xef, (byte) 0xde, (byte) 0xac, (byte) 0x75, (byte) 0x0f,
				(byte) 0xc5 };
		byte[] kid = new byte[] { (byte) 0x01 };
		CBORObject idCredX = CBORObject.NewMap();
		idCredX.Add(KeyKeys.KeyId, kid);

		// Sign
		byte[] mySignature = Util.computeSignature(idCredX, externalData, payloadToSign, keyPair);

		// Can't compare values since the signing is currently not deterministic
		Assert.assertNotNull(mySignature);
		Assert.assertEquals(64, mySignature.length);

		// Try verifying the signature
		boolean verified = Util.verifySignature(mySignature, idCredX, externalData, payloadToSign, keyPair);
		Assert.assertTrue(verified);
	}

	/**
	 * Test encryption and decryption with AES_CCM_16_64_128.
	 * 
	 * @throws CoseException on encryption or decryption failure
	 */
	@Test
	public void testEncryptDecrypt() throws CoseException {
		// Set up needed parameters
		byte[] externalData = new byte[] { (byte) 0xef, (byte) 0xde, (byte) 0xac, (byte) 0x75, (byte) 0x0f,
				(byte) 0xc5 };
		byte[] kid = new byte[] { (byte) 0x01 };
		CBORObject idCredX = CBORObject.NewMap();
		idCredX.Add(KeyKeys.KeyId, kid);
		byte[] payloadToEncrypt = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0,
				(byte) 0x5c };
		byte[] symmetricKey = new byte[] { (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
				(byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x013,
				(byte) 0x14, (byte) 0x15 };
		byte[] iv = { (byte) 0xc5, (byte) 0xb7, (byte) 0x17, (byte) 0x0e, (byte) 0x65, (byte) 0xd5, (byte) 0x4f,
				(byte) 0x1a, (byte) 0xe0, (byte) 0x5d, (byte) 0x10, (byte) 0xaf, (byte) 0x56, };
		AlgorithmID encryptionAlg = AlgorithmID.AES_CCM_16_64_128;

		// Perform the encryption
		byte[] myCiphertext = Util.encrypt(idCredX, externalData, payloadToEncrypt, encryptionAlg, iv, symmetricKey);

		byte[] expectedCiphertext = Utils.hexToBytes("b1e139edeec6d38f707e1b35b72b");
		Assert.assertArrayEquals(expectedCiphertext, myCiphertext);

		// Perform decryption
		byte[] myPlaintext = Util.decrypt(idCredX, externalData, myCiphertext, encryptionAlg, iv, symmetricKey);

		Assert.assertArrayEquals(payloadToEncrypt, myPlaintext);

	}

	/**
	 * Test encryption and decryption with the algorithms AES_CCM_16_64_128,
	 * AES_CCM_16_128_128, AES_CCM_64_64_128, AES_CCM_64_128_128, AES_GCM_128,
	 * AES_GCM_192 & AES_GCM_256.
	 * 
	 * @throws CoseException on encryption or decryption failure
	 */
	@Test
	public void testEncryptDecryptAlgs() throws CoseException {

		AlgorithmID[] algorithms = new AlgorithmID[] { AlgorithmID.AES_CCM_16_64_128, AlgorithmID.AES_CCM_16_128_128,
				AlgorithmID.AES_CCM_64_64_128, AlgorithmID.AES_CCM_64_128_128, AlgorithmID.AES_GCM_128,
				AlgorithmID.AES_GCM_192, AlgorithmID.AES_GCM_256 };

		Random rand = new Random();

		// Set up needed parameters
		byte[] externalData = new byte[] { (byte) 0xef, (byte) 0xde, (byte) 0xac, (byte) 0x75, (byte) 0x0f,
				(byte) 0xc5 };
		byte[] kid = new byte[] { (byte) 0x01 };
		CBORObject idCredX = CBORObject.NewMap();
		idCredX.Add(KeyKeys.KeyId, kid);
		byte[] payloadToEncrypt = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0,
				(byte) 0x5c };

		for (int i = 0; i < algorithms.length; i++) {

			AlgorithmID encryptionAlg = algorithms[i];

			int ivLen = EncryptCommon.ivLength(encryptionAlg);
			byte[] iv = Bytes.createBytes(rand, ivLen);

			int keyLen = encryptionAlg.getKeySize() / 8;
			byte[] symmetricKey = Bytes.createBytes(rand, keyLen);

			// Perform the encryption
			byte[] myCiphertext = Util.encrypt(idCredX, externalData, payloadToEncrypt, encryptionAlg, iv,
					symmetricKey);

			// Perform decryption
			byte[] myPlaintext = Util.decrypt(idCredX, externalData, myCiphertext, encryptionAlg, iv, symmetricKey);

			Assert.assertArrayEquals("Failed test for algorithm " + encryptionAlg, payloadToEncrypt, myPlaintext);
		}

	}

	/**
	 * Test building a CBOR map in deterministic order.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#page-18
	 */
	@Test
	public void testBuildDeterministicCBORMap() {
		// Build a list with labels for the map
		List<CBORObject> labelList = new ArrayList<CBORObject>();
		labelList.add(CBORObject.FromObject(1));
		labelList.add(CBORObject.FromObject(-1));
		labelList.add(CBORObject.FromObject(-2));
		labelList.add(CBORObject.FromObject("subject name"));

		// Build a list with values for the map
		List<CBORObject> valueList = new ArrayList<CBORObject>();
		valueList.add(CBORObject.FromObject(1));
		valueList.add(CBORObject.FromObject(4));
		valueList.add(CBORObject
				.FromObject(Utils.hexToBytes("b1a3e89460e88d3a8d54211dc95f0b903ff205eb71912d6db8f4af980d2db83a")));
		valueList.add(CBORObject.FromObject("42-50-31-FF-EF-37-32-39"));

		// Build equivalent CBOR map normally
		CBORObject comparisonMap = CBORObject.NewMap();
		comparisonMap.Add(CBORObject.FromObject(1), CBORObject.FromObject(1));
		comparisonMap.Add(CBORObject.FromObject(-1), CBORObject.FromObject(4));
		comparisonMap.Add(CBORObject.FromObject(-2), CBORObject
				.FromObject(Utils.hexToBytes("b1a3e89460e88d3a8d54211dc95f0b903ff205eb71912d6db8f4af980d2db83a")));
		comparisonMap.Add(CBORObject.FromObject("subject name"), CBORObject.FromObject("42-50-31-FF-EF-37-32-39"));

		// Generate the bytes of the map
		byte[] mapBytes = Util.buildDeterministicCBORMap(labelList, valueList);
		
		// Try to parse it as a CBOR map
		CBORObject parsedMap = CBORObject.DecodeFromBytes(mapBytes);

		// Compare that it contains what is expected
		Assert.assertEquals(comparisonMap.size(), parsedMap.size());
		ArrayList<CBORObject> keys = new ArrayList<>(comparisonMap.getKeys());

		for(int i = 0 ; i < keys.size() ; i++) {
			CBORObject key = keys.get(i);
			Assert.assertEquals(comparisonMap.get(key), parsedMap.get(key));
		}

		// Finally compare with the expected bytes
		byte[] expectedBytes = Utils.hexToBytes(
				"a401012004215820b1a3e89460e88d3a8d54211dc95f0b903ff205eb71912d6db8f4af980d2db83a6c7375626a656374206e616d657734322d35302d33312d46462d45462d33372d33322d3339");
		Assert.assertArrayEquals(expectedBytes, mapBytes);
	}
}
