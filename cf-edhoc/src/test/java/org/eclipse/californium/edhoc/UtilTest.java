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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

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
}
