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

}
