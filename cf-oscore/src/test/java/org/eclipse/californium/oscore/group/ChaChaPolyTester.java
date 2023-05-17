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
 *    Rikard Höglund (RISE SICS)
 ******************************************************************************/
package org.eclipse.californium.oscore.group;

import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.eclipse.californium.elements.util.StringUtil;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

/**
 * Class for testing encryption/decryption with ChaCha20-Poly1305
 *
 */
public class ChaChaPolyTester {

	/**
	 * Size of the encryption key in bits
	 */
	private static final int KEY_SIZE_BITS = 256;

	/**
	 * Size of the nonce in bytes
	 */
	private static final int NONCE_SIZE_BITS = 96;

	/**
	 * Size of the authentication tag in bits
	 */
	private static final int TAG_SIZE_BITS = 128;

	/**
	 * Encrypts the plaintext using ChaCha20-Poly1305 algorithm with additional
	 * authenticated data (AAD)
	 * 
	 * @param plaintext the plaintext
	 * @param nonce the nonce
	 * @param key the key
	 * @param aad the aad
	 * @return the encrypted bytes
	 *
	 */
	public static byte[] encryptWithChaChaPoly(byte[] plaintext, byte[] nonce, byte[] key, byte[] aad) {
		byte[] ciphertext = null;

		if (8 * nonce.length != NONCE_SIZE_BITS) {
			throw new IllegalArgumentException("Incorrect IV/nonce size");
		}

		if (8 * key.length != KEY_SIZE_BITS) {
			throw new IllegalArgumentException("Incorrect key size");
		}

		try {
			byte[] aadCopy = Arrays.copyOf(aad, aad.length);

			// Create a ChaCha20Poly1305 cipher instance
			ChaCha20Poly1305 cipher = new ChaCha20Poly1305();

			// Set the encryption key
			KeyParameter keyParam = new KeyParameter(key);

			// Initialize the cipher for encryption with the provided AAD
			cipher.init(true, new AEADParameters(keyParam, TAG_SIZE_BITS, nonce, aadCopy));

			// Create an output buffer for the ciphertext
			ciphertext = new byte[cipher.getOutputSize(plaintext.length)];

			// Process the plaintext and generate the ciphertext
			int len = cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);

			// Finalize the encryption and generate the authentication tag
			cipher.doFinal(ciphertext, len);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ciphertext;
	}

	/**
	 * Decrypts the ciphertext using ChaCha20-Poly1305 algorithm with additional
	 * authenticated data (AAD)
	 * 
	 * @param ciphertext the ciphertext
	 * @param nonce the nonce
	 * @param key the key
	 * @param aad the aad
	 * @return the decrypted bytes
	 *
	 */
	public static byte[] decryptWithChaChaPoly(byte[] ciphertext, byte[] nonce, byte[] key, byte[] aad) {
		byte[] plaintext = null;

		if (8 * nonce.length != NONCE_SIZE_BITS) {
			throw new IllegalArgumentException("Incorrect IV/nonce size");
		}

		if (8 * key.length != KEY_SIZE_BITS) {
			throw new IllegalArgumentException("Incorrect key size");
		}

		try {
			// Create a copy of the AAD
			byte[] aadCopy = Arrays.copyOf(aad, aad.length);

			// Create a ChaCha20Poly1305 cipher instance
			ChaCha20Poly1305 cipher = new ChaCha20Poly1305();

			// Set the decryption key
			KeyParameter keyParam = new KeyParameter(key);

			// Initialize the cipher for encryption with the provided AAD
			cipher.init(true, new AEADParameters(keyParam, TAG_SIZE_BITS, nonce, aadCopy));

			// Create a buffer for the decrypted plaintext
			plaintext = new byte[cipher.getOutputSize(ciphertext.length)];

			// Process the ciphertext and generate the decrypted plaintext
			int len = cipher.processBytes(ciphertext, 0, ciphertext.length, plaintext, 0);

			// Finalize the decryption and verify the authentication tag
			cipher.doFinal(plaintext, len);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return plaintext;
	}

	/**
	 * Test encryption/decryption with ChaCha20-Poly1305.
	 * 
	 * Uses the test vectors from:
	 * https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
	 * 
	 */
	@Test
	public void testChaCha20Poly1305() {
		// Test vector input values
		byte[] key = StringUtil.hex2ByteArray("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
		byte[] plaintext = StringUtil.hex2ByteArray(
				"4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e");
		byte[] nonce = StringUtil.hex2ByteArray("07000000" + "4041424344454647");
		byte[] aad = StringUtil.hex2ByteArray("50515253c0c1c2c3c4c5c6c7");

		// Invoke the encryption function
		byte[] ciphertext = encryptWithChaChaPoly(plaintext, nonce, key, aad);
		byte[] ciphertextOnly = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - TAG_SIZE_BITS / 8);
		byte[] tag = Arrays.copyOfRange(ciphertext, ciphertext.length - TAG_SIZE_BITS / 8, ciphertext.length);

		// Compare the ciphertext with the expected value
		byte[] expectedCiphertext = StringUtil.hex2ByteArray(
				"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
		byte[] expectedTag = StringUtil.hex2ByteArray("1ae10b594f09e26a7e902ecbd0600691");

		System.out.println("Ciphertext: " + StringUtil.byteArray2Hex(ciphertextOnly));
		System.out.println("Expected Ciphertext: " + StringUtil.byteArray2Hex(expectedCiphertext));

		System.out.println("Tag: " + StringUtil.byteArray2Hex(tag));
		System.out.println("Expected Tag: " + StringUtil.byteArray2Hex(expectedTag));

		System.out.println("Ciphertext matches: " + Arrays.equals(expectedCiphertext, ciphertextOnly));
		Assert.assertArrayEquals(expectedCiphertext, ciphertextOnly);
		System.out.println("Tag matches: " + Arrays.equals(expectedTag, tag));
		Assert.assertArrayEquals(expectedTag, tag);

		// Invoke the decryption function
		byte[] plaintextOut = decryptWithChaChaPoly(ciphertext, nonce, key, aad);
		System.out.println("Decrypted ciphertext: " + StringUtil.byteArray2Hex(plaintextOut));

		// Check that decrypted plaintext is correct
		byte[] plaintextOutOnly = Arrays.copyOfRange(plaintextOut, 0, plaintextOut.length - 2 * (TAG_SIZE_BITS / 8));
		System.out.println("Decrypted Plaintext: " + StringUtil.byteArray2Hex(plaintextOutOnly));
		System.out.println("Expected Plaintext: " + StringUtil.byteArray2Hex(plaintext));
		System.out.println("Plaintext matches: " + Arrays.equals(plaintext, plaintextOutOnly));
		Assert.assertArrayEquals(plaintext, plaintextOutOnly);

	}

}
