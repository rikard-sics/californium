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

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.elements.util.StringUtil;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.Arrays;

/**
 * Class for testing encryption/decryption with AES CCM:
 * 
 * https://www.iana.org/assignments/cose/cose.xhtml
 * 
 * AES-CCM-16-64-256: AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
 *
 * AES-CCM-64-64-256: AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
 * 
 * AES-CCM-16-128-256: AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
 * 
 * AES-CCM-64-128-256: AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
 * 
 * Test vectors from for AES-CCM-64-128-256 & AES-CCM-16-128-256 from :
 * https://raw.githubusercontent.com/google/wycheproof/master/testvectors/aes_ccm_test.json
 */
public class AesCcmTester {

	@BeforeClass
	public static void initCrypto() {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test AES-CCM-16-64-256
	 * 
	 * @throws Exception on failure
	 */
	@Test
	public void testAesCcm16_64_256() throws Exception {

		byte[] key = StringUtil.hex2ByteArray("c8ac9ff421cc062fc34209f7715f2d526ea6938b2e56d5dc55665956840ac690");
		byte[] nonce = StringUtil.hex2ByteArray("215d562fc7e34209f514bad37d");
		byte[] aad = StringUtil.hex2ByteArray("c563c66750a3809b");
		byte[] plaintext = StringUtil.hex2ByteArray("b2caa8c5d8daa91ec79d286bcc115f10");
		byte[] expectedCiphertext = StringUtil.hex2ByteArray("7816078D59531D50A65FEAE0D1A89264");
		byte[] expectedTag = StringUtil.hex2ByteArray("7F06D8CD05A695DA");

		Assert.assertEquals("Incorrect key length", 256, key.length * 8);
		Assert.assertEquals("Incorrect Tag length", 64, expectedTag.length * 8);
		Assert.assertEquals("Incorrect IV/nonce length", 13, nonce.length);

		testAesCcm(key, nonce, aad, plaintext, expectedCiphertext, expectedTag);
	}

	/**
	 * Test AES-CCM-64-64-256
	 * 
	 * @throws Exception on failure
	 */
	@Test
	public void testAesCcm64_64_256() throws Exception {

		byte[] key = StringUtil.hex2ByteArray("c8ac9ff421cc062fc34209f7715f2d526ea6938b2e56d5dc55665956840ac690");
		byte[] nonce = StringUtil.hex2ByteArray("215d5514bad37d");
		byte[] aad = StringUtil.hex2ByteArray("c563c66750a3809b");
		byte[] plaintext = StringUtil.hex2ByteArray("b2caa8c5d8daa91ec79d286bcc115f10");
		byte[] expectedCiphertext = StringUtil.hex2ByteArray("E1338DA2C36078F039E4B4EC6708AB19");
		byte[] expectedTag = StringUtil.hex2ByteArray("AD80DC04C82949AD");

		Assert.assertEquals("Incorrect key length", 256, key.length * 8);
		Assert.assertEquals("Incorrect Tag length", 64, expectedTag.length * 8);
		Assert.assertEquals("Incorrect IV/nonce length", 7, nonce.length);

		testAesCcm(key, nonce, aad, plaintext, expectedCiphertext, expectedTag);
	}

	/**
	 * Test AES-CCM-16-128-256
	 * 
	 * tcId: 301
	 * 
	 * @throws Exception on failure
	 */
	@Test
	public void testAesCcm16_128_256() throws Exception {

		byte[] key = StringUtil.hex2ByteArray("a6938b2e56d5dc55665956840ac690c8ac9ff421cc062fc34209f7715f2d526e");
		byte[] nonce = StringUtil.hex2ByteArray("ad37de72d3521546d5ff51462b");
		byte[] aad = StringUtil.hex2ByteArray("0a3809bc563c6675");
		byte[] plaintext = StringUtil.hex2ByteArray("9d286bcc115f10b2caa8c5d8daa91ec7");
		byte[] expectedCiphertext = StringUtil.hex2ByteArray("4ed4dbc8aa8cf6375021d15e43c1f6c3");
		byte[] expectedTag = StringUtil.hex2ByteArray("bfba9c41ec63aa296b1446b888b6251c");

		Assert.assertEquals("Incorrect key length", 256, key.length * 8);
		Assert.assertEquals("Incorrect Tag length", 128, expectedTag.length * 8);
		Assert.assertEquals("Incorrect IV/nonce length", 13, nonce.length);

		testAesCcm(key, nonce, aad, plaintext, expectedCiphertext, expectedTag);
	}

	/**
	 * Test AES-CCM-64-128-256
	 * 
	 * tcId: 271
	 * 
	 * @throws Exception on failure
	 */
	@Test
	public void testAesCcm64_128_256() throws Exception {

		byte[] key = StringUtil.hex2ByteArray("e0d82f6088ec675d92ec6b44a67dc6eb6600f1b742bdd5a851b036af02eef825");
		byte[] nonce = StringUtil.hex2ByteArray("06edf6ab0c7a92");
		byte[] aad = StringUtil.hex2ByteArray("e98fdd292291dd01");
		byte[] plaintext = StringUtil.hex2ByteArray("5bb3639265c8563e6fb738bed8c8532c");
		byte[] expectedCiphertext = StringUtil.hex2ByteArray("cb2513417f9cb546d73830b919b2cb33");
		byte[] expectedTag = StringUtil.hex2ByteArray("d3c06c1614f7ca3b0952d67a5bd0d017");

		Assert.assertEquals("Incorrect key length", 256, key.length * 8);
		Assert.assertEquals("Incorrect Tag length", 128, expectedTag.length * 8);
		Assert.assertEquals("Incorrect IV/nonce length", 7, nonce.length);

		testAesCcm(key, nonce, aad, plaintext, expectedCiphertext, expectedTag);
	}

	private static void testAesCcm(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext, byte[] expectedCiphertext,
			byte[] expectedTag) throws Exception {
		byte[] ciphertextAndTag = encryptAesCcm(plaintext, key, aad, expectedTag.length * 8, nonce);

		// Split into ciphertext and tag
		byte[] ciphertext = Arrays.copyOfRange(ciphertextAndTag, 0, ciphertextAndTag.length - expectedTag.length);
		byte[] tag = Arrays.copyOfRange(ciphertextAndTag, ciphertextAndTag.length - expectedTag.length,
				ciphertextAndTag.length);

		// Check against expected values
		Assert.assertArrayEquals("Incorrect ciphertext", ciphertext, expectedCiphertext);
		Assert.assertArrayEquals("Incorrect tag", tag, expectedTag);

		// Decrypt and check
		byte[] decryptedPlaintext = decryptAesCcm(ciphertextAndTag, key, aad, tag.length * 8, nonce);
		Assert.assertArrayEquals("Incorrect decrypted plaintext", plaintext, decryptedPlaintext);
	}

	private static final String ALGORITHM = "AES/CCM/NoPadding";

	/**
	 * Encrypts the provided plaintext using AES in CCM mode.
	 *
	 * @param plaintext The data to be encrypted.
	 * @param key The encryption key.
	 * @param aad The additional authenticated data.
	 * @param tagLengthBits The length of the authentication tag.
	 * @param nonce The nonce.
	 * @return The encrypted data.
	 * @throws Exception If any error occurs during encryption.
	 */
	public static byte[] encryptAesCcm(byte[] plaintext, byte[] key, byte[] aad, int tagLengthBits, byte[] nonce)
			throws Exception {
		// Ensure key length is 256 bits.
		if (key.length * 8 != 256) {
			throw new IllegalArgumentException("Invalid key length");
		}

		// Initialize cipher and key specification.
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		GCMParameterSpec spec = new GCMParameterSpec(tagLengthBits, nonce);
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

		// Initialize cipher in encryption mode.
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

		// If Additional Authenticated Data (AAD) is provided, update cipher
		// with it.
		if (aad != null) {
			cipher.updateAAD(aad);
		}

		// Encrypt the plaintext and return the ciphertext.
		return cipher.doFinal(plaintext);
	}

	/**
	 * Decrypts the provided ciphertext using AES in CCM mode.
	 *
	 * @param ciphertext The data to be decrypted, including the authentication
	 *            tag.
	 * @param key The encryption key.
	 * @param aad The additional authenticated data.
	 * @param tagLengthBits The length of the authentication tag.
	 * @param nonce The nonce.
	 * @return The decrypted data.
	 * @throws Exception If any error occurs during decryption, including if the
	 *             authentication tag is invalid.
	 */
	public static byte[] decryptAesCcm(byte[] ciphertext, byte[] key, byte[] aad, int tagLengthBits, byte[] nonce)
			throws Exception {
		// Ensure key length is 256 bits.
		if (key.length * 8 != 256) {
			throw new IllegalArgumentException("Invalid key length");
		}

		// Initialize cipher and key specification.
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		GCMParameterSpec spec = new GCMParameterSpec(tagLengthBits, nonce);
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

		// Initialize cipher in decryption mode.
		cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

		// If Additional Authenticated Data (AAD) is provided, update cipher
		// with it.
		if (aad != null) {
			cipher.updateAAD(aad);
		}

		// Decrypt the ciphertext and return the plaintext.
		return cipher.doFinal(ciphertext);
	}

}
