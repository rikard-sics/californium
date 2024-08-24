/*******************************************************************************

 * Copyright (c) 2016, Jim Schaad
 * Copyright (c) 2018, Tobias Andersson, RISE SICS
 * Copyright (c) 2024, Rikard Höglund, RISE SICS
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.

 * Neither the name of COSE-JAVA nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
     
 ******************************************************************************/
package org.eclipse.californium.cose;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import java.security.spec.AlgorithmParameterSpec;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;


import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.dtls.cipher.CCMBlockCipher;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalCipher;

/**
 * 
 * This class is copied from the COSE Java repository. Changes made: Directly
 * changed the used cipher to Scandium's CCMBlockCipher code. Added support for
 * AES GCM and ChaCha20-Poly1305.
 *
 */
public abstract class EncryptCommon extends Message {

	private static final int CHACHA_POLY_IV_LENGTH = 96 / 8;
	private static final int CHACHA_IV_LENGTH = CHACHA_POLY_IV_LENGTH;
	private final static int AES_CCM_16_IV_LENGTH = 13;
	private final static int AES_CCM_64_IV_LENGTH = 7;
	private final static int AES_GCM_IV_LENGTH = 12;
	private final static int AES_CBC_IV_LENGTH = 16;
	private final static int AES_CTR_IV_LENGTH = 16;

<<<<<<< HEAD
<<<<<<< HEAD
	private final static int AES_GCM_IV_LENGTH = 12;
	private static final int CHACHA_POLY_IV_LENGTH = 12;

	private static final String AES_SPEC = "AES";
	private static final String AES_GCM_SPEC = "AES/GCM/NoPadding";
	private static final String CHACHA_SPEC = "ChaCha20";
	private static final String CHACHA_POLY_SPEC = "ChaCha20-Poly1305";

	private static final ThreadLocalCipher AES_GCM_CIPHER = new ThreadLocalCipher(AES_GCM_SPEC);
	private static final ThreadLocalCipher CHACHA_POLY_CIPHER = new ThreadLocalCipher(CHACHA_POLY_SPEC);



	private static final String AES_256_SPEC = "AES/CCM/NoPadding";

	private final String AES_SPEC = "AES";
	private final String AES_GCM_SPEC = AES_SPEC + "/GCM/NoPadding";
	private final static int AES_GCM_IV_LENGTH = 12;

	private static final String AES_SPEC = "AES";
	private static final String AES_256_SPEC = "AES/CCM/NoPadding";
	private static final String AES_GCM_SPEC = "AES/GCM/NoPadding";
	private static final String AES_CTR_SPEC = "AES/CTR/NoPadding";
	private static final String AES_CBC_SPEC = "AES/CBC/PKCS5Padding";



	protected String context;
	protected byte[] rgbEncrypt;
	SecureRandom random = new SecureRandom();

	protected byte[] decryptWithKey(byte[] rgbKey) throws CoseException {
		CBORObject algX = findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(algX);

		if (rgbEncrypt == null)
			throw new CoseException("No Encrypted Content Specified");


		validateObjectState(rgbKey);

		switch (alg) {
		case AES_CCM_16_64_128:
		case AES_CCM_16_128_128:
		case AES_CCM_16_64_256:
		case AES_CCM_16_128_256:
		case AES_CCM_64_64_128:
		case AES_CCM_64_128_128:
		case AES_CCM_64_64_256:
		case AES_CCM_64_128_256:
			AES_CCM_Decrypt(alg, rgbKey);
			break;
		case AES_GCM_128:
		case AES_GCM_192:
		case AES_GCM_256:
			AES_GCM_Decrypt(alg, rgbKey);
			break;
		case CHACHA20_POLY1305:
			ChaCha20_Poly1305_Decrypt(alg, rgbKey);
			break;
		default:
			break;
		}


		if (isSupportedAesCcm(alg)) {

		if (isSupportedAesCcm128(alg)) {

			AES_CCM_Decrypt(alg, rgbKey);
		} else if (isSupportedAesCcm256(alg)) {
			AES_CCM256_Decrypt(alg, rgbKey);
		} else if (isSupportedAesGcm(alg)) {
			AES_GCM_Decrypt(alg, rgbKey);
		} else if (isSupportedChaChaPoly(alg)) {
			ChaCha20_Poly1305_Decrypt(alg, rgbKey);
		} else if (isSupportedChaCha(alg)) {
			ChaCha20_Decrypt(alg, rgbKey);
		} else if (isSupportedAesCbc(alg)) {
			AES_CBC_Decrypt(alg, rgbKey);
		} else if (isSupportedAesCtr(alg)) {
			AES_CTR_Decrypt(alg, rgbKey);
		} else {
			throw new CoseException("Unsupported Algorithm Specified");
		}


		return rgbContent;
	}

	void encryptWithKey(byte[] rgbKey) throws CoseException, IllegalStateException {
		CBORObject algX = findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(algX);

		if (rgbContent == null)
			throw new CoseException("No Content Specified");



		validateObjectState(rgbKey);

		switch (alg) {
		case AES_CCM_16_64_128:
		case AES_CCM_16_128_128:
		case AES_CCM_16_64_256:
		case AES_CCM_16_128_256:
		case AES_CCM_64_64_128:
		case AES_CCM_64_128_128:
		case AES_CCM_64_64_256:
		case AES_CCM_64_128_256:
			AES_CCM_Encrypt(alg, rgbKey);
			break;
		case AES_GCM_128:
		case AES_GCM_192:
		case AES_GCM_256:
			AES_GCM_Encrypt(alg, rgbKey);
			break;
		case CHACHA20_POLY1305:
			ChaCha20_Poly1305_Encrypt(alg, rgbKey);
			break;
		default:
			break;
		}
		

		if (isSupportedAesCcm(alg)) {

		if (isSupportedAesCcm128(alg)) {

			AES_CCM_Encrypt(alg, rgbKey);
		} else if (isSupportedAesCcm256(alg)) {
			AES_CCM256_Encrypt(alg, rgbKey);
		} else if (isSupportedAesGcm(alg)) {
			AES_GCM_Encrypt(alg, rgbKey);
		} else if (isSupportedChaChaPoly(alg)) {
			ChaCha20_Poly1305_Encrypt(alg, rgbKey);
		} else if (isSupportedChaCha(alg)) {
			ChaCha20_Encrypt(alg, rgbKey);
		} else if (isSupportedAesCbc(alg)) {
			AES_CBC_Encrypt(alg, rgbKey);
		} else if (isSupportedAesCtr(alg)) {
			AES_CTR_Encrypt(alg, rgbKey);
		} else {
			throw new CoseException("Unsupported Algorithm Specified");
		}


		ProcessCounterSignatures();
	}

	// Method taken from EncryptCommon in COSE. This will provide the full AAD /
	// Encrypt0-structure.
	private byte[] getAADBytes() {
		CBORObject obj = CBORObject.NewArray();

		obj.Add(context);
		if (objProtected.size() == 0)
			rgbProtected = new byte[0];
		else
			rgbProtected = objProtected.EncodeToBytes();

		obj.Add(rgbProtected);
		obj.Add(CBORObject.FromObject(externalData));

		return obj.EncodeToBytes();
	}

	private void AES_CCM_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {

		CBORObject iv = findAttribute(HeaderKeys.IV);

		// validate key
		if (rgbKey.length != alg.getKeySize() / Byte.SIZE) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate IV
		final int ivLen = ivLengthCcm128(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv == null) {
			throw new CoseException("Missing IV during decryption");
		}
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect");
		}

		// Modified to use the full AAD here rather than just the external AAD
		// Tag length (last parameter) was also included

		byte[] aad = getAADBytes();

		try {
			rgbContent = CCMBlockCipher.decrypt(new SecretKeySpec(rgbKey, AES_SPEC), iv.GetByteString(), aad,
					getEncryptedContent(), alg.getTagSize() / Byte.SIZE);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (InvalidKeyException ex) {
			if (ex.getMessage().equals("Illegal key size")) {
				throw new CoseException("Unsupported key size", ex);
			}
			throw new CoseException("Decryption failure", ex);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new CoseException("Decryption failure", ex);
		}
	}

	private void AES_CCM_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {
		CBORObject iv = findAttribute(HeaderKeys.IV);
		byte[] aad = getAADBytes();

		try {
			rgbEncrypt = CCMBlockCipher.encrypt(new SecretKeySpec(rgbKey, AES_SPEC), iv.GetByteString(), aad, GetContent(),
					alg.getTagSize() / Byte.SIZE);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	private void AES_GCM_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		CBORObject iv = findAttribute(HeaderKeys.IV);
<<<<<<< HEAD

		byte[] aad = getAADBytes();

		try {
			// get and prepare cipher
			Cipher cipher = AES_GCM_CIPHER.currentWithCause();
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rgbKey, AES_SPEC),
					new GCMParameterSpec(alg.getTagSize(), iv.GetByteString()));
			cipher.updateAAD(aad);

			// create plaintext output
			rgbContent = cipher.doFinal(rgbEncrypt);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Decryption failure", ex);
		}
	}

	private void AES_GCM_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {
		CBORObject iv = findAttribute(HeaderKeys.IV);

		int ivLen = ivLengthCcm(alg);

		int ivLen = ivLengthCcm128(alg);

		if (iv == null) {
			byte[] tmp = new byte[ivLen];
			random.nextBytes(tmp);
			iv = CBORObject.FromObject(tmp);
			addAttribute(HeaderKeys.IV, iv, Attribute.UNPROTECTED);
		} else {
			if (iv.getType() != CBORType.ByteString) {
				throw new CoseException("IV is incorrectly formed.");
			}
			if (iv.GetByteString().length > ivLen) {
				throw new CoseException("IV is too long.");
			}
		}

		// Modified to use the full AAD here rather than just the external AAD
		// Tag length (last parameter) was also included

		byte[] aad = getAADBytes();

		try {
<<<<<<< HEAD
			// get and prepare cipher
			Cipher cipher = AES_GCM_CIPHER.currentWithCause();
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rgbKey, AES_SPEC),
					new GCMParameterSpec(alg.getTagSize(), iv.GetByteString()));
			cipher.updateAAD(aad);

			// create ciphertext output
			rgbEncrypt = cipher.doFinal(rgbContent);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	private void ChaCha20_Poly1305_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		byte[] aad = getAADBytes();
		CBORObject iv = findAttribute(HeaderKeys.IV);

		try {
			// get a ChaCha20Poly1305 cipher instance
			Cipher cipher = CHACHA_POLY_CIPHER.currentWithCause();

			// create ivParameterSpec
			AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(iv.GetByteString());

			// set the decryption key
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, CHACHA_SPEC);

			// initialize the cipher for decryption
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);

			// add AAD
			cipher.updateAAD(aad);

			// process the ciphertext and generate the plaintext
			rgbContent = cipher.doFinal(rgbEncrypt);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Decryption failure", ex);
		}
	}

	private void ChaCha20_Poly1305_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		byte[] aad = getAADBytes();
		CBORObject iv = findAttribute(HeaderKeys.IV);

		try {
			// get a ChaCha20Poly1305 cipher instance
			Cipher cipher = CHACHA_POLY_CIPHER.currentWithCause();
			
			// create ivParameterSpec
			AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(iv.GetByteString());

			// set the encryption key
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, CHACHA_SPEC);

			// initialize the cipher for encryption
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);

			// add AAD
			cipher.updateAAD(aad);

			// process the plaintext and generate the ciphertext
			rgbEncrypt = cipher.doFinal(rgbContent);


			rgbEncrypt = CCMBlockCipher.encrypt(new SecretKeySpec(rgbKey, AES_SPEC), iv.GetByteString(), aad,
					GetContent(), alg.getTagSize() / Byte.SIZE);

		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	private void AES_GCM_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		CBORObject iv = findAttribute(HeaderKeys.IV);

		// validate key
		if (rgbKey.length != alg.getKeySize() / 8) {
			throw new CoseException("Key Size is incorrect");
		}

		// get and validate iv
		final int ivLen = ivLengthGcm(alg);
		if (iv == null) {
			throw new CoseException("Missing IV during decryption");
		}
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect");
		}

		try {
			// create and prepare cipher
			Cipher cipher;
			cipher = Cipher.getInstance(AES_GCM_SPEC);
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rgbKey, AES_SPEC),
					new GCMParameterSpec(alg.getTagSize(), iv.GetByteString()));
			cipher.updateAAD(getAADBytes());

			// setup plaintext output
			rgbContent = new byte[cipher.getOutputSize(rgbEncrypt.length)];

			// decryptit!
			ByteBuffer input = ByteBuffer.wrap(rgbEncrypt);
			ByteBuffer output = ByteBuffer.wrap(rgbContent);
			cipher.doFinal(input, output);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (InvalidKeyException ex) {
			if (ex.getMessage() == "Illegal key size") {
				throw new CoseException("Unsupported key size", ex);
			}
			throw new CoseException("Decryption failure", ex);
		} catch (Exception ex) {
			throw new CoseException("Decryption failure", ex);
		}
	}

	private void AES_GCM_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {
		// validate key
		if (rgbKey.length != alg.getKeySize() / 8) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		final int ivLen = ivLengthGcm(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv == null) {
			// generate IV
			byte[] tmp = new byte[ivLen];
			random.nextBytes(tmp);
			iv = CBORObject.FromObject(tmp);
			addAttribute(HeaderKeys.IV, iv, PROTECTED);
		} else {
			if (iv.getType() != CBORType.ByteString) {
				throw new CoseException("IV is incorrectly formed");
			}
			if (iv.GetByteString().length != ivLen) {
				throw new CoseException("IV size is incorrect");
			}
		}

		try {
			Cipher cipher = Cipher.getInstance(AES_GCM_SPEC);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rgbKey, AES_SPEC),
					new GCMParameterSpec(alg.getTagSize(), iv.GetByteString()));
			cipher.updateAAD(getAADBytes());

			rgbEncrypt = new byte[cipher.getOutputSize(rgbContent.length)];
			ByteBuffer input = ByteBuffer.wrap(rgbContent);
			ByteBuffer output = ByteBuffer.wrap(rgbEncrypt);
			cipher.doFinal(input, output);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	/**
	 * Decrypts the ciphertext using ChaCha20-Poly1305 algorithm with additional
	 * authenticated data (AAD)
	 * 
	 * @param alg the algorithm to use
	 * @param rgbKey the key
	 * @throws CoseException on encryption failure
	 *
	 */
	private void ChaCha20_Poly1305_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		byte[] aad = getAADBytes();
		byte[] ciphertext = rgbEncrypt;

		// validate key
		if (rgbKey.length != alg.getKeySize() / 8) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		final int ivLen = ivLengthChaChaPoly(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV length is incorrect.");
		}
		byte[] nonce = iv.GetByteString();

		try {
			// Create a copy of the AAD
			byte[] aadCopy = Arrays.copyOf(aad, aad.length);

			// Create a ChaCha20Poly1305 cipher instance
			Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");

			// Create ivParameterSpec with nonce
			AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

			// Set the decryption key
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, "ChaCha20");

			// Initialize the cipher for decryption
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);

			// Add AAD (if any)
			if (aadCopy != null) {
				cipher.updateAAD(aadCopy);
			}

			// Process the ciphertext and generate the plaintext
			rgbContent = cipher.doFinal(ciphertext);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}

	}

	/**
	 * Encrypts the plaintext using ChaCha20-Poly1305 algorithm with additional
	 * authenticated data (AAD)
	 * 
	 * @param alg the algorithm to use
	 * @param rgbKey the key
	 * @throws CoseException on encryption failure
	 *
	 */
	private void ChaCha20_Poly1305_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		byte[] aad = getAADBytes();
		byte[] plaintext = rgbContent;

		// validate key
		if (rgbKey.length != alg.getKeySize() / 8) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		final int ivLen = ivLengthChaChaPoly(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV length is incorrect.");
		}
		byte[] nonce = iv.GetByteString();

		try {
			byte[] aadCopy = Arrays.copyOf(aad, aad.length);

			// Create a ChaCha20Poly1305 cipher instance
			Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");

			// Create ivParameterSpec with nonce
			AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

			// Set the encryption key
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, "ChaCha20");

			// Initialize the cipher for encryption
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);

			// Add AAD (if any)
			if (aadCopy != null) {
				cipher.updateAAD(aadCopy);
			}

			// Process the plaintext and generate the ciphertext
			rgbEncrypt = cipher.doFinal(plaintext);

		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	/**
	 * Decrypts the ciphertext using ChaCha20 algorithm (without Poly1305) with no additional authenticated data (AAD)
	 * 
	 * @param alg the algorithm to use
	 * @param rgbKey the key
	 * @throws CoseException on encryption failure
	 *
	 */
	private void ChaCha20_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		byte[] ciphertext = rgbEncrypt;

		// validate key
		if (rgbKey.length != alg.getKeySize() / 8) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		final int ivLen = ivLengthChaCha(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV length is incorrect.");
		}
		byte[] nonce = iv.GetByteString();

		try {
			// Create a ChaCha20 cipher instance
			Cipher cipher = Cipher.getInstance("ChaCha20");

			// Create ivParameterSpec with nonce
			AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

			// Set the decryption key
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, "ChaCha20");

			// Initialize the cipher for decryption
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);

			// Process the ciphertext and generate the plaintext
			rgbContent = cipher.doFinal(ciphertext);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	/**
	 * Encrypts the plaintext using ChaCha20 algorithm (without Poly1305) with
	 * no additional authenticated data (AAD)
	 * 
	 * @param alg the algorithm to use
	 * @param rgbKey the key
	 * @throws CoseException on encryption failure
	 *
	 */
	private void ChaCha20_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		byte[] plaintext = rgbContent;

		// validate key
		if (rgbKey.length != alg.getKeySize() / 8) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		final int ivLen = ivLengthChaCha(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV length is incorrect.");
		}
		byte[] nonce = iv.GetByteString();

		try {
			// Create a ChaCha20 cipher instance
			Cipher cipher = Cipher.getInstance("ChaCha20");

			// Create ivParameterSpec with nonce
			AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(nonce);

			// Set the encryption key
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, "ChaCha20");

			// Initialize the cipher for encryption
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);

			// Process the plaintext and generate the ciphertext
			rgbEncrypt = cipher.doFinal(plaintext);

		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	/**
	 * Decrypts the provided ciphertext using AES in CCM mode with 256 bit key.
	 *
	 * @param alg the algorithm to use
	 * @param rgbKey the key
	 * @throws CoseException on encryption failure
	 */
	public void AES_CCM256_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		// validate key
		if (rgbKey.length != alg.getKeySize() / 8) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		final int ivLen = ivLengthCcm256(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV length is incorrect.");
		}
		byte[] nonce = iv.GetByteString();

		try {
			// Initialize cipher and key specification.
			Cipher cipher = Cipher.getInstance(AES_256_SPEC);
			GCMParameterSpec spec = new GCMParameterSpec(alg.getTagSize(), nonce);
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, AES_SPEC);

			// Initialize cipher in decryption mode.
			cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

			// If Additional Authenticated Data (AAD) is provided, update cipher
			// with it.
			byte[] aad = getAADBytes();
			if (aad != null) {
				cipher.updateAAD(aad);
			}

			// Decrypt the ciphertext and return the plaintext.
			rgbContent = cipher.doFinal(rgbEncrypt);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (InvalidKeyException ex) {
			if (ex.getMessage().equals("Illegal key size")) {
				throw new CoseException("Unsupported key size", ex);
			}
			throw new CoseException("Decryption failure", ex);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new CoseException("Decryption failure", ex);
		}
	}

	/**
	 * Encrypts the provided plaintext using AES in CCM mode with 256 bit key.
	 *
	 * @param alg the algorithm to use
	 * @param rgbKey the key
	 * @throws CoseException on encryption failure
	 */
	public void AES_CCM256_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException {
		// validate key
		if (rgbKey.length != alg.getKeySize() / 8) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		final int ivLen = ivLengthCcm256(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV length is incorrect.");
		}
		byte[] nonce = iv.GetByteString();

		try {
			// Initialize cipher and key specification.
			Cipher cipher = Cipher.getInstance(AES_256_SPEC);
			GCMParameterSpec spec = new GCMParameterSpec(alg.getTagSize(), nonce);
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, AES_SPEC);

			// Initialize cipher in encryption mode.
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

			// If Additional Authenticated Data (AAD) is provided, update cipher
			// with it.
			byte[] aad = getAADBytes();
			if (aad != null) {
				cipher.updateAAD(aad);
			}

			// Encrypt the plaintext and return the ciphertext.
			rgbEncrypt = cipher.doFinal(rgbContent);
		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (InvalidKeyException ex) {
			if (ex.getMessage().equals("Illegal key size")) {
				throw new CoseException("Unsupported key size", ex);
			}
			throw new CoseException("Decryption failure", ex);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new CoseException("Decryption failure", ex);
		}
	}

	private void AES_CTR_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {
		// validate key
		if (rgbKey.length != alg.getKeySize() / Byte.SIZE) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate IV
		final int ivLen = ivLengthCtr(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv == null) {
			throw new CoseException("Missing IV during decryption");
		}
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect");
		}

		try {
			Cipher cipher = Cipher.getInstance(AES_CTR_SPEC);
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, AES_SPEC);
			IvParameterSpec ivSpec = new IvParameterSpec(iv.GetByteString());
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
			rgbContent = cipher.doFinal(getEncryptedContent());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (InvalidKeyException ex) {
			if (ex.getMessage().equals("Illegal key size")) {
				throw new CoseException("Unsupported key size", ex);
			}
			throw new CoseException("Decryption failure", ex);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new CoseException("Decryption failure", ex);
		}
	}

	private void AES_CTR_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {

		// validate key
		if (rgbKey.length != alg.getKeySize() / Byte.SIZE) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		CBORObject iv = findAttribute(HeaderKeys.IV);
		int ivLen = ivLengthCtr(alg);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect.");
		}

		try {
			Cipher cipher = Cipher.getInstance(AES_CTR_SPEC);
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, AES_SPEC);
			IvParameterSpec ivSpec = new IvParameterSpec(iv.GetByteString());
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			rgbEncrypt = cipher.doFinal(GetContent());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	private void AES_CBC_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {
		// validate key
		if (rgbKey.length != alg.getKeySize() / Byte.SIZE) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate IV
		final int ivLen = ivLengthCbc(alg);
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv == null) {
			throw new CoseException("Missing IV during decryption");
		}
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect");
		}

		try {
			Cipher cipher = Cipher.getInstance(AES_CBC_SPEC);
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, AES_SPEC);
			IvParameterSpec ivSpec = new IvParameterSpec(iv.GetByteString());
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
			rgbContent = cipher.doFinal(getEncryptedContent());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (InvalidKeyException ex) {
			if (ex.getMessage().equals("Illegal key size")) {
				throw new CoseException("Unsupported key size", ex);
			}
			throw new CoseException("Decryption failure", ex);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new CoseException("Decryption failure", ex);
		}
	}

	private void AES_CBC_Encrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {

		// validate key
		if (rgbKey.length != alg.getKeySize() / Byte.SIZE) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate iv
		CBORObject iv = findAttribute(HeaderKeys.IV);
		int ivLen = ivLengthCbc(alg);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect.");
		}

		try {
			Cipher cipher = Cipher.getInstance(AES_CBC_SPEC);
			SecretKeySpec keySpec = new SecretKeySpec(rgbKey, AES_SPEC);
			IvParameterSpec ivSpec = new IvParameterSpec(iv.GetByteString());
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			rgbEncrypt = cipher.doFinal(GetContent());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	/**
	 * Used to obtain the encrypted content for the cases where detached content
	 * is requested.
	 * 
	 * @return bytes of the encrypted content
	 * @throws CoseException if content has not been encrypted
	 */
	public byte[] getEncryptedContent() throws CoseException {
		if (rgbEncrypt == null)
			throw new CoseException("No Encrypted Content Specified");

		return rgbEncrypt;
	}

	/**
	 * Set the encrypted content for detached content cases.
	 * 
	 * @param rgb encrypted content to be used
	 */
	public void setEncryptedContent(byte[] rgb) {
		rgbEncrypt = rgb;
	}

	@Override
	protected void ProcessCounterSignatures() throws CoseException {
		if (!counterSignList.isEmpty()) {
			if (counterSignList.size() == 1) {
				counterSignList.get(0).sign(rgbProtected, rgbEncrypt);
				addAttribute(HeaderKeys.CounterSignature, counterSignList.get(0).EncodeToCBORObject(),
						Attribute.UNPROTECTED);
			} else {
				CBORObject list = CBORObject.NewArray();
				for (CounterSign sig : counterSignList) {
					sig.sign(rgbProtected, rgbEncrypt);
					list.Add(sig.EncodeToCBORObject());
				}
				addAttribute(HeaderKeys.CounterSignature, list, Attribute.UNPROTECTED);
			}
		}

		if (counterSign1 != null) {
			counterSign1.sign(rgbProtected, rgbEncrypt);
			addAttribute(HeaderKeys.CounterSignature0, counterSign1.EncodeToCBORObject(), Attribute.UNPROTECTED);
		}
	}

	@Override
	public boolean validate(CounterSign1 countersignature) throws CoseException {

		// Fix issue with rgbProtected being NULL instead of empty CBOR bstr
		// when doing verification before decryption.
		if (objProtected.size() == 0)
			rgbProtected = new byte[0];
		else
			rgbProtected = objProtected.EncodeToBytes();

		return countersignature.validate(rgbProtected, rgbEncrypt);
	}

	@Override
	public boolean validate(CounterSign countersignature) throws CoseException {
		return countersignature.validate(rgbProtected, rgbEncrypt);
	}

	/**
<<<<<<< HEAD

	 * Validate the state of the object before performing encryption or
	 * decryption
	 * 
	 * @param rgbKey the intended key for encryption/decryption
	 * @throws CoseException if the object state is invalid
	 */
	private void validateObjectState(byte[] rgbKey) throws CoseException {
		AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
		int ivLen = getIvLength(alg);

		// validate key length
		if (rgbKey.length != alg.getKeySize() / Byte.SIZE) {
			throw new CoseException("Key Size is incorrect");
		}

		// check if selected algorithm is supported
		if (ivLen == -1)
			throw new CoseException("Unsupported Algorithm Specified");

		// obtain and validate IV
		CBORObject iv = findAttribute(HeaderKeys.IV);
		if (iv == null) {
			throw new CoseException("Missing IV during decryption");
		}
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect");
		}
	}

	/**
	 * Get IV length in bytes.

	 * Get IV length for AES CCM in bytes.


	 * Get IV length for AES CCM 128 bit key in bytes.

	 * 
	 * @param alg algorithm ID:
	 * @return iv length, or -1 if the algorithm is unsupported
	 */


	public static int getIvLength(AlgorithmID alg) {

	private static int ivLengthCcm(AlgorithmID alg) {


	private static int ivLengthCcm128(AlgorithmID alg) {

		switch (alg) {
		case AES_CCM_16_64_128:
		case AES_CCM_16_128_128:
		case AES_CCM_16_64_256:
		case AES_CCM_16_128_256:
			return AES_CCM_16_IV_LENGTH;
		case AES_CCM_64_64_128:
		case AES_CCM_64_128_128:
		case AES_CCM_64_64_256:
		case AES_CCM_64_128_256:
			return AES_CCM_64_IV_LENGTH;
		case AES_GCM_128:
		case AES_GCM_192:
		case AES_GCM_256:
			return AES_GCM_IV_LENGTH;
		case CHACHA20_POLY1305:
			return CHACHA_POLY_IV_LENGTH;
		default:
			return -1;
		}
	}


	/**
	 * Get IV length for AES CCM 256 bit key in bytes.
	 * 
	 * @param alg algorithm ID:
	 * @return iv length
	 */
	private static int ivLengthCcm256(AlgorithmID alg) {
		switch (alg) {
		case AES_CCM_16_64_256:
		case AES_CCM_16_128_256:
			return AES_CCM_16_IV_LENGTH;
		case AES_CCM_64_64_256:
		case AES_CCM_64_128_256:
			return AES_CCM_64_IV_LENGTH;
		default:
			return -1;
		}
	}

	/**
	 * Get IV length for AES GCM in bytes.
	 * 
	 * @param alg algorithm ID:
	 * @return iv length
	 */
	private static int ivLengthGcm(AlgorithmID alg) {
		switch (alg) {
		case AES_GCM_128:
		case AES_GCM_192:
		case AES_GCM_256:
			return AES_GCM_IV_LENGTH;
		default:
			return -1;
		}
	}

	/**
	 * Get IV length for ChaCha20-Poly1305 in bytes.
	 * 
	 * @param alg algorithm ID:
	 * @return iv length
	 */
	private static int ivLengthChaChaPoly(AlgorithmID alg) {
		switch (alg) {
		case CHACHA20_POLY1305:
			return CHACHA_POLY_IV_LENGTH;
		default:
			return -1;
		}
	}

	/**
	 * Get IV length for ChaCha20 in bytes.
	 * 
	 * @param alg algorithm ID:
	 * @return iv length
	 */
	private static int ivLengthChaCha(AlgorithmID alg) {
		switch (alg) {
		case CHACHA20:
			return CHACHA_IV_LENGTH;
		default:
			return -1;
		}
	}

	/**
	 * Get IV length for AES CTR in bytes.
	 * 
	 * @param alg algorithm ID:
	 * @return iv length
	 */
	private static int ivLengthCtr(AlgorithmID alg) {
		switch (alg) {
		case A128CTR:
			return AES_CTR_IV_LENGTH;
		case A192CTR:
			return AES_CTR_IV_LENGTH;
		case A256CTR:
			return AES_CTR_IV_LENGTH;
		default:
			return -1;
		}
	}

	/**
	 * Get IV length for AES CBC in bytes.
	 * 
	 * @param alg algorithm ID:
	 * @return iv length
	 */
	private static int ivLengthCbc(AlgorithmID alg) {
		switch (alg) {
		case A128CBC:
			return AES_CBC_IV_LENGTH;
		case A192CBC:
			return AES_CBC_IV_LENGTH;
		case A256CBC:
			return AES_CBC_IV_LENGTH;
		default:
			return -1;
		}
	}

	/**
	 * Get IV length for supported algorithms in bytes.
	 * 
	 * @param alg algorithm ID:
	 * @return iv length
	 */
	public static int ivLength(AlgorithmID alg) {
		int ccmIvLength = ivLengthCcm128(alg);
		if (ccmIvLength != -1) {
			return ccmIvLength;
		}

		ccmIvLength = ivLengthCcm256(alg);
		if (ccmIvLength != -1) {
			return ccmIvLength;
		}

		int gcmIvLength = ivLengthGcm(alg);
		if (gcmIvLength != -1) {
			return gcmIvLength;
		}

		int chaChaPolyIvLength = ivLengthChaChaPoly(alg);
		if (chaChaPolyIvLength != -1) {
			return chaChaPolyIvLength;
		}

		int chaChaIvLength = ivLengthChaCha(alg);
		if (chaChaIvLength != -1) {
			return chaChaIvLength;
		}

		int cbcIvLength = ivLengthCbc(alg);
		if (cbcIvLength != -1) {
			return cbcIvLength;
		}

		int ctrIvLength = ivLengthCtr(alg);
		if (ctrIvLength != -1) {
			return ctrIvLength;
		}

		return -1;
	}

	/**
	 * Check if an AES CCM 128 bit key algorithm is supported.
	 * 
	 * @param alg the algorithm
	 * @return if it is supported
	 */
	private static boolean isSupportedAesCcm128(AlgorithmID alg) {
		if (ivLengthCcm128(alg) == -1) {
			return false;
		}

		return true;
	}

	/**
	 * Check if an AES CCM 256 bit key algorithm is supported.
	 * 
	 * @param alg the algorithm
	 * @return if it is supported
	 */
	private static boolean isSupportedAesCcm256(AlgorithmID alg) {
		if (ivLengthCcm256(alg) == -1) {
			return false;
		}

		return true;
	}

	/**
	 * Check if an AES GCM algorithm is supported.
	 * 
	 * @param alg the algorithm
	 * @return if it is supported
	 */
	private static boolean isSupportedAesGcm(AlgorithmID alg) {
		if (ivLengthGcm(alg) == -1) {
			return false;
		}

		return true;
	}


	/**
	 * Check if a ChaCha20-Poly1305 algorithm is supported.
	 * 
	 * @param alg the algorithm
	 * @return if it is supported
	 */
	private static boolean isSupportedChaChaPoly(AlgorithmID alg) {
		if (ivLengthChaChaPoly(alg) == -1) {
			return false;
		}

		return true;
	}


	/**
	 * Check if a ChaCha20 algorithm is supported.
	 * 
	 * @param alg the algorithm
	 * @return if it is supported
	 */
	private static boolean isSupportedChaCha(AlgorithmID alg) {
		if (ivLengthChaCha(alg) == -1) {
			return false;
		}

		return true;
	}

	/**
	 * Check if an AES CTR algorithm is supported.
	 * 
	 * @param alg the algorithm
	 * @return if it is supported
	 */
	private static boolean isSupportedAesCtr(AlgorithmID alg) {
		if (ivLengthCtr(alg) == -1) {
			return false;
		}

		return true;
	}

	/**
	 * Check if an AES CBC algorithm is supported.
	 * 
	 * @param alg the algorithm
	 * @return if it is supported
	 */
	private static boolean isSupportedAesCbc(AlgorithmID alg) {
		if (ivLengthCbc(alg) == -1) {
			return false;
		}

		return true;
	}

}
