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

import net.i2p.crypto.eddsa.Utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.util.Bytes;
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

	private final static int AES_CCM_16_IV_LENGTH = 13;
	private final static int AES_CCM_64_IV_LENGTH = 7;
	private final static int AES_GCM_IV_LENGTH = 12;
	private static final int CHACHA_POLY_IV_LENGTH = 12;
	private static final int CHACHA_IV_LENGTH = CHACHA_POLY_IV_LENGTH;
	private final static int AES_CBC_IV_LENGTH = 16;
	private final static int AES_CTR_IV_LENGTH = 16;

	private static final String AES_SPEC = "AES";
	private static final String AES_GCM_SPEC = "AES/GCM/NoPadding";
	private static final String CHACHA_SPEC = "ChaCha20";
	private static final String CHACHA_POLY_SPEC = "ChaCha20-Poly1305";
	private static final String AES_CTR_SPEC = "AES/CTR/NoPadding";
	private static final String AES_CBC_SPEC = "AES/CBC/PKCS5Padding";

	private static final ThreadLocalCipher AES_GCM_CIPHER = new ThreadLocalCipher(AES_GCM_SPEC);
	private static final ThreadLocalCipher CHACHA_POLY_CIPHER = new ThreadLocalCipher(CHACHA_POLY_SPEC);
	private static final ThreadLocalCipher CHACHA_CIPHER = new ThreadLocalCipher(CHACHA_SPEC);
	private static final ThreadLocalCipher AES_CTR_CIPHER = new ThreadLocalCipher(AES_CTR_SPEC);
	private static final ThreadLocalCipher AES_CBC_CIPHER = new ThreadLocalCipher(AES_CBC_SPEC);

	protected String context;
	protected byte[] rgbEncrypt;

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
		case CHACHA20:
			ChaCha20_Decrypt(alg, rgbKey);
			break;
		case A128CTR:
		case A192CTR:
		case A256CTR:
			AES_CTR_Decrypt(alg, rgbKey);
			break;
		case A128CBC:
		case A192CBC:
		case A256CBC:
			AES_CBC_Decrypt(alg, rgbKey);
			break;
		default:
			break;
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
		case CHACHA20:
			ChaCha20_Encrypt(alg, rgbKey);
			break;
		case A128CTR:
		case A192CTR:
		case A256CTR:
			AES_CTR_Encrypt(alg, rgbKey);
			break;
		case A128CBC:
		case A192CBC:
		case A256CBC:
			AES_CBC_Encrypt(alg, rgbKey);
			break;
		default:
			break;
		}

		ProcessCounterSignatures();
	}

	// Method taken from EncryptCommon in COSE. This will provide the full AAD /
	// Encrypt0-structure.
	//
	// ===
	// Fix is not applied when AAD is not retrieved, such as for the no-MAC
	// algos ===
	private byte[] getAADBytes() {
		CBORObject obj = CBORObject.NewArray();

		if (objProtected != null) {
			System.out.println("Checking objProtected before fix: " + Utils.bytesToHex(objProtected.EncodeToBytes()));			
		} else {
			System.out.println("Checking objProtected before fix: " + "NULL");
		}
		

		obj.Add(context);
		if (objProtected.size() == 0)
		{
			rgbProtected = new byte[0];
			System.out.println("** Did normal fix");
		} else {
			rgbProtected = objProtected.EncodeToBytes();
			System.out.println("** No normal fix");
		}

		obj.Add(rgbProtected);
		obj.Add(CBORObject.FromObject(externalData));

		return obj.EncodeToBytes();
	}

	private void AES_CCM_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {
		CBORObject iv = findAttribute(HeaderKeys.IV);
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
		byte[] aad = getAADBytes();

		try {
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

		} catch (NoSuchAlgorithmException ex) {
			throw new CoseException("Algorithm not supported", ex);
		} catch (Exception ex) {
			throw new CoseException("Encryption failure", ex);
		}
	}

	/**
	 * Decrypts the ciphertext using ChaCha20 algorithm (without Poly1305) with
	 * no additional authenticated data (AAD)
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
		final int ivLen = getIvLength(alg);
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
			Cipher cipher = CHACHA_CIPHER.currentWithCause();

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
		final int ivLen = getIvLength(alg);
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
			Cipher cipher = CHACHA_CIPHER.currentWithCause();

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

	private void AES_CTR_Decrypt(AlgorithmID alg, byte[] rgbKey) throws CoseException, IllegalStateException {
		// validate key
		if (rgbKey.length != alg.getKeySize() / Byte.SIZE) {
			throw new CoseException("Key Size is incorrect");
		}

		// obtain and validate IV
		final int ivLen = getIvLength(alg);
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
			Cipher cipher = AES_CTR_CIPHER.currentWithCause();
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
		int ivLen = getIvLength(alg);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect.");
		}

		try {
			Cipher cipher = AES_CTR_CIPHER.currentWithCause();
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
		final int ivLen = getIvLength(alg);
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
			Cipher cipher = AES_CBC_CIPHER.currentWithCause();
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
		int ivLen = getIvLength(alg);
		if (iv.getType() != CBORType.ByteString) {
			throw new CoseException("IV is incorrectly formed.");
		}
		if (iv.GetByteString().length != ivLen) {
			throw new CoseException("IV size is incorrect.");
		}

		try {
			Cipher cipher = AES_CBC_CIPHER.currentWithCause();
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

		System.out.println("## rgbBodyProtect: " + rgbProtected);
		System.out.println("## rgbBodyProtect: " + Utils.bytesToHex(rgbProtected));

		System.out.println("## rgbEncrypt: " + rgbEncrypt);
		System.out.println("## rgbEncrypt: " + Utils.bytesToHex(rgbEncrypt));

		if (counterSign1 != null) {
			counterSign1.sign(rgbProtected, rgbEncrypt);
			addAttribute(HeaderKeys.CounterSignature0, counterSign1.EncodeToCBORObject(), Attribute.UNPROTECTED);
		}
	}

	@Override
	public boolean validate(CounterSign1 countersignature) throws CoseException {

		// Fix issue with rgbProtected being NULL instead of empty CBOR bstr
		// when doing verification before decryption.
		if (objProtected.size() == 0) {
			rgbProtected = new byte[0];
			System.out.println("Did normal fix");
		} else {
			rgbProtected = objProtected.EncodeToBytes();
			System.out.println("No normal fix");
		}

		return countersignature.validate(rgbProtected, rgbEncrypt);
	}

	@Override
	public boolean validate(CounterSign countersignature) throws CoseException {
		return countersignature.validate(rgbProtected, rgbEncrypt);
	}

	/**
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
	 * 
	 * @param alg algorithm ID:
	 * @return iv length, or -1 if the algorithm is unsupported
	 */
	public static int getIvLength(AlgorithmID alg) {
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
		case CHACHA20:
			return CHACHA_IV_LENGTH;
		case A128CTR:
		case A192CTR:
		case A256CTR:
			return AES_CTR_IV_LENGTH;
		case A128CBC:
		case A192CBC:
		case A256CBC:
			return AES_CBC_IV_LENGTH;
		default:
			return -1;
		}
	}
}
