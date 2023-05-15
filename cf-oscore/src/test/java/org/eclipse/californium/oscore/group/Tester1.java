package org.eclipse.californium.oscore.group;

import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.eclipse.californium.elements.util.StringUtil;

import java.util.Arrays;

public class Tester1 {

	// Size of the encryption key in bits
	private static final int KEY_SIZE_BITS = 256;
	// Size of the nonce in bytes
	private static final int NONCE_SIZE_BITS = 96;
	// Size of the authentication tag in bits
	private static final int TAG_SIZE_BITS = 128;

	/**
	 * Decrypts the ciphertext using ChaCha20-Poly1305 algorithm with additional
	 * authenticated data (AAD)
	 * 
	 * @param ciphertext
	 * @param nonce
	 * @param key
	 * @param aad
	 * @return
	 *
	 */
	public static byte[] decryptWithChaChaPoly(byte[] ciphertext, byte[] nonce, byte[] key, byte[] aad) {
		byte[] plaintext = null;

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
	 * Encrypts the plaintext using ChaCha20-Poly1305 algorithm with additional
	 * authenticated data (AAD)
	 * 
	 * @param plaintext
	 * @param nonce
	 * @param key
	 * @param aad
	 * @return
	 *
	 */
	public static byte[] encryptWithChaChaPoly(byte[] plaintext, byte[] nonce, byte[] key, byte[] aad) {
		byte[] ciphertext = null;

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

	public static void main(String[] args) {
		// Test vector values
		String keyHex = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
		String plaintextHex = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
		String nonceHex = "070000004041424344454647";
		String aadHex = "50515253c0c1c2c3c4c5c6c7";
		String expectedCiphertextHex = "e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6";

		// Convert hex strings to byte arrays
		byte[] key = hexToBytes(keyHex);
		byte[] plaintext = hexToBytes(plaintextHex);
		byte[] nonce = hexToBytes(nonceHex);
		byte[] aad = hexToBytes(aadHex);

		// Invoke the encryption function
		byte[] ciphertext = encryptWithChaChaPoly(plaintext, nonce, key, aad);

		// Compare the ciphertext with the expected value
		String ciphertextHex = bytesToHex(ciphertext);
		System.out.println("Ciphertext: " + ciphertextHex);
		System.out.println("Expected Ciphertext: " + expectedCiphertextHex);
		System.out.println("Match: " + ciphertextHex.equalsIgnoreCase(expectedCiphertextHex));
		
		// Invoke the decryption function
		byte[] plaintextOut = decryptWithChaChaPoly(ciphertext, nonce, key, aad);
		System.out.println("Out: " + StringUtil.byteArray2Hex(plaintextOut));

	}

	// Helper method to convert a hex string to a byte array
	private static byte[] hexToBytes(String hex) {
		int len = hex.length();
		byte[] bytes = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		}
		return bytes;
	}

	// Helper method to convert a byte array to a hex string
	private static String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X", b));
		}
		return sb.toString();
	}

}
