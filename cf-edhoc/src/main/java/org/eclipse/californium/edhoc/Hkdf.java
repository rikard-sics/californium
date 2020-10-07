package org.eclipse.californium.edhoc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Hkdf {

	/**
	 * HMAC-based Extract-and-Expand Key Derivation Function.
	 * https://tools.ietf.org/html/rfc5869
	 * 
	 * @param salt optional salt value
	 * @param ikm input keying material
	 * @param info context and application specific information
	 * @param len length of output keying material in octets
	 * @return output keying material
	 * 
	 * @throws InvalidKeyException if the HMAC procedure fails
	 * @throws NoSuchAlgorithmException if an unknown HMAC is used
	 */
	static byte[] extractExpand(byte[] salt, byte[] ikm, byte[] info, int len)
			throws InvalidKeyException, NoSuchAlgorithmException {

		final String digest = "SHA256"; // Hash to use

		String HMAC_ALG_NAME = "Hmac" + digest;
		Mac hmac = Mac.getInstance(HMAC_ALG_NAME);
		int hashLen = hmac.getMacLength();

		// Perform extract
		if (salt.length == 0) {
			salt = new byte[] { 0x00 };
		}
		hmac.init(new SecretKeySpec(salt, HMAC_ALG_NAME));
		byte[] rgbExtract = hmac.doFinal(ikm);

		// Perform expand
		hmac.init(new SecretKeySpec(rgbExtract, HMAC_ALG_NAME));
		int c = (len / hashLen) + 1;
		byte[] okm = new byte[len];
		int maxLen = (hashLen * c > len) ? hashLen * c : len;
		byte[] T = new byte[maxLen];
		byte[] last = new byte[0];
		for (int i = 0; i < c; i++) {
			hmac.reset();
			hmac.update(last);
			hmac.update(info);
			hmac.update((byte) (i + 1));
			last = hmac.doFinal();
			System.arraycopy(last, 0, T, i * hashLen, hashLen);
		}
		System.arraycopy(T, 0, okm, 0, len);
		return okm;
	}
}
