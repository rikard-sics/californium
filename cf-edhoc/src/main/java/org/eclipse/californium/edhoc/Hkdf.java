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
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-based Extract-and-Expand Key Derivation Function.
 *
 * https://tools.ietf.org/html/rfc5869
 * 
 */
public class Hkdf {
		
	/**
	 * HKDF Extract-and-Expand.
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
		byte[] prk = hmac.doFinal(ikm);

		// Perform expand
		hmac.init(new SecretKeySpec(prk, HMAC_ALG_NAME));
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

	/**
	 * HKDF-Extract.
	 * 
	 * @param salt optional salt value
	 * @param ikm input keying material
	 * @return the pseudorandom key
	 * 
	 * @throws InvalidKeyException if the HMAC procedure fails
	 * @throws NoSuchAlgorithmException if an unknown HMAC is used
	 */
	static byte[] extract(byte[] salt, byte[] ikm) throws InvalidKeyException, NoSuchAlgorithmException {

		final String digest = "SHA256"; // Hash to use

		String HMAC_ALG_NAME = "Hmac" + digest;
		Mac hmac = Mac.getInstance(HMAC_ALG_NAME);

		// Perform extract
		if (salt.length == 0) {
			salt = new byte[] { 0x00 };
		}
		hmac.init(new SecretKeySpec(salt, HMAC_ALG_NAME));
		byte[] prk = hmac.doFinal(ikm);

		return prk;
	}

	/**
	 * HKDF-Expand.
	 * 
	 * @param prk the pseudorandom key
	 * @param info context and application specific information
	 * @param len length of output keying material in octets
	 * @return output keying material
	 * 
	 * @throws InvalidKeyException if the HMAC procedure fails
	 * @throws NoSuchAlgorithmException if an unknown HMAC is used
	 */
	static byte[] expand(byte[] prk, byte[] info, int len) throws InvalidKeyException, NoSuchAlgorithmException {

		final String digest = "SHA256"; // Hash to use

		String HMAC_ALG_NAME = "Hmac" + digest;
		Mac hmac = Mac.getInstance(HMAC_ALG_NAME);
		int hashLen = hmac.getMacLength();

		// Perform expand
		hmac.init(new SecretKeySpec(prk, HMAC_ALG_NAME));
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
