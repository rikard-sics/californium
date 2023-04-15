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
 * Contributors:
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore.group;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;

import com.upokecenter.cbor.CBORObject;

/**
 * Methods for building CCS to use as credentials.
 *
 */
public class CcsBuilder {

	/**
	 * Build a CCS with basic parameters containing a random key.
	 * 
	 * @param alg algorithm to use for generating the key
	 * 
	 * @return the CCS
	 */
	public static CBORObject buildBasicCcs(AlgorithmID alg) {

		return buildCcs(null, "", null, null, null, null, null, alg);
	}

	/**
	 * Build a CCS with specific parameters containing a random key.
	 * 
	 * @param issuer the issuer
	 * @param subject the subject
	 * @param audience the audience
	 * @param expirationTime the expiration time
	 * @param notBefore the notBefore parameter
	 * @param issuedAt the issuedAt parameter
	 * @param cwtId the CWT ID
	 * @param alg algorithm to use for generating the key
	 * 
	 * @return the CCS
	 */
	public static CBORObject buildCcs(String issuer, String subject, String audience, Integer expirationTime,
			Integer notBefore, Integer issuedAt, byte[] cwtId, AlgorithmID alg) {

		CBORObject ccs = CBORObject.NewOrderedMap();

		if (issuer != null) {
			ccs.Add(CBORObject.FromObject(1), CBORObject.FromObject(issuer));
		}
		if (subject != null) {
			ccs.Add(CBORObject.FromObject(2), CBORObject.FromObject(subject));
		}
		if (audience != null) {
			ccs.Add(CBORObject.FromObject(3), CBORObject.FromObject(audience));
		}
		if (expirationTime != null) {
			ccs.Add(CBORObject.FromObject(4), CBORObject.FromObject(expirationTime));
		}
		if (notBefore != null) {
			ccs.Add(CBORObject.FromObject(5), CBORObject.FromObject(notBefore));
		}
		if (issuedAt != null) {
			ccs.Add(CBORObject.FromObject(6), CBORObject.FromObject(issuedAt));
		}
		if (cwtId != null) {
			ccs.Add(CBORObject.FromObject(7), CBORObject.FromObject(cwtId));
		}
		OneKey key = null;
		try {
			key = OneKey.generateKey(alg);
		} catch (CoseException e) {
			System.err.println("Failed to build COSE OneKey!");
			e.printStackTrace();
		}
		if (key != null) {
			ccs.Add(CBORObject.FromObject(8), CBORObject.FromObject(key.AsCBOR()));
		}

		return ccs;
	}

}
