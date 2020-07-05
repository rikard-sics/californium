/*******************************************************************************
 * Copyright (c) 2020 RISE SICS and others.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.junit.BeforeClass;
import org.junit.Test;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerFieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerLittleEndianEncoding;

/**
 * Tests for remapping Edwards25519 curve coordinates to Curve25519 coordinates.
 *
 */
public class KeyRemappingTest {

	/*
	 * Useful links:
	 * https://crypto.stackexchange.com/questions/63732/curve-25519-x25519-
	 * ed25519-convert-coordinates-between-montgomery-curve-and-t/63734
	 * 
	 * https://tools.ietf.org/html/rfc7748
	 * 
	 * https://tools.ietf.org/html/rfc8032
	 */

	// Create the ed25519 field
	private static Field ed25519Field = new Field(256, // b
			Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q(2^255-19)
			new BigIntegerLittleEndianEncoding());

	// Install crypto provider for EdDSA
	@BeforeClass
	public static void installCryptoProvider() {
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);
	}

	/**
	 * Test from values in RFC7748.
	 * 
	 * @throws CoseException on error in operations with COSE keys
	 */
	@Test
	public void testRfcVectors() throws CoseException {
		// Define test values x and y from RFC7748. Created as field elements to
		// use for calculations in the field.
		BigIntegerFieldElement x = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"));
		BigIntegerFieldElement y = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));

		// Define correctly calculated values of u and v from RFC7748
		BigIntegerFieldElement u_correct = new BigIntegerFieldElement(ed25519Field, new BigInteger("9"));
		BigIntegerFieldElement v_correct = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401"));

		// Calculate u and v values
		FieldElement u = KeyRemapping.calcCurve25519_u(y);
		FieldElement v = KeyRemapping.calcCurve25519_v(x, u);

		// Print calculated values
		System.out.println("x: " + x);
		System.out.println("y: " + y);

		System.out.println("v: " + v);
		System.out.println("u: " + u);

		// Check that calculated u and v values are correct
		assertArrayEquals(u.toByteArray(), u_correct.toByteArray());
		if (Arrays.equals(u.toByteArray(), u_correct.toByteArray())) {
			System.out.println("u value is correct!");
		} else {
			System.out.println("u value is INCORRECT!");
		}

		assertArrayEquals(v.toByteArray(), v_correct.toByteArray());
		if (Arrays.equals(v.toByteArray(), v_correct.toByteArray())) {
			System.out.println("v value is correct!");
		} else {
			System.out.println("v value is INCORRECT!");
		}

	}

	/**
	 * Testing starting with a COSE Key
	 * 
	 * @throws CoseException on error in operations with COSE keys
	 */
	@Test
	public void testRemappingWithCOSEKey() throws CoseException {
		OneKey myKey = OneKey.generateKey(AlgorithmID.EDDSA);
		FieldElement y_fromKeyAlt = KeyRemapping.extractCOSE_y_alt(myKey);
		FieldElement y_fromKey = KeyRemapping.extractCOSE_y(myKey);

		System.out.println("y from COSE key (alt): " + y_fromKeyAlt);
		System.out.println("y from COSE key: " + y_fromKey);
		System.out.println("COSE key X param_: " + myKey.get(KeyKeys.OKP_X));

		System.out.println("y from COSE key (alt) (bytes): " + Utils.bytesToHex(y_fromKeyAlt.toByteArray()));
		System.out.println("y from COSE key (bytes): " + Utils.bytesToHex(y_fromKey.toByteArray()));

		// Check that calculating y in both ways give the same result
		assertArrayEquals(y_fromKeyAlt.toByteArray(), y_fromKey.toByteArray());
		if (Arrays.equals(y_fromKeyAlt.toByteArray(), y_fromKey.toByteArray())) {
			System.out.println("y from key value is correct!");
		} else {
			System.out.println("y from key value is INCORRECT!");
		}

		/**/
		System.out.println();
		System.out.println();
		/**/

		FieldElement x_fromKey = KeyRemapping.extractCOSE_x(myKey);
		System.out.println("x from COSE key: " + x_fromKey);
		assertEquals(32, x_fromKey.toByteArray().length);

		FieldElement u1 = KeyRemapping.calcCurve25519_u(y_fromKeyAlt);
		FieldElement u2 = KeyRemapping.calcCurve25519_u(y_fromKey);

		// The two calculated u values match
		assertArrayEquals(u1.toByteArray(), u2.toByteArray());

		System.out.println(u1);
		System.out.println(u2);

	}

}
