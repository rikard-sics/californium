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

	/* Methods for Weierstrass conversions below */
	// https://tools.ietf.org/html/draft-ietf-lwig-curve-representations-10#appendix-E.2

	/**
	 * Test converting a Curve25519 u coordinate to a Wei25519 X coordinate.
	 */
	@Test
	public void testCurve25519uToWei25519X() {
		// u value (input)
		BigIntegerFieldElement u = new BigIntegerFieldElement(ed25519Field, new BigInteger("9"));

		// The expected correct X value
		BigIntegerFieldElement expectedX = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("19298681539552699237261830834781317975544997444273427339909597334652188435546"));

		// Calculate the X value (output)
		FieldElement resultX = KeyRemapping.curve25519uToWei25519X(u);

		System.out.println("Correct " + Utils.bytesToHex(expectedX.toByteArray()));
		System.out.println("Result " + Utils.bytesToHex(resultX.toByteArray()));

		assertArrayEquals(expectedX.toByteArray(), resultX.toByteArray());
	}

	/**
	 * Test converting a Curve25519 v coordinate to a Wei25519 Y coordinate.
	 */
	@Test
	public void testCurve25519vToWei25519Y() {
		// v value (input)
		BigIntegerFieldElement v = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401"));

		// The expected correct Y value
		BigIntegerFieldElement expectedY = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401"));

		// Calculate the Y value (output)
		FieldElement resultY = KeyRemapping.curve25519vToWei25519Y(v);

		System.out.println("Correct " + Utils.bytesToHex(expectedY.toByteArray()));
		System.out.println("Result " + Utils.bytesToHex(resultY.toByteArray()));

		assertArrayEquals(expectedY.toByteArray(), resultY.toByteArray());
	}

	/**
	 * Test converting a Wei25519 X coordinate to a Curve25519 u coordinate.
	 */
	@Test
	public void testWei25519XToCurve25519u() {
		// X value (input)
		BigIntegerFieldElement X = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("19298681539552699237261830834781317975544997444273427339909597334652188435546"));

		// The expected correct u value
		BigIntegerFieldElement expectedU = new BigIntegerFieldElement(ed25519Field, new BigInteger("9"));

		// Calculate the u value (output)
		FieldElement resultU = KeyRemapping.wei25519XToCurve25519u(X);

		System.out.println("Correct " + Utils.bytesToHex(expectedU.toByteArray()));
		System.out.println("Result " + Utils.bytesToHex(resultU.toByteArray()));

		assertArrayEquals(expectedU.toByteArray(), resultU.toByteArray());
	}

	/**
	 * Test converting a Wei25519 Y coordinate to a Curve25519 v coordinate.
	 */
	@Test
	public void testWei25519YToCurve25519v() {
		// Y value (input)
		BigIntegerFieldElement Y = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401"));

		// The expected correct v value
		BigIntegerFieldElement expectedV = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401"));

		// Calculate the v value (output)
		FieldElement resultV = KeyRemapping.wei25519YToCurve25519v(Y);

		System.out.println("Correct " + Utils.bytesToHex(expectedV.toByteArray()));
		System.out.println("Result " + Utils.bytesToHex(resultV.toByteArray()));

		assertArrayEquals(expectedV.toByteArray(), resultV.toByteArray());
	}

	/**
	 * Test converting a Edwards25519 y coordinate to a Wei25519 X coordinate
	 */
	@Test
	public void testEdwards25519yToWei25519X() {
		// y value (input)
		BigIntegerFieldElement y = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));

		// The expected correct X value
		BigIntegerFieldElement expectedX = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("19298681539552699237261830834781317975544997444273427339909597334652188435546"));

		FieldElement calculatedX = KeyRemapping.edwards25519yToWei25519X(y);

		System.out.println("Correct " + Utils.bytesToHex(expectedX.toByteArray()));
		System.out.println("Result " + Utils.bytesToHex(calculatedX.toByteArray()));

		assertArrayEquals(expectedX.toByteArray(), calculatedX.toByteArray());

	}

	/**
	 * Test converting a Edwards25519 x (& y) coordinate to a Wei25519 Y
	 * coordinate
	 */
	@Test
	public void testEdwards25519xToWei25519Y() {
		// y value (input)
		BigIntegerFieldElement y = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
		// x value (input)
		BigIntegerFieldElement x = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"));

		// The expected correct Y value
		BigIntegerFieldElement expectedY = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401"));

		FieldElement calculatedY = KeyRemapping.edwards25519xToWei25519Y(x, y);

		System.out.println("Correct " + Utils.bytesToHex(expectedY.toByteArray()));
		System.out.println("Result " + Utils.bytesToHex(calculatedY.toByteArray()));

		assertArrayEquals(expectedY.toByteArray(), calculatedY.toByteArray());

	}

	/**
	 * Test converting a Wei25519 X coordinate to an Edwards25519 y coordinate
	 */
	@Test
	public void testWei25519XToEdwards25519y() {
		// X value (input)
		BigIntegerFieldElement X = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("19298681539552699237261830834781317975544997444273427339909597334652188435546"));

		// The expected correct y value
		BigIntegerFieldElement expectedY = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));

		FieldElement calculatedY = KeyRemapping.wei25519XToEdwards25519y(X);

		System.out.println("Correct " + Utils.bytesToHex(expectedY.toByteArray()));
		System.out.println("Result " + Utils.bytesToHex(calculatedY.toByteArray()));

		assertArrayEquals(expectedY.toByteArray(), calculatedY.toByteArray());

	}

	/**
	 * Test converting a Wei25519 Y (& X) coordinate to an Edwards25519 x
	 * coordinate
	 */
	@Test
	public void Wei25519YToEdwards25519x() {
		// Y value (input)
		BigIntegerFieldElement Y = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("14781619447589544791020593568409986887264606134616475288964881837755586237401"));
		// X value (input)
		BigIntegerFieldElement X = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("19298681539552699237261830834781317975544997444273427339909597334652188435546"));

		// The expected correct x value
		BigIntegerFieldElement expectedX = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"));

		FieldElement calculatedX = KeyRemapping.wei25519YToEdwards25519x(Y, X);

		System.out.println("Correct " + Utils.bytesToHex(expectedX.toByteArray()));
		System.out.println("Result " + Utils.bytesToHex(calculatedX.toByteArray()));

		assertArrayEquals(expectedX.toByteArray(), calculatedX.toByteArray());

	}

}
