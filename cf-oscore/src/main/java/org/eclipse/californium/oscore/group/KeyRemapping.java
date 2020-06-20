/*******************************************************************************
 * Copyright (c) 2020 RISE SICS and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore.group;

import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerFieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerLittleEndianEncoding;

/**
 * Class implementing functionality for key remapping from Edwards coordinates
 * to Montgomery coordinates.
 *
 */
public class KeyRemapping {

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

	// Value of sqrt(-486664) hardcoded (note that there are 2 roots)
	private static BigIntegerFieldElement root = new BigIntegerFieldElement(ed25519Field,
			new BigInteger("51042569399160536130206135233146329284152202253034631822681833788666877215207"));

	/**
	 * Main method running a number of tests on the code.
	 * 
	 * @param args command line arguments
	 * @throws Exception on failure in some of the tests
	 */
	public static void main(String args[]) throws Exception {
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

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
		FieldElement u = calcCurve25519_u(y);
		FieldElement v = calcCurve25519_v(x, u);

		// Print calculated values
		System.out.println("x: " + x);
		System.out.println("y: " + y);

		System.out.println("v: " + v);
		System.out.println("u: " + u);

		// Check that calculated u and v values are correct
		if (Arrays.equals(u.toByteArray(), u_correct.toByteArray())) {
			System.out.println("u value is correct!");
		} else {
			System.out.println("u value is INCORRECT!");
		}
		if (Arrays.equals(v.toByteArray(), v_correct.toByteArray())) {
			System.out.println("v value is correct!");
		} else {
			System.out.println("v value is INCORRECT!");
		}

		/**/
		System.out.println();
		System.out.println();
		/**/

		// Testing starting with a COSE Key

		OneKey myKey = OneKey.generateKey(AlgorithmID.EDDSA);
		FieldElement y_fromKeyAlt = extractCOSE_y_alt(myKey);
		FieldElement y_fromKey = extractCOSE_y(myKey);

		System.out.println("y from COSE key (alt): " + y_fromKeyAlt);
		System.out.println("y from COSE key: " + y_fromKey);
		System.out.println("COSE key X param_: " + myKey.get(KeyKeys.OKP_X));

		System.out.println("y from COSE key (alt) (bytes): " + Utils.bytesToHex(y_fromKeyAlt.toByteArray()));
		System.out.println("y from COSE key (bytes): " + Utils.bytesToHex(y_fromKey.toByteArray()));

		// Check that calculating y in both ways give the same result
		if (Arrays.equals(y_fromKeyAlt.toByteArray(), y_fromKey.toByteArray())) {
			System.out.println("y from key value is correct!");
		} else {
			System.out.println("y from key value is INCORRECT!");
		}
		
		/**/
		System.out.println();
		System.out.println();
		/**/
		
		FieldElement x_fromKey = extractCOSE_x(myKey);
		System.out.println("x from COSE key: " + x_fromKey);

		FieldElement uuu1 = calcCurve25519_u(y_fromKeyAlt);
		FieldElement uuu2 = calcCurve25519_u(y_fromKey);
		// calcCurve25519_v(x_fromKey, uuu1);
		// calcCurve25519_v(x_fromKey, uuu2);
		//
		System.out.println(uuu1);
		System.out.println(uuu2);

	}

	/**
	 * Calculate Curve25519 u coordinate from Ed25519 y coordinate
	 * 
	 * @param y the Ed25519 y coordinate
	 * @return the Curve25519 u coordinate
	 */
	static FieldElement calcCurve25519_u(FieldElement y) {

		/* Calculate u from y */
		// u = (1+y)/(1-y)

		// 1 + y -> y + 1
		FieldElement one_plus_y = y.addOne();

		// 1 - y -> -y + 1
		FieldElement one_minus_y = (y.negate()).addOne();

		// invert(1 - y)
		FieldElement one_minus_y_invert = one_minus_y.invert();

		// (1 + y) / (1 - y) -> (1 + y) * invert(1 - y)
		FieldElement u = one_plus_y.multiply(one_minus_y_invert);

		return u;

	}

	/**
	 * Calculate Curve25519 v coordinate from Ed25519 x coordinate and
	 * Curve25519 u coordinate
	 * 
	 * @param x the Ed25519 x coordinate
	 * @param u the Curve25519 u coordinate
	 * @return the Curve25519 v coordinate
	 */
	static FieldElement calcCurve25519_v(FieldElement x, FieldElement u) {

		/* Calculate v from u and x */
		// v = sqrt(-486664)*u/x

		// invert(x)
		FieldElement x_invert = x.invert();

		// u / x -> u * invert(x)
		FieldElement u_over_x = u.multiply(x_invert);

		// calculate v
		FieldElement v = root.multiply(u_over_x);

		return v;

	}

	/* COSE related functions below */

	/**
	 * Extract the y point coordinate from a COSE Key (OneKey). Alternative way
	 * using division.
	 * 
	 * @param key the COSE key
	 * @return the y point coordinate
	 * 
	 * @throws CoseException if retrieving public key part fails
	 */
	static FieldElement extractCOSE_y_alt(OneKey key) throws CoseException {
		EdDSAPublicKey pubKey = (EdDSAPublicKey) key.AsPublicKey();

		// Get projective coordinates for Y and Z
		FieldElement Y = pubKey.getA().getY();
		FieldElement Z = pubKey.getA().getZ();

		// y = Y/Z -> y = Y * invert(Z)
		FieldElement recip = Z.invert();
		FieldElement y = Y.multiply(recip);

		return y;
	}

	/**
	 * Extract the y point coordinate from a COSE Key (OneKey). Way using the X
	 * value of the key directly, clearing one bit.
	 * https://tools.ietf.org/html/rfc8032#section-5.1.2
	 * 
	 * @param key the COSE key
	 * @return the y point coordinate
	 * 
	 * @throws CoseException if retrieving public key part fails
	 */
	static FieldElement extractCOSE_y(OneKey key) throws CoseException {

		// Retrieve X value from COSE key as byte array
		byte[] X_value = key.get(KeyKeys.OKP_X).GetByteString();

		// Clear most significant bit of the final octet in the X value (that
		// indicates sign of x coordinate). The result is the y coordinate.
		byte[] y_array = X_value.clone();
		y_array[y_array.length - 1] &= 0B01111111;

		// The array must be reversed to have correct byte order
		// BigInteger wants Big Endian but it is in Little Endian
		byte[] y_array_inv = invertArray(y_array);
		
		// Create field element for y from updated X value
		FieldElement y = new BigIntegerFieldElement(ed25519Field, new BigInteger(y_array_inv));

		return y;
	}

	/**
	 * Extract the x point coordinate from a COSE Key (OneKey). Way using
	 * division.
	 * 
	 * @param key the COSE key
	 * @return the x point coordinate
	 * 
	 * @throws CoseException if retrieving public key part fails
	 */
	static FieldElement extractCOSE_x(OneKey key) throws CoseException {
		EdDSAPublicKey pubKey = (EdDSAPublicKey) key.AsPublicKey();

		// Get projective coordinates for X and Z
		FieldElement X = pubKey.getA().getX();
		FieldElement Z = pubKey.getA().getZ();

		// x = X/Z -> x = X * invert(Z)
		FieldElement recip = Z.invert();
		FieldElement x = X.multiply(recip);

		return x;
	}

	/**
	 * Invert a byte array
	 * 
	 * @param input the input byte array
	 * @return the inverted byte array
	 */
	private static byte[] invertArray(byte[] input) {
		byte[] output = input.clone();
		for (int i = 0; i < input.length; i++) {
			output[i] = input[input.length - i - 1];
		}
		return output;
	}
}
