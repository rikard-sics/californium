/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
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
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.edhoc;

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

	/**
	 * BigInteger z_2_bi = new BigInteger(invertArray(z_2.toByteArray()));
	 * BigIntegerFieldElement z_2_bif = new BigIntegerFieldElement(ed25519Field,
	 * z_2_bi);
	 */

	/**
	 * Calculate Curve25519 v coordinate from Ed25519 x coordinate and
	 * Curve25519 u coordinate
	 * 
	 * @param x the Ed25519 x coordinate
	 * @param u the Curve25519 u coordinate
	 * @return the Curve25519 v coordinate
	 */
	static FieldElement calcCurve25519_v_alt(FieldElement x, FieldElement u) {

		/* Calculate v from u and x */
		// v = sqrt(-486664)*u/x

		// invert(x)
		FieldElement x_invert = x.invert();

		// u / x -> u * invert(x)
		FieldElement _x_invert = ed25519ToBiginteger(x_invert);
		FieldElement u_over_x = u.multiply(_x_invert);

		// calculate v
		FieldElement v = root.multiply(u_over_x);

		return v;
	}

	/**
	 * Convert a Ed25519FieldElement to a BigIntegerFieldElement
	 * 
	 * @param input the Ed25519FieldElement
	 * @return the resulting BigIntegerFieldElement
	 */
	static BigIntegerFieldElement ed25519ToBiginteger(FieldElement input) {
		BigInteger outputBi = new BigInteger(invertArray(input.toByteArray()));
		BigIntegerFieldElement outputFieldElement = new BigIntegerFieldElement(ed25519Field, outputBi);

		return outputFieldElement;
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
	public static byte[] invertArray(byte[] input) {
		byte[] output = input.clone();
		for (int i = 0; i < input.length; i++) {
			output[i] = input[input.length - i - 1];
		}
		return output;
	}

	/* Methods for Weierstrass conversions below */
	// https://tools.ietf.org/html/draft-ietf-lwig-curve-representations-10#appendix-E.2

	/**
	 * Remap a Curve25519 u coordinate to a Wei25519 X coordinate.
	 * 
	 * @param u the Curve25519 u coordinate
	 * 
	 * @return the Wei25519 X coordinate
	 */
	public static FieldElement curve25519uToWei25519X(FieldElement u) {
		BigIntegerFieldElement A = new BigIntegerFieldElement(ed25519Field, new BigInteger("486662"));
		BigIntegerFieldElement three = new BigIntegerFieldElement(ed25519Field, new BigInteger("3"));

		// X = u + A/3
		FieldElement AoverThree = A.multiply(three.invert());

		FieldElement X = u.add(AoverThree);

		return X;

	}

	/**
	 * Remap a Curve25519 v coordinate to a Wei25519 Y coordinate.
	 * 
	 * @param v the Curve25519 v coordinate
	 * 
	 * @return the Wei25519 Y coordinate
	 */
	public static FieldElement curve25519vToWei25519Y(FieldElement v) {
		// Y = v
		FieldElement Y = v;

		return Y;
	}

	/**
	 * Remap a Wei25519 X coordinate to a Curve25519 u coordinate.
	 * 
	 * @param X the Wei25519 X coordinate
	 * 
	 * @return the Curve25519 u coordinate
	 */
	public static FieldElement wei25519XToCurve25519u(FieldElement X) {
		BigIntegerFieldElement A = new BigIntegerFieldElement(ed25519Field, new BigInteger("486662"));
		BigIntegerFieldElement three = new BigIntegerFieldElement(ed25519Field, new BigInteger("3"));

		// u = X - A/3
		FieldElement AoverThree = A.multiply(three.invert());

		FieldElement u = X.subtract(AoverThree);

		return u;
	}

	/**
	 * Remap a Wei25519 Y coordinate to a Curve25519 v coordinate.
	 * 
	 * @param Y the Wei25519 Y coordinate
	 * 
	 * @return the Curve25519 v coordinate
	 */
	public static FieldElement wei25519YToCurve25519v(FieldElement Y) {
		// v = Y
		FieldElement v = Y;

		return v;

	}

	/**
	 * Remap a Edwards25519 y coordinate to a Wei25519 X coordinate
	 * 
	 * @param y the Edwards25519 y coordinate
	 * @return the Wei25519 X coordinate
	 */
	public static FieldElement edwards25519yToWei25519X(FieldElement y) {
		// X = ((1+y)/(1-y)+A/3

		BigIntegerFieldElement A = new BigIntegerFieldElement(ed25519Field, new BigInteger("486662"));
		BigIntegerFieldElement three = new BigIntegerFieldElement(ed25519Field, new BigInteger("3"));
		BigIntegerFieldElement one = new BigIntegerFieldElement(ed25519Field, new BigInteger("1"));
		FieldElement AoverThree = A.multiply(three.invert());

		FieldElement onePlusY = one.add(y);
		FieldElement oneMinusY = one.subtract(y);

		FieldElement divided = onePlusY.multiply(oneMinusY.invert());

		FieldElement X = divided.add(AoverThree);

		return X;
	}

	/**
	 * Remap a Edwards25519 x (& y) coordinate to a Wei25519 Y coordinate
	 * 
	 * @param x the Edwards25519 x coordinate
	 * @param y the Edwards25519 y coordinate
	 * @return the Wei25519 Y coordinate
	 */
	public static FieldElement edwards25519xToWei25519Y(FieldElement x, FieldElement y) {
		// Y = c*(1+y)/((1-y)*x)

		BigIntegerFieldElement c = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("51042569399160536130206135233146329284152202253034631822681833788666877215207"));
		BigIntegerFieldElement one = new BigIntegerFieldElement(ed25519Field, new BigInteger("1"));

		FieldElement onePlusY = one.add(y);
		FieldElement oneMinusY = one.subtract(y);

		FieldElement onePlusYmultC = c.multiply(onePlusY);
		FieldElement oneMinusYmultX = oneMinusY.multiply(x);

		FieldElement Y = onePlusYmultC.multiply((oneMinusYmultX.invert()));

		return Y;
	}

	/**
	 * Remap a Weierstrass X coordinate to a Edwards25519 y coordinate
	 * 
	 * @param X the Weierstrass X coordinate
	 * @return the Edwards25519 y coordinate
	 */
	public static FieldElement wei25519XToEdwards25519y(FieldElement X) {
		// y = (X-A/3-1)/(X-A/3+1)

		BigIntegerFieldElement A = new BigIntegerFieldElement(ed25519Field, new BigInteger("486662"));
		BigIntegerFieldElement three = new BigIntegerFieldElement(ed25519Field, new BigInteger("3"));
		BigIntegerFieldElement one = new BigIntegerFieldElement(ed25519Field, new BigInteger("1"));
		FieldElement AoverThree = A.multiply(three.invert());

		FieldElement numerator = X.subtract(AoverThree).subtract(one);
		FieldElement denominator = X.subtract(AoverThree).add(one);

		FieldElement y = numerator.multiply(denominator.invert());

		return y;
	}

	/**
	 * Remap a Weierstrass Y (& X) coordinate to an Edwards25519 x coordinate
	 * 
	 * @param Y the Weierstrass Y coordinate
	 * @param X the Weierstrass X coordinate
	 * @return the Edwards25519 x coordinate
	 */
	public static FieldElement wei25519YToEdwards25519x(FieldElement Y, FieldElement X) {
		// x = (c*(X-A/3)/Y

		BigIntegerFieldElement c = new BigIntegerFieldElement(ed25519Field,
				new BigInteger("51042569399160536130206135233146329284152202253034631822681833788666877215207"));

		BigIntegerFieldElement A = new BigIntegerFieldElement(ed25519Field, new BigInteger("486662"));
		BigIntegerFieldElement three = new BigIntegerFieldElement(ed25519Field, new BigInteger("3"));
		FieldElement AoverThree = A.multiply(three.invert());

		FieldElement XminusAoverThree = X.subtract(AoverThree);

		FieldElement numerator = XminusAoverThree.multiply(c);
		FieldElement denominator = Y;

		FieldElement x = numerator.multiply(denominator.invert());

		return x;
	}

}
