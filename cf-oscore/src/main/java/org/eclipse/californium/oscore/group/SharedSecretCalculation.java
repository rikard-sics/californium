/*******************************************************************************
 * Copyright (c) 2023 RISE SICS and others.
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
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.StringUtil;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerFieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerLittleEndianEncoding;

/**
 * Class implementing the X25519 function, supporting functionality, tests and
 * shared secret calculation.
 *
 */
public class SharedSecretCalculation {

	/*
	 * Useful links:
	 * https://crypto.stackexchange.com/questions/63732/curve-25519-x25519-
	 * ed25519-convert-coordinates-between-montgomery-curve-and-t/63734
	 * 
	 * https://tools.ietf.org/html/rfc7748
	 * 
	 * https://tools.ietf.org/html/rfc8032
	 * 
	 * https://github.com/bifurcation/fourq
	 * 
	 * https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
	 * 
	 * See java-test.py I made.
	 */

	// Create the ed25519 field
	private static Field ed25519Field = new Field(256, // b
			StringUtil.hex2ByteArray("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q(2^255-19)
			new BigIntegerLittleEndianEncoding());

	/**
	 * Run a number of tests on the code.
	 * 
	 * @throws Exception on failure in one of the tests
	 */
	public static void runTests() throws Exception {
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		/* Start tests */

		/* -- Test decodeLittleEndian -- */

		System.out.println("Test decodeLittleEndian");

		// Input value:
		// a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
		byte[] input = new byte[] { (byte) 0xa5, (byte) 0x46, (byte) 0xe3, (byte) 0x6b, (byte) 0xf0, (byte) 0x52,
				(byte) 0x7c, (byte) 0x9d, (byte) 0x3b, (byte) 0x16, (byte) 0x15, (byte) 0x4b, (byte) 0x82, (byte) 0x46,
				(byte) 0x5e, (byte) 0xdd, (byte) 0x62, (byte) 0x14, (byte) 0x4c, (byte) 0x0a, (byte) 0xc1, (byte) 0xfc,
				(byte) 0x5a, (byte) 0x18, (byte) 0x50, (byte) 0x6a, (byte) 0x22, (byte) 0x44, (byte) 0xba, (byte) 0x44,
				(byte) 0x9a, (byte) 0xc4 };

		// Output value (from Python code)
		// 88925887110773138616681052956207043583107764937498542285260013040410376226469
		BigInteger correct = new BigInteger(
				"88925887110773138616681052956207043583107764937498542285260013040410376226469");

		BigInteger res = decodeLittleEndian(input, 255);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		// --

		// Input value:
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
		input = new byte[] { (byte) 0xe5, (byte) 0x21, (byte) 0x0f, (byte) 0x12, (byte) 0x78, (byte) 0x68, (byte) 0x11,
				(byte) 0xd3, (byte) 0xf4, (byte) 0xb7, (byte) 0x95, (byte) 0x9d, (byte) 0x05, (byte) 0x38, (byte) 0xae,
				(byte) 0x2c, (byte) 0x31, (byte) 0xdb, (byte) 0xe7, (byte) 0x10, (byte) 0x6f, (byte) 0xc0, (byte) 0x3c,
				(byte) 0x3e, (byte) 0xfc, (byte) 0x4c, (byte) 0xd5, (byte) 0x49, (byte) 0xc7, (byte) 0x15, (byte) 0xa4,
				(byte) 0x93 };

		// Output value (from Python code)
		// 66779901969842027605876251890954603246052331132842480964984187926304357556709
		correct = new BigInteger("66779901969842027605876251890954603246052331132842480964984187926304357556709");

		res = decodeLittleEndian(input, 255);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		/* -- Test decodeScalar -- */

		System.out.println("Test decodeScalar");

		// Input value:
		// 3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3
		input = new byte[] { (byte) 0x3d, (byte) 0x26, (byte) 0x2f, (byte) 0xdd, (byte) 0xf9, (byte) 0xec, (byte) 0x8e,
				(byte) 0x88, (byte) 0x49, (byte) 0x52, (byte) 0x66, (byte) 0xfe, (byte) 0xa1, (byte) 0x9a, (byte) 0x34,
				(byte) 0xd2, (byte) 0x88, (byte) 0x82, (byte) 0xac, (byte) 0xef, (byte) 0x04, (byte) 0x51, (byte) 0x04,
				(byte) 0xd0, (byte) 0xd1, (byte) 0xaa, (byte) 0xe1, (byte) 0x21, (byte) 0x70, (byte) 0x0a, (byte) 0x77,
				(byte) 0x9c, (byte) 0x98, (byte) 0x4c, (byte) 0x24, (byte) 0xf8, (byte) 0xcd, (byte) 0xd7, (byte) 0x8f,
				(byte) 0xbf, (byte) 0xf4, (byte) 0x49, (byte) 0x43, (byte) 0xeb, (byte) 0xa3, (byte) 0x68, (byte) 0xf5,
				(byte) 0x4b, (byte) 0x29, (byte) 0x25, (byte) 0x9a, (byte) 0x4f, (byte) 0x1c, (byte) 0x60, (byte) 0x0a,
				(byte) 0xd3 };

		// Output value (from Python code)
		// 41823108910914769844969816812214719139234914957831430028237854386113666295352
		correct = new BigInteger("41823108910914769844969816812214719139234914957831430028237854386113666295352");

		res = decodeScalar(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		// --

		// Input value:
		// 4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d
		input = new byte[] { (byte) 0x4b, (byte) 0x66, (byte) 0xe9, (byte) 0xd4, (byte) 0xd1, (byte) 0xb4, (byte) 0x67,
				(byte) 0x3c, (byte) 0x5a, (byte) 0xd2, (byte) 0x26, (byte) 0x91, (byte) 0x95, (byte) 0x7d, (byte) 0x6a,
				(byte) 0xf5, (byte) 0xc1, (byte) 0x1b, (byte) 0x64, (byte) 0x21, (byte) 0xe0, (byte) 0xea, (byte) 0x01,
				(byte) 0xd4, (byte) 0x2c, (byte) 0xa4, (byte) 0x16, (byte) 0x9e, (byte) 0x79, (byte) 0x18, (byte) 0xba,
				(byte) 0x0d };

		// Output value (from Python code)
		// 35156891815674817266734212754503633747128614016119564763269015315466259359304
		correct = new BigInteger("35156891815674817266734212754503633747128614016119564763269015315466259359304");

		res = decodeScalar(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		/* -- Test decodeUCoordinate -- */

		System.out.println("Test decodeUCoordinate");

		// Input value:
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
		input = new byte[] { (byte) 0xe5, (byte) 0x21, (byte) 0x0f, (byte) 0x12, (byte) 0x78, (byte) 0x68, (byte) 0x11,
				(byte) 0xd3, (byte) 0xf4, (byte) 0xb7, (byte) 0x95, (byte) 0x9d, (byte) 0x05, (byte) 0x38, (byte) 0xae,
				(byte) 0x2c, (byte) 0x31, (byte) 0xdb, (byte) 0xe7, (byte) 0x10, (byte) 0x6f, (byte) 0xc0, (byte) 0x3c,
				(byte) 0x3e, (byte) 0xfc, (byte) 0x4c, (byte) 0xd5, (byte) 0x49, (byte) 0xc7, (byte) 0x15, (byte) 0xa4,
				(byte) 0x93 };

		// Output value (from Python code)
		// 8883857351183929894090759386610649319417338800022198945255395922347792736741
		correct = new BigInteger("8883857351183929894090759386610649319417338800022198945255395922347792736741");

		res = decodeUCoordinate(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		// --

		// Input value:
		// 06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086
		input = new byte[] { (byte) 0x06, (byte) 0xfc, (byte) 0xe6, (byte) 0x40, (byte) 0xfa, (byte) 0x34, (byte) 0x87,
				(byte) 0xbf, (byte) 0xda, (byte) 0x5f, (byte) 0x6c, (byte) 0xf2, (byte) 0xd5, (byte) 0x26, (byte) 0x3f,
				(byte) 0x8a, (byte) 0xad, (byte) 0x88, (byte) 0x33, (byte) 0x4c, (byte) 0xbd, (byte) 0x07, (byte) 0x43,
				(byte) 0x7f, (byte) 0x02, (byte) 0x0f, (byte) 0x08, (byte) 0xf9, (byte) 0x81, (byte) 0x4d, (byte) 0xc0,
				(byte) 0x31, (byte) 0xdd, (byte) 0xbd, (byte) 0xc3, (byte) 0x8c, (byte) 0x19, (byte) 0xc6, (byte) 0xda,
				(byte) 0x25, (byte) 0x83, (byte) 0xfa, (byte) 0x54, (byte) 0x29, (byte) 0xdb, (byte) 0x94, (byte) 0xad,
				(byte) 0xa1, (byte) 0x8a, (byte) 0xa7, (byte) 0xa7, (byte) 0xfb, (byte) 0x4e, (byte) 0xf8, (byte) 0xa0,
				(byte) 0x86 };

		// Output value (from Python code)
		// 22503099155545401511747743372988183427981498984445290765916415810160808098822
		correct = new BigInteger("22503099155545401511747743372988183427981498984445290765916415810160808098822");

		res = decodeUCoordinate(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));

		/* -- Test encodeUCoordinate -- */

		System.out.println("Test encodeUCoordinate");

		// Input value:
		// 8883857351183929894090759386610649319417338800022198945255395922347792736741
		BigInteger inputInt = new BigInteger(
				"8883857351183929894090759386610649319417338800022198945255395922347792736741");

		// Output value (from Python code)
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413
		byte[] correctArray = new byte[] { (byte) 0xe5, (byte) 0x21, (byte) 0x0f, (byte) 0x12, (byte) 0x78, (byte) 0x68,
				(byte) 0x11, (byte) 0xd3, (byte) 0xf4, (byte) 0xb7, (byte) 0x95, (byte) 0x9d, (byte) 0x05, (byte) 0x38,
				(byte) 0xae, (byte) 0x2c, (byte) 0x31, (byte) 0xdb, (byte) 0xe7, (byte) 0x10, (byte) 0x6f, (byte) 0xc0,
				(byte) 0x3c, (byte) 0x3e, (byte) 0xfc, (byte) 0x4c, (byte) 0xd5, (byte) 0x49, (byte) 0xc7, (byte) 0x15,
				(byte) 0xa4, (byte) 0x13 };

		byte[] resArray = encodeUCoordinate(inputInt);

		System.out.println("Expected: " + Utils.bytesToHex(correctArray));
		System.out.println("Actual: " + Utils.bytesToHex(resArray));
		System.out.println("Same: " + Arrays.equals(correctArray, resArray));

		// --

		// Input value:
		// 5834050823475987305959238492374969056969794868074987349740858586932482375934
		inputInt = new BigInteger("5834050823475987305959238492374969056969794868074987349740858586932482375934");

		// Output value (from Python code)
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413
		correctArray = new byte[] { (byte) 0xfe, (byte) 0x80, (byte) 0x97, (byte) 0x47, (byte) 0xf0, (byte) 0x4e,
				(byte) 0x46, (byte) 0xf8, (byte) 0x35, (byte) 0xaa, (byte) 0x79, (byte) 0x60, (byte) 0xdc, (byte) 0x0d,
				(byte) 0xa8, (byte) 0x52, (byte) 0x1d, (byte) 0x4a, (byte) 0x68, (byte) 0x14, (byte) 0xd9, (byte) 0x0a,
				(byte) 0xca, (byte) 0x92, (byte) 0x5f, (byte) 0xa0, (byte) 0x85, (byte) 0xfa, (byte) 0xab, (byte) 0xf4,
				(byte) 0xe5, (byte) 0x0c };

		resArray = encodeUCoordinate(inputInt);

		System.out.println("Expected: " + Utils.bytesToHex(correctArray));
		System.out.println("Actual: " + Utils.bytesToHex(resArray));
		System.out.println("Same: " + Arrays.equals(correctArray, resArray));

		/* Test cswap */

		System.out.println("Test cswap");

		// First no swap

		BigInteger a_bi = new BigInteger(
				"8883857351183929894090759386610649319417338800022198945255395922347792736741");
		BigInteger b_bi = new BigInteger(
				"5834050823475987305959238492374969056969794868074987349740858586932482375934");

		BigIntegerFieldElement a = new BigIntegerFieldElement(ed25519Field, a_bi);
		BigIntegerFieldElement b = new BigIntegerFieldElement(ed25519Field, b_bi);

		BigInteger swap = BigInteger.ZERO;

		Tuple result = cswap(swap, a, b);
		System.out.println("Swap correct: " + result.a.equals(a) + " and " + result.b.equals(b));

		// Now do swap

		swap = BigInteger.ONE;
		result = cswap(swap, a, b);
		System.out.println("Swap correct: " + result.a.equals(b) + " and " + result.b.equals(a));

		/* Test X25519 */

		System.out.println("Test X25519");

		byte[] k = new byte[] { (byte) 0xa5, (byte) 0x46, (byte) 0xe3, (byte) 0x6b, (byte) 0xf0, (byte) 0x52,
				(byte) 0x7c, (byte) 0x9d, (byte) 0x3b, (byte) 0x16, (byte) 0x15, (byte) 0x4b, (byte) 0x82, (byte) 0x46,
				(byte) 0x5e, (byte) 0xdd, (byte) 0x62, (byte) 0x14, (byte) 0x4c, (byte) 0x0a, (byte) 0xc1, (byte) 0xfc,
				(byte) 0x5a, (byte) 0x18, (byte) 0x50, (byte) 0x6a, (byte) 0x22, (byte) 0x44, (byte) 0xba, (byte) 0x44,
				(byte) 0x9a, (byte) 0xc4 };
		byte[] u = new byte[] { (byte) 0xe6, (byte) 0xdb, (byte) 0x68, (byte) 0x67, (byte) 0x58, (byte) 0x30,
				(byte) 0x30, (byte) 0xdb, (byte) 0x35, (byte) 0x94, (byte) 0xc1, (byte) 0xa4, (byte) 0x24, (byte) 0xb1,
				(byte) 0x5f, (byte) 0x7c, (byte) 0x72, (byte) 0x66, (byte) 0x24, (byte) 0xec, (byte) 0x26, (byte) 0xb3,
				(byte) 0x35, (byte) 0x3b, (byte) 0x10, (byte) 0xa9, (byte) 0x03, (byte) 0xa6, (byte) 0xd0, (byte) 0xab,
				(byte) 0x1c, (byte) 0x4c };
		byte[] c = new byte[] { (byte) 0xc3, (byte) 0xda, (byte) 0x55, (byte) 0x37, (byte) 0x9d, (byte) 0xe9,
				(byte) 0xc6, (byte) 0x90, (byte) 0x8e, (byte) 0x94, (byte) 0xea, (byte) 0x4d, (byte) 0xf2, (byte) 0x8d,
				(byte) 0x08, (byte) 0x4f, (byte) 0x32, (byte) 0xec, (byte) 0xcf, (byte) 0x03, (byte) 0x49, (byte) 0x1c,
				(byte) 0x71, (byte) 0xf7, (byte) 0x54, (byte) 0xb4, (byte) 0x07, (byte) 0x55, (byte) 0x77, (byte) 0xa2,
				(byte) 0x85, (byte) 0x52 };

		byte[] xresult = X25519(k, u);

		System.out.println("R: " + Utils.bytesToHex(xresult));
		System.out.println("X25519 result is correct: " + Arrays.equals(c, xresult));

		/* Test X25519 test vectors */
		// See https://tools.ietf.org/html/rfc7748#section-5.2

		System.out.println("Test X25519 test vectors");

		// First X25519 test vector

		byte[] inputScalar = StringUtil
				.hex2ByteArray("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
		byte[] inputUCoordinate = StringUtil
				.hex2ByteArray("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
		byte[] outputUCoordinate = StringUtil
				.hex2ByteArray("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

		byte[] myResult = X25519(inputScalar, inputUCoordinate);
		System.out.println("First test vector works: " + Arrays.equals(myResult, outputUCoordinate));

		// Second X25519 test vector

		inputScalar = StringUtil.hex2ByteArray("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
		inputUCoordinate = StringUtil.hex2ByteArray("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
		outputUCoordinate = StringUtil
				.hex2ByteArray("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

		myResult = X25519(inputScalar, inputUCoordinate);
		System.out.println("Second test vector works: " + Arrays.equals(myResult, outputUCoordinate));

		// Third X25519 test vector (iterations)
		inputScalar = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		inputUCoordinate = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] resultIteration1 = StringUtil
				.hex2ByteArray("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

		byte[] myResult_1 = X25519(inputScalar, inputUCoordinate);
		System.out.println("Third test vector works (1 iteration): " + Arrays.equals(myResult_1, resultIteration1));

		// 1000 iterations

		byte[] tU = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] tK = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] tR = null;
		for (int i = 0; i < 1000; i++) {

			tR = X25519(tK.clone(), tU.clone()).clone();
			tU = tK;
			tK = tR;

		}

		byte[] resultIteration1000 = StringUtil
				.hex2ByteArray("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
		byte[] myResult_1000 = tK;

		System.out.println(
				"Third test vector works (1000 iterations): " + Arrays.equals(myResult_1000, resultIteration1000));

		// 1 000 000 iterations
		// Takes a very long time ~45 minutes

		boolean runMillionTest = false;

		if (runMillionTest) {

			tU = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
			tK = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
			tR = null;
			long startTime = System.nanoTime();
			for (int i = 0; i < 1000000; i++) {

				tR = X25519(tK, tU);
				tU = tK;
				tK = tR;

				if (i % 20000 == 0) {
					long timeElapsed = System.nanoTime() - startTime;
					System.out.println("Iteration: " + i + ". Time: " + timeElapsed / 1000000 / 1000 + " seconds");
				}
			}

			byte[] resultIteration1000000 = StringUtil
					.hex2ByteArray("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
			byte[] myResult_1000000 = tK;

			System.out.println("Third test vector works (1 000 000 iterations): "
					+ Arrays.equals(myResult_1000000, resultIteration1000000));
		}

		/* Test Diffie Hellman */
		// See https://tools.ietf.org/html/rfc7748#section-6.1

		byte[] private_key_a = StringUtil
				.hex2ByteArray("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
		byte[] public_key_KA = StringUtil
				.hex2ByteArray("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

		byte[] private_key_b = StringUtil
				.hex2ByteArray("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
		byte[] public_key_KB = StringUtil
				.hex2ByteArray("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

		byte[] nine = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");

		// Check public keys
		byte[] public_key_KA_calc = X25519(private_key_a, nine);
		byte[] public_key_KB_calc = X25519(private_key_b, nine);

		System.out.println("Public Key KA correct: " + Arrays.equals(public_key_KA_calc, public_key_KA));
		System.out.println("Public Key KB correct: " + Arrays.equals(public_key_KB_calc, public_key_KB));

		byte[] sharedSecret = StringUtil
				.hex2ByteArray("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

		// Check shared secret
		byte[] sharedSecret_calc_one = X25519(private_key_a, public_key_KB);
		byte[] sharedSecret_calc_two = X25519(private_key_b, public_key_KA);

		System.out.println(
				"Shared secret matches each other: " + Arrays.equals(sharedSecret_calc_one, sharedSecret_calc_two));
		System.out
				.println("Shared secret matches correct value: " + Arrays.equals(sharedSecret_calc_one, sharedSecret));

		/* Test starting from COSE Keys */

		/*
		 * Key section:
		 * 
		 * Ed25519 keys start life as a 32-byte (256-bit) uniformly random
		 * binary seed (e.g. the output of SHA256 on some random input). The
		 * seed is then hashed using SHA512, which gets you 64 bytes (512 bits),
		 * which is then split into a "left half" (the first 32 bytes) and a
		 * "right half". The left half is massaged into a curve25519 private
		 * scalar "a" by setting and clearing a few high/low-order bits.
		 * 
		 * https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
		 */

		System.out.println("Test starting from COSE Keys");

		// Key one

		OneKey myKey1 = OneKey.generateKey(AlgorithmID.EDDSA);

		// Get u coordinate from public key
		FieldElement y_fromKey1 = KeyRemapping.extractCOSE_y(myKey1);
		FieldElement uuu1 = KeyRemapping.calcCurve25519_u(y_fromKey1);
		byte[] publicKey1U = uuu1.toByteArray();

		// Get private scalar (from private key)
		// byte[] privateKey1 = myKey1.get(KeyKeys.OKP_D).GetByteString();
		byte[] privateKey1H = ((EdDSAPrivateKey) myKey1.AsPrivateKey()).getH();
		privateKey1H = Arrays.copyOf(privateKey1H, 32);

		System.out.println("H priv1: " + Utils.bytesToHex(privateKey1H));
		System.out.println("u from key one (public part): " + uuu1);
		// System.out.println("From key one (private part): " +
		// Utils.bytesToHex(privateKey1));

		// Key two

		OneKey myKey2 = OneKey.generateKey(AlgorithmID.EDDSA);

		// Get u coordinate from public key
		FieldElement y_fromKey2 = KeyRemapping.extractCOSE_y(myKey2);
		FieldElement uuu2 = KeyRemapping.calcCurve25519_u(y_fromKey2);
		byte[] publicKey2U = uuu2.toByteArray();

		// Get private scalar (from private key)
		// byte[] privateKey2 = myKey2.get(KeyKeys.OKP_D).GetByteString();
		byte[] privateKey2H = ((EdDSAPrivateKey) myKey2.AsPrivateKey()).getH();
		privateKey2H = Arrays.copyOf(privateKey2H, 32);

		System.out.println("H priv2: " + Utils.bytesToHex(privateKey2H));
		System.out.println("u from key two (public part): " + uuu2);
		// System.out.println("From key two (private part): " +
		// Utils.bytesToHex(privateKey2));

		// Calculated shared secrets
		// X25519(my private scalar, your public key U)
		byte[] sharedSecret1 = X25519(privateKey1H, publicKey2U);
		byte[] sharedSecret2 = X25519(privateKey2H, publicKey1U);

		System.out.println("Shared secret 1: " + Utils.bytesToHex(sharedSecret1));
		System.out.println("Shared secret 2: " + Utils.bytesToHex(sharedSecret2));
		System.out.println("Shared secrets match: " + Arrays.equals(sharedSecret1, sharedSecret2));

		/* End testing */

		sharedSecretTest();

		System.out.println("Testing finished");

		// --

	}

	/**
	 * Calculate the shared secret from a COSE OneKey using EdDSA. It is first
	 * converted to Montgomery coordinates and after that the X25519 function is
	 * used to perform the shared secret calculation.
	 * 
	 * @param publicKey the public key (of the other party)
	 * @param privateKey the private key (your own)
	 * @return the shared secret calculated
	 * @throws CoseException on failure
	 */
	public static byte[] calculateSharedSecret(OneKey publicKey, OneKey privateKey) throws CoseException {

		/* Calculate u coordinate from public key */

		FieldElement public_y = KeyRemapping.extractCOSE_y(publicKey);
		FieldElement public_u = KeyRemapping.calcCurve25519_u(public_y);
		byte[] public_u_array = public_u.toByteArray();

		/* Get private scalar from private key */

		byte[] private_hash = ((EdDSAPrivateKey) privateKey.AsPrivateKey()).getH();
		byte[] private_scalar = Arrays.copyOf(private_hash, 32);

		/* -- Calculated shared secret -- */
		// secret = X25519(my private scalar, your public key U)

		byte[] sharedSecret = X25519(private_scalar, public_u_array);

		return sharedSecret;
	}

	private static void sharedSecretTest() throws CoseException {

		/* -- Key one (Bob) -- */

		OneKey BobKey = OneKey.generateKey(AlgorithmID.EDDSA);

		// Calculate u coordinate from Bob's public key
		FieldElement bob_y = KeyRemapping.extractCOSE_y(BobKey);
		FieldElement bob_u = KeyRemapping.calcCurve25519_u(bob_y);
		byte[] bob_u_array = bob_u.toByteArray();

		// Get private scalar (from Bob's private key)
		byte[] bob_hash = ((EdDSAPrivateKey) BobKey.AsPrivateKey()).getH();
		byte[] bob_private_scalar = Arrays.copyOf(bob_hash, 32); // Left half

		/* -- Key two (Alice) -- */

		OneKey AliceKey = OneKey.generateKey(AlgorithmID.EDDSA);

		// Calculate u coordinate from Alice's public key
		FieldElement alice_y = KeyRemapping.extractCOSE_y(AliceKey);
		FieldElement alice_u = KeyRemapping.calcCurve25519_u(alice_y);
		byte[] alice_u_array = alice_u.toByteArray();

		// Get private scalar (from Alice's private key)
		byte[] alice_hash = ((EdDSAPrivateKey) AliceKey.AsPrivateKey()).getH();
		byte[] alice_private_scalar = Arrays.copyOf(alice_hash, 32);

		/* -- Calculated shared secrets -- */
		// secret = X25519(my private scalar, your public key U)

		byte[] sharedSecret1 = X25519(bob_private_scalar, alice_u_array);
		byte[] sharedSecret2 = X25519(alice_private_scalar, bob_u_array);

		System.out.println("Shared secret 1: " + Utils.bytesToHex(sharedSecret1));
		System.out.println("Shared secret 2: " + Utils.bytesToHex(sharedSecret2));
		System.out.println("Shared secrets match: " + Arrays.equals(sharedSecret1, sharedSecret2));

	}

	static byte[] X25519(byte[] k, byte[] u) {

		k = k.clone(); // Needed?
		u = u.clone(); // Needed?

		BigInteger kn = decodeScalar(k);
		BigInteger un = decodeUCoordinate(u);

		BigIntegerFieldElement kn_bif = new BigIntegerFieldElement(ed25519Field, kn);
		BigIntegerFieldElement un_bif = new BigIntegerFieldElement(ed25519Field, un);

		FieldElement res = X25519_calculate(kn_bif, un_bif);

		BigInteger res_bi = new BigInteger(invertArray(res.toByteArray()));

		return encodeUCoordinate(res_bi);

	}

	// Skips decoding the scalar k
	// Since it may not be encoded in the first place
	// But in the end it seems decoding multiple times changes nothing
	@SuppressWarnings("unused")
	private static byte[] X25519_noDecodeScalar(byte[] k, byte[] u) {

		k = k.clone(); // Needed?
		u = u.clone(); // Needed?

		BigInteger kn = decodeLittleEndian(k, 255);
		BigInteger un = decodeUCoordinate(u);

		BigIntegerFieldElement kn_bif = new BigIntegerFieldElement(ed25519Field, kn);
		BigIntegerFieldElement un_bif = new BigIntegerFieldElement(ed25519Field, un);

		FieldElement res = X25519_calculate(kn_bif, un_bif);

		BigInteger res_bi = new BigInteger(invertArray(res.toByteArray()));

		return encodeUCoordinate(res_bi);

	}

	/**
	 * Implements the XX25519 function.
	 * 
	 * See https://tools.ietf.org/html/rfc7748#section-5
	 */
	private static FieldElement X25519_calculate(FieldElement k, FieldElement u) {

		// Set bits
		// https://tools.ietf.org/html/rfc7748#page-7
		int bits = 255;

		// Initialize starting values
		FieldElement x_1 = u;
		FieldElement x_2 = new BigIntegerFieldElement(ed25519Field, new BigInteger("1"));

		FieldElement z_2 = new BigIntegerFieldElement(ed25519Field, new BigInteger("0"));

		FieldElement x_3 = u;
		FieldElement z_3 = new BigIntegerFieldElement(ed25519Field, new BigInteger("1"));

		BigInteger swap = new BigInteger("0");

		// https://tools.ietf.org/html/rfc7748#page-8
		FieldElement a24 = new BigIntegerFieldElement(ed25519Field, new BigInteger("121665"));

		// Uninitialized variables used in loop

		FieldElement A;
		FieldElement AA;
		FieldElement B;
		FieldElement BB;
		FieldElement E;
		FieldElement C;
		FieldElement D;
		FieldElement DA;
		FieldElement CB;

		// For loop here
		for (int t = bits - 1; t >= 0; t--) {

			// Swap step

			BigInteger k_bi = new BigInteger(invertArray(k.toByteArray()));
			// k_t = (k >> t) & 1
			BigInteger k_t = (k_bi.shiftRight(t)).and(BigInteger.ONE);

			swap = swap.xor(k_t); // swap ^= k_t

			// Swapping
			Tuple result = cswap(swap, x_2, x_3);
			x_2 = result.a;
			x_3 = result.b;
			// End swapping

			// Swapping
			Tuple result2 = cswap(swap, z_2, z_3);
			z_2 = result2.a;
			z_3 = result2.b;
			// End swapping

			swap = k_t; // swap = k_t

			// Calculation step

			A = x_2.add(z_2); // A = x_2 + z_2

			AA = A.multiply(A); // AA = A^2

			B = x_2.subtract(z_2); // B = x_2 - z_2

			BB = B.multiply(B); // B = B^2

			E = AA.subtract(BB); // E = AA - BB

			C = x_3.add(z_3); // C = x_3 + z_3

			D = x_3.subtract(z_3); // D = x_3 - z_3

			DA = D.multiply(A); // DA = D * A

			CB = C.multiply(B); // CB = C * B

			FieldElement DA_a_CB = DA.add(CB);
			x_3 = DA_a_CB.multiply(DA_a_CB); // x_3 = (DA + CB)^2

			FieldElement DA_s_CB = DA.subtract(CB);
			FieldElement DA_s_CB__x__DA_s_CB = DA_s_CB.multiply(DA_s_CB);
			z_3 = x_1.multiply(DA_s_CB__x__DA_s_CB); // z_3 = x_1 * (DA - CB)^2

			x_2 = AA.multiply(BB); // x_2 = AA * BB

			FieldElement a24_x_E = a24.multiply(E);
			FieldElement AA__a__a24_x_E = AA.add(a24_x_E);
			z_2 = E.multiply(AA__a__a24_x_E); // z_2 = E * (AA + a24 * E)
		}

		// Final swap step

		// Swapping
		Tuple result = cswap(swap, x_2, x_3);
		x_2 = result.a;
		x_3 = result.b;
		// End swapping

		// Swapping
		Tuple result2 = cswap(swap, z_2, z_3);
		z_2 = result2.a;
		z_3 = result2.b;
		// End swapping

		// Return step

		// Calculate p
		BigInteger pow = new BigInteger("2").pow(255);
		BigInteger p_bi = pow.subtract(new BigInteger("19"));
		FieldElement p = new BigIntegerFieldElement(ed25519Field, p_bi);

		// Calculate p minus 2
		FieldElement p_s_2 = p.subtractOne().subtractOne();

		// Calculate z_2^(p - 2)
		BigInteger z_2_bi = new BigInteger(invertArray(z_2.toByteArray()));
		BigIntegerFieldElement z_2_bif = new BigIntegerFieldElement(ed25519Field, z_2_bi);
		FieldElement val = z_2_bif.pow(p_s_2);

		// Calculate return vale
		FieldElement ret = x_2.multiply(val);

		return ret;

	}

	static BigInteger decodeLittleEndian(byte[] b, int bits) {

		byte[] cutArray = Arrays.copyOf(b, (bits + 7) / 8);

		BigInteger res = new BigInteger(1, invertArray(cutArray));

		return res;

	}

	static BigInteger decodeScalar(byte[] b) {

		b[0] &= 248;
		b[31] &= 127;
		b[31] |= 64;

		return decodeLittleEndian(b, 255);

	}

	static BigInteger decodeUCoordinate(byte[] u) {

		int bits = 255;

		for (int i = 0; i < u.length; i++) {
			if ((u[i] % 8) != 0) {
				u[u.length - 1] &= (1 << (bits % 8)) - 1;
			}
		}

		return decodeLittleEndian(u, bits);
	}

	// TODO: Optimize
	static byte[] encodeUCoordinate(BigInteger u) {

		int bits = 255;

		BigInteger pow = new BigInteger("2").pow(255);
		BigInteger p_bi = pow.subtract(new BigInteger("19"));

		u = u.mod(p_bi); // u = u % p

		byte[] res = new byte[(bits + 7) / 8];

		for (int i = 0; i < ((bits + 7) / 8); i++) {
			BigInteger temp = u.shiftRight(8 * i);
			byte[] temp2 = temp.toByteArray();

			res[i] = temp2[temp2.length - 1];
		}

		return res;
	}

	// TODO: Do I really need to make new objects?
	static class Tuple {

		public FieldElement a;
		public FieldElement b;

		Tuple(FieldElement a, FieldElement b) {

			BigInteger a_bi = new BigInteger(invertArray(a.toByteArray()));
			BigInteger b_bi = new BigInteger(invertArray(b.toByteArray()));

			this.a = new BigIntegerFieldElement(ed25519Field, a_bi);
			this.b = new BigIntegerFieldElement(ed25519Field, b_bi);
		}

	}

	/**
	 * Potentially swaps values of two FieldElements. Will swap values if the
	 * BigInteger swap equals 1.
	 * 
	 * @return the original or swapped Tuple depending on the input value of
	 *         swap
	 */
	static Tuple cswap(BigInteger swap, FieldElement a, FieldElement b) {

		byte[] aBytes = a.toByteArray();
		byte[] bBytes = b.toByteArray();

		byte[] mask = new byte[aBytes.length];
		byte[] dummy = new byte[aBytes.length];

		byte[] swapBytes = swap.toByteArray();
		byte swapValue = (byte) (-swapBytes[0]);
		Arrays.fill(mask, swapValue);
		
		for (int i = 0; i < aBytes.length; i++) {
			dummy[i] = (byte) (mask[i] & (aBytes[i] ^ bBytes[i]));
			aBytes[i] ^= dummy[i];
			bBytes[i] ^= dummy[i];
		}

		FieldElement newA = new BigIntegerFieldElement(ed25519Field, new BigInteger(invertArray(aBytes)));
		FieldElement newB = new BigIntegerFieldElement(ed25519Field, new BigInteger(invertArray(bBytes)));

		return new Tuple(newA, newB);
	}

	/**
	 * Invert a byte array
	 * 
	 * Needed to handle endianness
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
