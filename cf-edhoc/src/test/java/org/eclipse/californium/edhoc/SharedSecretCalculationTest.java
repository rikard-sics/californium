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

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.edhoc.SharedSecretCalculation.Tuple;
import org.eclipse.californium.elements.util.Base64;
import org.eclipse.californium.elements.util.StringUtil;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerFieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerLittleEndianEncoding;

/**
 * Tests for calculating a shared secret using X25519.
 *
 */
public class SharedSecretCalculationTest {

	/*
	 * Useful links:
	 * 
	 * https://crypto.stackexchange.com/questions/63732/curve-25519-x25519-
	 * ed25519-convert-coordinates-between-montgomery-curve-and-t/63734
	 * https://tools.ietf.org/html/rfc7748
	 * 
	 * https://tools.ietf.org/html/rfc8032 https://github.com/bifurcation/fourq
	 * https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
	 * https://www.tfzx.net/article/10082730.html
	 * 
	 * https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/
	 * bouncycastle/math/ec/rfc7748/test/X25519Test.java
	 * 
	 * https://tools.ietf.org/html/draft-ietf-lake-edhoc-02
	 * https://tools.ietf.org/html/rfc7748
	 * 
	 */

	// Create the ed25519 field
	private static Field ed25519Field = new Field(256, // b
			StringUtil.hex2ByteArray("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q(2^255-19)
			new BigIntegerLittleEndianEncoding());

	// Use the OSCORE stack factory with the client context DB
	@BeforeClass
	public static void setStackFactory() {
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
	}
	
	/**
	 * Test generation of Curve25519 key.
	 */
	@Test
	public void testGenerateCurve25519Key()
	{
		OneKey key = SharedSecretCalculation.generateCurve25519KeyTest();
		
		// Assert valid key
		Assert.assertNotNull(key);
		Assert.assertEquals(KeyKeys.OKP_X25519, key.get(KeyKeys.OKP_Curve));
	}

	/**
	 * Tests conversion of Ed25519 to Curve25519 key.
	 */
	@Test
	public void testConvertEd25519ToCurve25519() throws CoseException {
		OneKey outKey = SharedSecretCalculation.convertEd25519ToCurve25519(OneKey.generateKey(AlgorithmID.EDDSA));
		
		// Assert valid key
		Assert.assertNotNull(outKey);
		Assert.assertEquals(KeyKeys.OKP_X25519, outKey.get(KeyKeys.OKP_Curve));
	}
	
	/**
	 * Initial testing of calculating ECDSA_256 Y parameter from X.
	 * 
	 * @throws CoseException on test failure
	 * @throws IOException on test failure
	 */
	@Test
    @Deprecated
	public void testEcdsaYFromX() throws CoseException, IOException {
		OneKey ecdd = OneKey.generateKey((AlgorithmID.ECDSA_256));
		System.out.println(StringUtil.byteArray2HexString(ecdd.AsPublicKey().getEncoded()));

		OneKey rebuilt = SharedSecretCalculation.buildEcdsa256OneKey(ecdd.get(KeyKeys.OKP_D).GetByteString(),
				ecdd.get(KeyKeys.EC2_X).GetByteString(), ecdd.get(KeyKeys.EC2_Y).GetByteString());

		System.out.println("HELLO");

		SharedSecretCalculation.generateSharedSecret(ecdd, rebuilt);

		// https://crypto.stackexchange.com/questions/8914/ecdsa-compressed-public-key-point-back-to-uncompressed-public-key-point
		// https://asecuritysite.com/encryption/js08
		// https://bitcoin.stackexchange.com/questions/44024/get-uncompressed-public-key-from-compressed-form
		// http://www-cs-students.stanford.edu/~tjw/jsbn/ecdh.html
		// https://tools.ietf.org/html/rfc6090#appendix-C
		// jdk.crypto.ec/sun.security.ec.ECDHKeyAgreement

		// Testing with Curve base point
		BigInteger x = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);


		// secp256r1
		// y^2 = x^3 + ax + b -> y = +- sqrt(a x + b + x^3)
		BigInteger prime = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
		BigInteger A = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
		BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
		BigInteger three = new BigInteger("3");

		// p == 3 mod 4?
		// https://math.stackexchange.com/questions/464253/square-roots-in-finite-fields-i-e-mod-pm
		BigInteger primeMod4 = prime.mod(new BigInteger("4"));
		System.out.println("p == 3 mod 4: " + primeMod4);

		x = x.mod(prime);
		BigInteger xPow3 = x.modPow(three, prime);
		BigInteger ax = (A.multiply(x)).mod(prime);
		//BigInteger combined = (ax.add(B).add(xPow3)).mod(prime);
		BigInteger partial = ax.add(B).mod(prime);
		BigInteger combined = partial.add(xPow3).mod(prime);
		

		BigInteger root1 = squareMod(combined).mod(prime);
		BigInteger root2 = root1.negate().mod(prime);

		System.out.println("Root1: " + root1);
		System.out.println("Root1: " + StringUtil.byteArray2HexString(root1.toByteArray()));
		System.out.println("Root2: " + root2);
		System.out.println("Root2: " + StringUtil.byteArray2HexString(root2.toByteArray()));

		// Check roots
		System.out.println("Expected: " + combined);
		System.out.println("root1^2 " + root1.multiply(root1).mod(prime));
		System.out.println("root2^2 " + root2.multiply(root2).mod(prime));

		// Check if on point
		// http://hg.openjdk.java.net/jdk/jdk/rev/752e57845ad2#l1.97
		BigInteger rhs = x.modPow(BigInteger.valueOf(3), prime).add(A.multiply(x)).add(B).mod(prime);
		BigInteger lhs1 = root1.modPow(BigInteger.valueOf(2), prime).mod(prime);
		BigInteger lhs2 = root2.modPow(BigInteger.valueOf(2), prime).mod(prime);
		System.out.println("RHS  " + rhs);
		System.out.println("LHS1 " + lhs1);
		System.out.println("LHS2 " + lhs2);

		// Now build keys and try shared secret calc
		String keyPairBase64 = "pgMmAQIgASFYIPWSTdB9SCF/+CGXpy7gty8qipdR30t6HgdFGQo8ViiAIlggXvJCtXVXBJwmjMa4YdRbcdgjpXqM57S2CZENPrUGQnMjWCDXCb+hy1ybUu18KTAJMvjsmXch4W3Hd7Rw7mTF3ocbLQ==";
		OneKey privateKey = new OneKey(CBORObject.DecodeFromBytes(Base64.decode(keyPairBase64)));
		OneKey publicFirstY = SharedSecretCalculation.buildEcdsa256OneKey(null, x.toByteArray(), root1.toByteArray());
		OneKey publicSecondY = SharedSecretCalculation.buildEcdsa256OneKey(null, x.toByteArray(), root2.toByteArray());
		System.out.println("publicFirstY " + publicFirstY.AsCBOR().toString());
		System.out.println("publicSecondY " + publicSecondY.AsCBOR().toString());

		// Check if on point (other way) (first y)
		// jdk.crypto.ec/sun.security.ec.ECDHKeyAgreement
		ECPublicKey _key = (ECPublicKey) publicFirstY.AsPublicKey();
		BigInteger _x = _key.getW().getAffineX();
		System.out.println("First Y Affine X: " + StringUtil.byteArray2HexString(_x.toByteArray()));
		BigInteger _y = _key.getW().getAffineY();
		System.out.println("First Y Affine Y: " + StringUtil.byteArray2HexString(_y.toByteArray()));
		BigInteger _p = prime;
		EllipticCurve curve = _key.getParams().getCurve();
		BigInteger _rhs = _x.modPow(BigInteger.valueOf(3), _p).add(curve.getA().multiply(x)).add(curve.getB()).mod(_p);
		BigInteger _lhs = _y.modPow(BigInteger.valueOf(2), _p).mod(_p);
		if (!_rhs.equals(_lhs)) {
			System.out.println("Key using first Y not on curve!");
		}
		// Check if on point (other way) (second y)
		_key = (ECPublicKey) publicSecondY.AsPublicKey();
		_x = _key.getW().getAffineX();
		System.out.println("Second Y Affine X: " + StringUtil.byteArray2HexString(_x.toByteArray()));
		_y = _key.getW().getAffineY();
		System.out.println("Second Y Affine X: " + StringUtil.byteArray2HexString(_y.toByteArray()));
		_p = prime;
		curve = _key.getParams().getCurve();
		_rhs = _x.modPow(BigInteger.valueOf(3), _p).add(curve.getA().multiply(x)).add(curve.getB()).mod(_p);
		_lhs = _y.modPow(BigInteger.valueOf(2), _p).mod(_p);
		if (!_rhs.equals(_lhs)) {
			System.out.println("Key using second Y not on curve!");
		}

		byte[] secret1 = null;
		try {
			secret1 = SharedSecretCalculation.generateSharedSecret(privateKey, publicFirstY);
		} catch (Exception e) {
			System.out.println("Shared secret 1 generation failed: " + e);
		}
		byte[] secret2 = null;
		try {
			secret2 = SharedSecretCalculation.generateSharedSecret(privateKey, publicSecondY);
		} catch (Exception e) {
			System.out.println("Shared secret 2 generation failed: " + e);
		}

		System.out.println("Secret 1 " + StringUtil.byteArray2HexString(secret1));
		System.out.println("Secret 2 " + StringUtil.byteArray2HexString(secret2));

	}

	/**
	 * Square root in prime field. Only works if p == 3 mod 4
	 * 
	 * @param val value to take root of
	 * @return one of the roots
	 */
	BigInteger squareMod(BigInteger val) {
		// root = val^((prime+1) / 4)
		BigInteger prime = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
		BigInteger power = prime.add(BigInteger.ONE).divide(new BigInteger("4"));

		return val.modPow(power, prime);

	}

	@Test
	@Ignore
	public void testCalculateEcdsaYFromXOld() throws CoseException {
		BigInteger x = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
		byte[] y = SharedSecretCalculation.recomputeEcdsa256YFromX(x.toByteArray(), true);

		BigInteger expectedY = new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);

		System.out.println("Y " + StringUtil.byteArray2HexString(y));
		System.out.println("Expected Y " + StringUtil.byteArray2HexString(expectedY.toByteArray()));

		Assert.assertArrayEquals(expectedY.toByteArray(), y);

		//
		x = new BigInteger("a2339c12d4a03c33546de533268b4ad667debf458b464d77443636440ee7fec3", 16);
		y = SharedSecretCalculation.recomputeEcdsa256YFromX(x.toByteArray(), true);

		expectedY = new BigInteger("ef48a3ab26e20220bcda2c1851076839dae88eae962869a497bf73cb66faf536", 16);

		System.out.println("Y " + StringUtil.byteArray2HexString(y));
		System.out.println("Expected Y " + StringUtil.byteArray2HexString(expectedY.toByteArray()));

		Assert.assertArrayEquals(expectedY.toByteArray(), y);

	}

	@Test
	// https://github.com/conz27/crypto-test-vectors/blob/master/ecdh.py
	public void testCalculateEcdsaYFromX() throws CoseException {

		//
		BigInteger x = new BigInteger(
				StringUtil.hex2ByteArray("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
		byte[] y = SharedSecretCalculation.recomputeEcdsa256YFromX(x.toByteArray(), true);


		BigInteger expectedY = new BigInteger(
				StringUtil.hex2ByteArray("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));

		System.out.println("Y " + StringUtil.byteArray2HexString(y));
		System.out.println("Expected Y " + StringUtil.byteArray2HexString(expectedY.toByteArray()));

		Assert.assertArrayEquals(expectedY.toByteArray(), y);

		//
		x = new BigInteger(StringUtil.hex2ByteArray("a2339c12d4a03c33546de533268b4ad667debf458b464d77443636440ee7fec3"));
		y = SharedSecretCalculation.recomputeEcdsa256YFromX(x.toByteArray(), false);

		expectedY = new BigInteger(
				StringUtil.hex2ByteArray("ef48a3ab26e20220bcda2c1851076839dae88eae962869a497bf73cb66faf536"));

		System.out.println("Y " + StringUtil.byteArray2HexString(y));
		System.out.println("Expected Y " + StringUtil.byteArray2HexString(expectedY.toByteArray()));

		Assert.assertArrayEquals(expectedY.toByteArray(), y);

		//
		x = new BigInteger(StringUtil.hex2ByteArray("a28a2edf58025668f724aaf83a50956b7ac1cfbbff79b08c3bf87dfd2828d767"));
		y = SharedSecretCalculation.recomputeEcdsa256YFromX(x.toByteArray(), true);

		expectedY = new BigInteger(
				StringUtil.hex2ByteArray("dfa7bfffd4c766b86abeaf5c99b6e50cb9ccc9d9d00b7ffc7804b0491b67bc03"));

		System.out.println("Y " + StringUtil.byteArray2HexString(y));
		System.out.println("Expected Y " + StringUtil.byteArray2HexString(expectedY.toByteArray()));

		Assert.assertArrayEquals(expectedY.toByteArray(), y);

		// This test fails but that is because the other possibly Y is found
		x = new BigInteger(StringUtil.hex2ByteArray("7c9e950841d26c8dde8994398b8f5d475a022bc63de7773fcf8d552e01f1ba0a"));
		y = SharedSecretCalculation.recomputeEcdsa256YFromX(x.toByteArray(), true);

		expectedY = new BigInteger(
				StringUtil.hex2ByteArray("cc42b9885c9b3bee0f8d8c57d3a8f6355016c019c4062fa22cff2f209b5cc2e1"));

		System.out.println("Y " + StringUtil.byteArray2HexString(y));
		System.out.println("Expected Y " + StringUtil.byteArray2HexString(expectedY.toByteArray()));

		Assert.assertArrayEquals(expectedY.toByteArray(), y);

	}

	@Test
	public void testCalculateEcdsa384YFromX() throws CoseException {
		OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_384);

		byte[] x1 = key.get(KeyKeys.EC2_X).GetByteString();
		byte[] y_correct = key.get(KeyKeys.EC2_Y).GetByteString();
		byte[] y_first = SharedSecretCalculation.recomputeEcdsa384YFromX(x1, false);
		byte[] y_second = SharedSecretCalculation.recomputeEcdsa384YFromX(x1, true);

		System.out.println("Calculated Y: " + StringUtil.byteArray2HexString(y_first));
		System.out.println("Calculated Y: " + StringUtil.byteArray2HexString(y_second));
		System.out.println("Real Y: " + StringUtil.byteArray2HexString(y_correct));
		System.out.println("Real X: " + StringUtil.byteArray2HexString(x1));

		if (!Arrays.equals(y_first, y_correct) && !Arrays.equals(y_second, y_correct)) {
			Assert.fail("None of the calculated Y values matched expected Y");
		}

		//
		BigInteger x = new BigInteger(StringUtil.hex2ByteArray(
				"c33dff8fb15eeda94a2563b78180cdc6bf75a413668c0b33895e16140e5046fb8854ba1826dc9994d793853476176e21"));
		byte[] y = SharedSecretCalculation.recomputeEcdsa384YFromX(x.toByteArray(), true);

		BigInteger expectedY = new BigInteger(StringUtil.hex2ByteArray(
				"ef79a67b67c5c71b68603f7e319f6579ff7fa17b7277fba2bcae08829a0c90b1bf178170087d0fed7236bad69acb6f5b"));

		System.out.println("Y " + StringUtil.byteArray2HexString(y));
		System.out.println("Expected Y " + StringUtil.byteArray2HexString(expectedY.toByteArray()));

		Assert.assertArrayEquals(expectedY.toByteArray(), y);

	}

	/**
	 * Tests calculating a shared secret based on 2 different public keys where
	 * their Y values are different (but still correct for the X value.)
	 */
	@Test
	public void sharedSecretSameXDifferentY() {
		byte[] publicX = StringUtil.hex2ByteArray("7c9e950841d26c8dde8994398b8f5d475a022bc63de7773fcf8d552e01f1ba0a");
		byte[] publicY1 = StringUtil.hex2ByteArray("33bd4676a364c412f07273a82c5709caafe93fe73bf9d05dd300d0df64a33d1e");
		byte[] publicY2 = StringUtil.hex2ByteArray("cc42b9885c9b3bee0f8d8c57d3a8f6355016c019c4062fa22cff2f209b5cc2e1");

		OneKey publicKeyY1 = SharedSecretCalculation.buildEcdsa256OneKey(null,
				publicX, publicY1);
		OneKey publicKeyY2 = SharedSecretCalculation.buildEcdsa256OneKey(null,
				publicX, publicY2);

		OneKey privateKey = SharedSecretCalculation.buildEcdsa256OneKey(
				StringUtil.hex2ByteArray("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"),
				StringUtil.hex2ByteArray("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"),
				StringUtil.hex2ByteArray("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"));

		byte[] secret1 = SharedSecretCalculation.generateSharedSecret(privateKey, publicKeyY1);
		byte[] secret2 = SharedSecretCalculation.generateSharedSecret(privateKey, publicKeyY2);

		System.out.println("Secret1 " + StringUtil.byteArray2HexString(secret1));
		System.out.println("Secret2 " + StringUtil.byteArray2HexString(secret2));

		Assert.assertArrayEquals(secret1, secret2);

		// Now try with a third key that is using the buildEcdsa256OneKey method
		// (that should rebuild one Y value automatically)
		OneKey publicKey3 = SharedSecretCalculation.buildEcdsa256OneKey(null, publicX, null);
		byte[] secret3 = SharedSecretCalculation.generateSharedSecret(privateKey, publicKey3);
		Assert.assertArrayEquals(secret1, secret3);
		/*
		 * { / kty / 1:2, / kid / 2:h'E1', / crv / -1:1, / x /
		 * -2:h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219
		 * a86d6a09eff', / y /
		 * -3:h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6e
		 * d28bbfc117e', / d /
		 * -4:h'57c92077664146e876760c9520d054aa93c3afb04e306705db609
		 * 0308507b4d3' }
		 */
	}


	/* Start tests */

	/**
	 * Tests generating a Curve25519 OneKey and performing shared secret
	 * calculation with it.
	 * 
	 * TODO: Remove?
	 * 
	 * @throws Exception on test failure
	 */
	@SuppressWarnings("deprecation")
	@Test
	@Ignore
	public void testCurve25519KeyGeneration() throws Exception {

		OneKey key1 = SharedSecretCalculation.generateCurve25519KeyOld();
		OneKey key2 = SharedSecretCalculation.generateCurve25519KeyOld();

		byte[] sharedSecret1 = SharedSecretCalculation.generateSharedSecret(key1, key2);
		byte[] sharedSecret2 = SharedSecretCalculation.generateSharedSecret(key2, key1);

		// System.out.println("Matching1 " + Arrays.equals(sharedSecret1,
		// sharedSecret2));
		Assert.assertArrayEquals(sharedSecret1, sharedSecret2);

		byte[] priv1 = key1.get(KeyKeys.OKP_D).GetByteString();
		byte[] pub1 = key1.get(KeyKeys.OKP_X).GetByteString();

		byte[] priv2 = key2.get(KeyKeys.OKP_D).GetByteString();
		byte[] pub2 = key2.get(KeyKeys.OKP_X).GetByteString();

		System.out.println("D1 " + StringUtil.byteArray2HexString(key1.get(KeyKeys.OKP_D).GetByteString()));
		System.out.println("X1 " + StringUtil.byteArray2HexString(key1.get(KeyKeys.OKP_X).GetByteString()));

		System.out.println("D2 " + StringUtil.byteArray2HexString(key2.get(KeyKeys.OKP_D).GetByteString()));
		System.out.println("X2 " + StringUtil.byteArray2HexString(key2.get(KeyKeys.OKP_X).GetByteString()));

		sharedSecret1 = SharedSecretCalculation.X25519(priv1, pub2);
		sharedSecret2 = SharedSecretCalculation.X25519(priv2, pub1);

		Assert.assertArrayEquals(sharedSecret1, sharedSecret2);
		// System.out.println("Matching2 " + Arrays.equals(sharedSecret1,
		// sharedSecret2));

	}

	/**
	 * Test shared secret calculation from the test vectors in the EDHOC draft.
	 * Note that these are already in Curve25519 so does not need to be
	 * converted but can be feed straight into X25519. Covering Appendix B.1.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.1
	 * 
	 * @throws CoseException on test failure
	 * @throws InvalidAlgorithmParameterException on test failure
	 */
	@Test
	public void testSharedSecretEdhocVectorsB1() throws CoseException, InvalidAlgorithmParameterException {
		byte[] X = StringUtil.hex2ByteArray("8f781a095372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35");
		byte[] G_X = StringUtil.hex2ByteArray("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c");

		byte[] Y = StringUtil.hex2ByteArray("fd8cd877c9ea386e6af34ff7e606c4b64ca831c8ba33134fd4cd7167cabaecda");
		byte[] G_Y = StringUtil.hex2ByteArray("71a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e");

		byte[] sharedSecret1 = SharedSecretCalculation.X25519(Y, G_X);
		byte[] sharedSecret2 = SharedSecretCalculation.X25519(X, G_Y);

		Assert.assertArrayEquals(sharedSecret1, sharedSecret2);

		byte[] G_XY_correct = StringUtil.hex2ByteArray("2bb7fa6e135bc335d022d634cbfb14b3f582f3e2e3afb2b3150491495c61782b");

		Assert.assertArrayEquals(G_XY_correct, sharedSecret1);
	}

	/**
	 * Test shared secret calculation from the test vectors in the EDHOC draft.
	 * Note that these are already in Curve25519 so does not need to be
	 * converted but can be feed straight into X25519. Covering Appendix B.2.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.2
	 * 
	 * @throws CoseException on test failure
	 * @throws InvalidAlgorithmParameterException on test failure
	 */
	@Test
	public void testSharedSecretEdhocVectorsB2() throws CoseException, InvalidAlgorithmParameterException {

		// Calculating G_XY

		byte[] X = StringUtil.hex2ByteArray("ae11a0db863c0227e53992feb8f5924c50d0a7ba6eeab4ad1ff24572f4f57cfa");
		byte[] G_X = StringUtil.hex2ByteArray("8d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c");

		byte[] Y = StringUtil.hex2ByteArray("c646cddc58126e18105f01ce35056e5ebc35f4d4cc510749a3a5e069c116169a");
		byte[] G_Y = StringUtil.hex2ByteArray("52fba0bdc8d953dd86ce1ab2fd7c05a4658c7c30afdbfc3301047069451baf35");

		byte[] sharedSecret1 = SharedSecretCalculation.X25519(Y, G_X);
		byte[] sharedSecret2 = SharedSecretCalculation.X25519(X, G_Y);

		Assert.assertArrayEquals(sharedSecret1, sharedSecret2);

		byte[] G_XY_correct = StringUtil.hex2ByteArray("defc2f3569109b3d1fa4a73dc5e2feb9e1150d90c25ee2f066c2d885f4f8ac4e");

		Assert.assertArrayEquals(G_XY_correct, sharedSecret1);

		// Calculating G_RX

		byte[] R = StringUtil.hex2ByteArray("bb501aac67b9a95f97e0eded6b82a662934fbbfc7ad1b74c1fcad66a079422d0");
		byte[] G_R = StringUtil.hex2ByteArray("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");

		sharedSecret1 = SharedSecretCalculation.X25519(R, G_X);
		sharedSecret2 = SharedSecretCalculation.X25519(X, G_R);

		Assert.assertArrayEquals(sharedSecret1, sharedSecret2);

		byte[] GR_X_correct = StringUtil.hex2ByteArray("21c7eff4fb69fa4b6797d05884315d8411a3fda54f6dada61d4fcd85e7906668");

		Assert.assertArrayEquals(GR_X_correct, sharedSecret1);

		// Calculating G_IY

		byte[] SK_I = StringUtil.hex2ByteArray("2bbea655c23371c329cfbd3b1f02c6c062033837b8b59099a4436f666081b08e");
		byte[] G_I = StringUtil.hex2ByteArray("2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71");

		sharedSecret1 = SharedSecretCalculation.X25519(SK_I, G_Y);
		sharedSecret2 = SharedSecretCalculation.X25519(Y, G_I);

		Assert.assertArrayEquals(sharedSecret1, sharedSecret2);

		byte[] G_IY_correct = StringUtil.hex2ByteArray("cbff8cd34a81dfec4cb65d9a572ebd0964450c78563da4981d80d36c8b1a752a");

		Assert.assertArrayEquals(G_IY_correct, sharedSecret1);
	}

	@Test
	public void testDecodeLittleEndian() {
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

		BigInteger res = SharedSecretCalculation.decodeLittleEndian(input, 255);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));
		assertEquals(correct, res);

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

		res = SharedSecretCalculation.decodeLittleEndian(input, 255);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));
		assertEquals(correct, res);
	}

	@Test
	public void testDecodeScalar() {
		/* -- Test decodeScalar -- */

		System.out.println("Test decodeScalar");

		// Input value:
		// 3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3
		byte[] input = new byte[] { (byte) 0x3d, (byte) 0x26, (byte) 0x2f, (byte) 0xdd, (byte) 0xf9, (byte) 0xec,
				(byte) 0x8e, (byte) 0x88, (byte) 0x49, (byte) 0x52, (byte) 0x66, (byte) 0xfe, (byte) 0xa1, (byte) 0x9a,
				(byte) 0x34, (byte) 0xd2, (byte) 0x88, (byte) 0x82, (byte) 0xac, (byte) 0xef, (byte) 0x04, (byte) 0x51,
				(byte) 0x04, (byte) 0xd0, (byte) 0xd1, (byte) 0xaa, (byte) 0xe1, (byte) 0x21, (byte) 0x70, (byte) 0x0a,
				(byte) 0x77, (byte) 0x9c, (byte) 0x98, (byte) 0x4c, (byte) 0x24, (byte) 0xf8, (byte) 0xcd, (byte) 0xd7,
				(byte) 0x8f, (byte) 0xbf, (byte) 0xf4, (byte) 0x49, (byte) 0x43, (byte) 0xeb, (byte) 0xa3, (byte) 0x68,
				(byte) 0xf5, (byte) 0x4b, (byte) 0x29, (byte) 0x25, (byte) 0x9a, (byte) 0x4f, (byte) 0x1c, (byte) 0x60,
				(byte) 0x0a, (byte) 0xd3 };

		// Output value (from Python code)
		// 41823108910914769844969816812214719139234914957831430028237854386113666295352
		BigInteger correct = new BigInteger(
				"41823108910914769844969816812214719139234914957831430028237854386113666295352");

		BigInteger res = SharedSecretCalculation.decodeScalar(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));
		assertEquals(correct, res);

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

		res = SharedSecretCalculation.decodeScalar(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));
		assertEquals(correct, res);
	}

	@Test
	public void testDecodeUCoordinate() {
		/* -- Test decodeUCoordinate -- */

		System.out.println("Test decodeUCoordinate");

		// Input value:
		// e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493
		byte[] input = new byte[] { (byte) 0xe5, (byte) 0x21, (byte) 0x0f, (byte) 0x12, (byte) 0x78, (byte) 0x68,
				(byte) 0x11, (byte) 0xd3, (byte) 0xf4, (byte) 0xb7, (byte) 0x95, (byte) 0x9d, (byte) 0x05, (byte) 0x38,
				(byte) 0xae, (byte) 0x2c, (byte) 0x31, (byte) 0xdb, (byte) 0xe7, (byte) 0x10, (byte) 0x6f, (byte) 0xc0,
				(byte) 0x3c, (byte) 0x3e, (byte) 0xfc, (byte) 0x4c, (byte) 0xd5, (byte) 0x49, (byte) 0xc7, (byte) 0x15,
				(byte) 0xa4, (byte) 0x93 };

		// Output value (from Python code)
		// 8883857351183929894090759386610649319417338800022198945255395922347792736741
		BigInteger correct = new BigInteger(
				"8883857351183929894090759386610649319417338800022198945255395922347792736741");

		BigInteger res = SharedSecretCalculation.decodeUCoordinate(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));
		assertEquals(correct, res);

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

		res = SharedSecretCalculation.decodeUCoordinate(input);

		System.out.println("Expected: " + correct);
		System.out.println("Actual: " + res);
		System.out.println("Same: " + correct.equals(res));
		assertEquals(correct, res);
	}

	@Test
	public void testEncodeUCoordinate() {
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

		byte[] resArray = SharedSecretCalculation.encodeUCoordinate(inputInt);

		System.out.println("Expected: " + StringUtil.byteArray2HexString(correctArray));
		System.out.println("Actual: " + StringUtil.byteArray2HexString(resArray));
		System.out.println("Same: " + Arrays.equals(correctArray, resArray));
		assertArrayEquals(correctArray, resArray);

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

		resArray = SharedSecretCalculation.encodeUCoordinate(inputInt);

		System.out.println("Expected: " + StringUtil.byteArray2HexString(correctArray));
		System.out.println("Actual: " + StringUtil.byteArray2HexString(resArray));
		System.out.println("Same: " + Arrays.equals(correctArray, resArray));
		assertArrayEquals(correctArray, resArray);
	}

	@Test
	public void testCswap() {
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

		Tuple result = SharedSecretCalculation.cswap(swap, a, b);
		System.out.println("Swap correct: " + result.a.equals(a) + " and " + result.b.equals(b));
		assertEquals(a, result.a);
		assertEquals(b, result.b);

		// Now do swap

		swap = BigInteger.ONE;
		result = SharedSecretCalculation.cswap(swap, a, b);
		System.out.println("Swap correct: " + result.a.equals(b) + " and " + result.b.equals(a));
		assertEquals(b, result.a);
		assertEquals(a, result.b);
	}

	@Test
	public void testX25519() {
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

		byte[] result = SharedSecretCalculation.X25519(k, u);

		System.out.println("R: " + StringUtil.byteArray2HexString(result));
		System.out.println("X25519 result is correct: " + Arrays.equals(c, result));
		assertArrayEquals(c, result);

		/* Test X25519 test vectors */
		// See https://tools.ietf.org/html/rfc7748#section-5.2

		System.out.println("Test X25519 test vectors");

		// First X25519 test vector

		byte[] inputScalar = StringUtil.hex2ByteArray("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
		byte[] inputUCoordinate = StringUtil.hex2ByteArray("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
		byte[] outputUCoordinate = StringUtil.hex2ByteArray("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

		byte[] myResult = SharedSecretCalculation.X25519(inputScalar, inputUCoordinate);
		System.out.println("First test vector works: " + Arrays.equals(myResult, outputUCoordinate));
		assertArrayEquals(outputUCoordinate, myResult);

		// Second X25519 test vector

		inputScalar = StringUtil.hex2ByteArray("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
		inputUCoordinate = StringUtil.hex2ByteArray("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
		outputUCoordinate = StringUtil.hex2ByteArray("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

		myResult = SharedSecretCalculation.X25519(inputScalar, inputUCoordinate);
		System.out.println("Second test vector works: " + Arrays.equals(myResult, outputUCoordinate));
		assertArrayEquals(outputUCoordinate, myResult);

		// Third X25519 test vector (iterations)

		inputScalar = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		inputUCoordinate = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] resultIteration1 = StringUtil.hex2ByteArray("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

		byte[] myResult_1 = SharedSecretCalculation.X25519(inputScalar, inputUCoordinate);
		System.out.println("Third test vector works (1 iteration): " + Arrays.equals(myResult_1, resultIteration1));
		assertArrayEquals(resultIteration1, myResult_1);

		// 1000 iterations

		byte[] tU = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] tK = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] tR = null;
		for (int i = 0; i < 1000; i++) {

			tR = SharedSecretCalculation.X25519(tK.clone(), tU.clone()).clone();
			tU = tK;
			tK = tR;

		}

		byte[] resultIteration1000 = StringUtil.hex2ByteArray("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
		byte[] myResult_1000 = tK;

		System.out.println(
				"Third test vector works (1000 iterations): " + Arrays.equals(myResult_1000, resultIteration1000));
		assertArrayEquals(resultIteration1000, myResult_1000);

		// 1 000 000 iterations
		// Takes a very long time ~45 minutes

		boolean runMillionTest = false;

		if (runMillionTest) {

			tU = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
			tK = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
			tR = null;
			long startTime = System.nanoTime();
			for (int i = 0; i < 1000000; i++) {

				tR = SharedSecretCalculation.X25519(tK, tU);
				tU = tK;
				tK = tR;

				if (i % 20000 == 0) {
					long timeElapsed = System.nanoTime() - startTime;
					System.out.println("Iteration: " + i + ". Time: " + timeElapsed / 1000000 / 1000 + " seconds");
				}
			}

			byte[] resultIteration1000000 = StringUtil.hex2ByteArray(
					"7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
			byte[] myResult_1000000 = tK;

			System.out.println("Third test vector works (1 000 000 iterations): "
					+ Arrays.equals(myResult_1000000, resultIteration1000000));
			assertArrayEquals(resultIteration1000000, myResult_1000000);
		}
	}

	@Test
	public void testDiffieHellman() {
		/* Test Diffie Hellman */
		// See https://tools.ietf.org/html/rfc7748#section-6.1

		byte[] private_key_a = StringUtil.hex2ByteArray(
				"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
		byte[] public_key_KA = StringUtil.hex2ByteArray(
				"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

		byte[] private_key_b = StringUtil.hex2ByteArray(
				"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
		byte[] public_key_KB = StringUtil.hex2ByteArray(
				"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

		byte[] nine = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");

		// Check public keys
		byte[] public_key_KA_calc = SharedSecretCalculation.X25519(private_key_a, nine);
		byte[] public_key_KB_calc = SharedSecretCalculation.X25519(private_key_b, nine);

		System.out.println("Public Key KA correct: " + Arrays.equals(public_key_KA_calc, public_key_KA));
		System.out.println("Public Key KB correct: " + Arrays.equals(public_key_KB_calc, public_key_KB));
		assertArrayEquals(public_key_KA_calc, public_key_KA);
		assertArrayEquals(public_key_KB_calc, public_key_KB);

		byte[] sharedSecret = StringUtil.hex2ByteArray(
				"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

		// Check shared secret
		byte[] sharedSecret_calc_one = SharedSecretCalculation.X25519(private_key_a, public_key_KB);
		byte[] sharedSecret_calc_two = SharedSecretCalculation.X25519(private_key_b, public_key_KA);

		System.out.println(
				"Shared secret matches each other: " + Arrays.equals(sharedSecret_calc_one, sharedSecret_calc_two));
		System.out
				.println("Shared secret matches correct value: " + Arrays.equals(sharedSecret_calc_one, sharedSecret));
		assertArrayEquals(sharedSecret_calc_one, sharedSecret_calc_two);
		assertArrayEquals(sharedSecret_calc_one, sharedSecret);
	}

	@Test
	public void testSharedSecretWithCOSEKey() throws CoseException {
		/* Test starting from COSE Keys */

		/*
		 * Important section:
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

		System.out.println("H priv1: " + StringUtil.byteArray2HexString(privateKey1H));
		System.out.println("u from key one (public part): " + uuu1);
		// System.out.println("From key one (private part): " +
		// StringUtil.byteArray2HexString(privateKey1H);

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

		System.out.println("H priv2: " + StringUtil.byteArray2HexString(privateKey2H));
		System.out.println("u from key two (public part): " + uuu2);
		// System.out.println("From key two (private part): " +
		// StringUtil.byteArray2HexString(privateKey2H);

		// Calculated shared secrets
		// X25519(my private scalar, your public key U)
		byte[] sharedSecret1 = SharedSecretCalculation.X25519(privateKey1H, publicKey2U);
		byte[] sharedSecret2 = SharedSecretCalculation.X25519(privateKey2H, publicKey1U);

		System.out.println("Shared secret 1: " + StringUtil.byteArray2HexString(sharedSecret1));
		System.out.println("Shared secret 2: " + StringUtil.byteArray2HexString(sharedSecret2));
		System.out.println("Shared secrets match: " + Arrays.equals(sharedSecret1, sharedSecret2));
		assertArrayEquals(sharedSecret1, sharedSecret2);
	}

	/* End testing */

}
