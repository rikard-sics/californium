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
 *    Marco Tiloca (RISE)
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.StringUtil;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerFieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerLittleEndianEncoding;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

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
	 * https://tools.ietf.org/html/rfc7748
	 * 
	 * https://tools.ietf.org/html/rfc8032
	 * 
	 * https://github.com/bifurcation/fourq
	 * https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
	 * 
	 * https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/
	 * bouncycastle/math/ec/rfc7748/test/X25519Test.java
	 * 
	 * https://cryptojedi.org/peter/data/pairing-20131122.pdf
	 * 
	 * https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/
	 * bouncycastle/jcajce/provider/asymmetric/ec/KeyPairGeneratorSpi.java#L251
	 * 
	 * https://stackoverflow.com/questions/57852431/how-to-generate-curve25519-
	 * key-pair-for-diffie-hellman-algorithm
	 * 
	 * https://tools.ietf.org/html/rfc7748
	 * 
	 */

	// Create the ed25519 field
	private static Field ed25519Field = new Field(256, // b
			StringUtil.hex2ByteArray("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q(2^255-19)
			new BigIntegerLittleEndianEncoding());

	/**
	 * Build OneKey using Curve25519. This method does not need Java 11 or
	 * BouncyCastle, also it does not start from Ed25519 keys but generates
	 * Curve25519 keys directly. Note that this OneKey will not have the
	 * internal Java keys set.
	 * 
	 * @return the generated Curve25519 OneKey
	 */
	public static OneKey generateCurve25519OneKey() {

		int SCALAR_SIZE = 32;
		int POINT_SIZE = 32;

		byte[] kA = new byte[SCALAR_SIZE];
		byte[] qA = new byte[POINT_SIZE];

		SecureRandom random = new SecureRandom();

		random.nextBytes(kA);

		byte[] basePoint = new byte[32];
		basePoint[0] = 0x09;
		qA = SharedSecretCalculation.X25519(kA, basePoint);

		OneKey key = buildCurve25519OneKey(kA, qA);

		return key;
	}

	/**
	 * Build OneKey using Ed25519.
	 * 
	 * @return the generated Ed25519 OneKey
	 */
	public static OneKey generateEd25519OneKey() {

		OneKey key = null;
		try {
			key = OneKey.generateKey(KeyKeys.OKP_Ed25519);
		} catch (CoseException e) {
			System.err.println("Failed to generate Ed25519 key: " + e);
		}

		return key;
	}

	// https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/math/ec/rfc7748/test/X25519Test.java
	@Deprecated
	private static void bouncyCastleKeyAgreement() {
		SecureRandom RANDOM = new SecureRandom();
		AsymmetricCipherKeyPairGenerator kpGen = new X25519KeyPairGenerator();

		kpGen.init(new X25519KeyGenerationParameters(RANDOM));

		AsymmetricCipherKeyPair kpA = kpGen.generateKeyPair();
		AsymmetricCipherKeyPair kpB = kpGen.generateKeyPair();
		X25519Agreement agreeA = new X25519Agreement();

		AsymmetricKeyParameter pub1 = kpA.getPublic();
		AsymmetricKeyParameter pub2 = kpB.getPublic();

		AsymmetricKeyParameter priv1 = kpA.getPrivate();
		AsymmetricKeyParameter priv2 = kpB.getPrivate();

		agreeA.init(kpA.getPrivate());

		byte[] secretA = new byte[agreeA.getAgreementSize()];
		agreeA.calculateAgreement(kpB.getPublic(), secretA, 0);
		X25519Agreement agreeB = new X25519Agreement();
		agreeB.init(kpB.getPrivate());

		byte[] secretB = new byte[agreeB.getAgreementSize()];
		agreeB.calculateAgreement(kpA.getPublic(), secretB, 0);

	}

	/**
	 * Generate a COSE OneKey using Curve25519 for X25519. Note that this key
	 * will be lacking the Java keys internally.
	 * 
	 * https://cryptojedi.org/peter/data/pairing-20131122.pdf
	 * 
	 * FIXME: Not working
	 * 
	 * @return the COSE OneKey
	 */
	@Deprecated
	static OneKey generateCurve25519KeyTest() {

		// https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/ec/KeyPairGeneratorSpi.java#L251
		// https://stackoverflow.com/questions/57852431/how-to-generate-curve25519-key-pair-for-diffie-hellman-algorithm

		// Start by generating a Curve25519 key pair with BouncyCastle

		// MyRandom rand = new MyRandom();
		SecureRandom rand = new SecureRandom();

		X9ECParameters curveParams = CustomNamedCurves.getByName("Curve25519");
		// byte[] seed = StringUtil.hex2ByteArray(
		//  		"1122334455667788112233445566778811223344556677881122334455667788");
		ECParameterSpec ecSpec = new ECParameterSpec(curveParams.getCurve(), curveParams.getG(), curveParams.getN(),
				curveParams.getH(), curveParams.getSeed());

		// System.out.println("Spec using seed: " +
		// StringUtil.byteArray2HexString(ecSpec.getSeed()));

		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
			kpg.initialize(ecSpec);
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			System.err.println("Failed to generate Curve25519 key: " + e);
		}

		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		BCECPublicKey pubKey = (BCECPublicKey) publicKey;
		BCECPrivateKey privKey = (BCECPrivateKey) privateKey;

		// Build the COSE OneKey

		System.out.println("D " + StringUtil.byteArray2HexString(privKey.getD().toByteArray()));
		System.out.println("Seed priv " + StringUtil.byteArray2HexString(privKey.getParameters().getSeed()));
		System.out.println("Seed pub " + StringUtil.byteArray2HexString(pubKey.getParameters().getSeed()));
		System.out.println();
		System.out.println("Q pub " + pubKey.getQ().toString());
		System.out.println("Q pub uncompressed " + StringUtil.byteArray2HexString(pubKey.getQ().getEncoded(false)));
		System.out.println("Q pub 1st half " + StringUtil.byteArray2HexString(Arrays.copyOf(pubKey.getQ().getEncoded(false), 32)));
		System.out.println("Q compressed   " + StringUtil.byteArray2HexString(pubKey.getQ().getEncoded(true)));
		System.out.println("Sing of v?   " + StringUtil.byteArray2HexString(Arrays.copyOf(pubKey.getQ().getEncoded(true), 1)));
		System.out
				.println("Actual U?   " + StringUtil.byteArray2HexString(Arrays.copyOfRange(pubKey.getQ().getEncoded(true), 1, 33)));
		System.out.println(
				"getAffineXCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getAffineXCoord().toBigInteger().toByteArray()));
		System.out.println(
				"getAffineYCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getAffineYCoord().toBigInteger().toByteArray()));
		System.out.println();
		System.out
				.println("getRawXCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getRawXCoord().toBigInteger().toByteArray()));
		System.out
				.println("getRawYCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getRawYCoord().toBigInteger().toByteArray()));
		System.out.println();
		System.out.println("getXCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getXCoord().toBigInteger().toByteArray()));
		System.out.println("getYCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getYCoord().toBigInteger().toByteArray()));
		System.out.println();
		System.out.println("Pubkey encoded: " + StringUtil.byteArray2HexString(pubKey.getEncoded()));
		System.out.println("Privkey encoded: " + StringUtil.byteArray2HexString(privKey.getEncoded()));
		System.out.println();
		System.out.println("S: " + StringUtil.byteArray2HexString(privKey.getS().toByteArray()));
		System.out.println();
		privKey.getParameters().getH();
		System.out.println("H: " + StringUtil.byteArray2HexString(privKey.getParameters().getH().toByteArray()));
		System.out.println();
		System.out.println("Pubkey (Java) encoded: " + StringUtil.byteArray2HexString(publicKey.getEncoded()));
		System.out.println("Privkey (Java) encoded: " + StringUtil.byteArray2HexString(privateKey.getEncoded()));

		// Get the private D
		byte[] rgbD = invertArray(privKey.getD().toByteArray());
		// Get the public point Q (compressed true)
		byte[] rgbX = pubKey.getQ().getXCoord().getEncoded();

		OneKey key = new OneKey();

		key.add(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
		key.add(KeyKeys.OKP_Curve, KeyKeys.OKP_X25519);
		key.add(KeyKeys.OKP_X, CBORObject.FromObject(rgbX));
		key.add(KeyKeys.OKP_D, CBORObject.FromObject(rgbD));

		return key;
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers EdDSA with the curve Ed25519.
	 * 
	 * @param privateKey the private key bytes
	 * @param publicKey the public key bytes
	 * 
	 * @return a OneKey representing the input material
	 */
	public static OneKey buildEd25519OneKey(byte[] privateKey, byte[] publicKey) {
		byte[] rgbX = publicKey;
		byte[] rgbD = privateKey;

		CBORObject keyMap = CBORObject.NewMap();
		
		keyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.EDDSA.AsCBOR());
		keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
		keyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
		keyMap.Add(KeyKeys.OKP_X.AsCBOR(), CBORObject.FromObject(rgbX));
		
		if (privateKey != null)
			keyMap.Add(KeyKeys.OKP_D.AsCBOR(), CBORObject.FromObject(rgbD));

		OneKey key = null;
		try {
			key = new OneKey(keyMap);
		} catch (CoseException e) {
			System.err.println("Failed to generate COSE OneKey: " + e);
		}

		return key;
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers EdDSA with the curve Curve25519. Will not fill
	 * the Java private and public key in the COSE key. So can only be used for
	 * shared secret calculation.
	 * 
	 * @param privateKey the private key bytes (private scalar here)
	 * @param publicKey the public key bytes
	 * 
	 * @return a OneKey representing the input material
	 */
	public static OneKey buildCurve25519OneKey(byte[] privateKey, byte[] publicKey) {
		byte[] rgbX = publicKey;
		byte[] rgbD = privateKey;

		OneKey key = new OneKey();
		
		key.add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
		key.add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_X25519);
		key.add(KeyKeys.OKP_X.AsCBOR(), CBORObject.FromObject(rgbX));
		
		// FIXME: D should be seed?
		if (privateKey != null)
			key.add(KeyKeys.OKP_D.AsCBOR(), CBORObject.FromObject(rgbD));

		return key;
	}

	/**
	 * Build a Java key pair from raw byte arrays containing the public and
	 * private keys. Considers EdDSA with the curve Ed25519.
	 * 
	 * @param privateKey the private key bytes
	 * @param publicKey the public key bytes
	 * @return a Java KeyPair representing the input material
	 */
	static KeyPair buildEd25519JavaKey(byte[] privateKey, byte[] publicKey) {
		EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(privateKey, EdDSANamedCurveTable.getByName("Ed25519"));
		EdDSAPrivateKey priv = new EdDSAPrivateKey(privSpec);
		EdDSAPublicKeySpec pubSpec = new EdDSAPublicKeySpec(publicKey, EdDSANamedCurveTable.getByName("Ed25519"));
		EdDSAPublicKey pub = new EdDSAPublicKey(pubSpec);

		KeyPair pair = new KeyPair(pub, priv);

		return pair;
	}

	/**
	 * Calculate public key for a corresponding private key. Considers EdDSA
	 * with the curve Ed25519.
	 * 
	 * @param privateKey the private key bytes
	 * @return the public key bytes
	 */
	static byte[] calculatePublicEd25519FromPrivate(byte[] privateKey) {
		EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
		byte[] seed = privateKey;
		EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(seed, spec);
		EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKeySpec.getA(), spec);

		EdDSAPublicKey pubKeyKey = new EdDSAPublicKey(pubKeySpec);
		return pubKeyKey.getAbyte();
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers ECDSA_384. Will recompute the Y value according
	 * to the indicated sign.
	 *
	 * @param privateKey the private key bytes
	 * @param publicKeyX the public key X parameter bytes
	 * @param signY the sign of the Y value to be recomputed
	 * 
	 * @return a OneKey representing the input material
	 */
	static OneKey buildEcdsa384OneKey(byte[] privateKey, byte[] publicKeyX, boolean signY) {
		// Recalculate Y value
		byte[] publicKeyY = null;
		try {
			publicKeyY = recomputeEcdsa384YFromX(publicKeyX, signY);
		} catch (CoseException e) {
			System.err.println("Failed to recompute missing Y value: " + e);
		}

		return buildEcdsa384OneKey(privateKey, publicKeyX, publicKeyY);
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers ECDSA_384.
	 *
	 * @param privateKey the private key bytes
	 * @param publicKeyX the public key X parameter bytes
	 * @param publicKeyY the public key Y parameter bytes. If none is provided a
	 *            valid Y will be recomputed. Note that the sign positive Y will
	 *            always be returned.
	 * 
	 * @return a OneKey representing the input material
	 */
	static OneKey buildEcdsa384OneKey(byte[] privateKey, byte[] publicKeyX, byte[] publicKeyY) {

		// Attempt to recalculate Y value if missing
		if (publicKeyY == null) {
			try {
				publicKeyY = recomputeEcdsa384YFromX(publicKeyX, true);
			} catch (CoseException e) {
				System.err.println("Failed to recompute missing Y value: " + e);
			}
		}

		CBORObject keyMap = CBORObject.NewMap();

		keyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_384.AsCBOR());
		keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
		keyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P384);
		keyMap.Add(KeyKeys.EC2_X.AsCBOR(), CBORObject.FromObject(publicKeyX));
		if (publicKeyY != null)
			keyMap.Add(KeyKeys.EC2_Y.AsCBOR(), CBORObject.FromObject(publicKeyY));
		if (privateKey != null)
			keyMap.Add(KeyKeys.EC2_D.AsCBOR(), CBORObject.FromObject(privateKey));

		OneKey key = null;
		try {
			key = new OneKey(keyMap);
		} catch (CoseException e) {
			System.err.println("Failed to generate COSE OneKey: " + e);
		}

		return key;
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public X key and
	 * the private key. Considers ECDSA_256. Will recompute the Y value
	 * according to the indicated sign.
	 * 
	 * @param privateKey the private key bytes
	 * @param publicKeyX the public key X parameter bytes
	 * @param signY the sign of the Y value to be recomputed
	 * 
	 * @return a OneKey representing the input material
	 */
	static OneKey buildEcdsa256OneKey(byte[] privateKey, byte[] publicKeyX, boolean signY) {
		// Recalculate Y value
		byte[] publicKeyY = null;
		try {
			publicKeyY = recomputeEcdsa256YFromX(publicKeyX, signY);
		} catch (CoseException e) {
			System.err.println("Failed to recompute missing Y value: " + e);
		}

		return buildEcdsa256OneKey(privateKey, publicKeyX, publicKeyY);
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers ECDSA_256.
	 *
	 * @param privateKey the private key bytes
	 * @param publicKeyX the public key X parameter bytes
	 * @param publicKeyY the public key Y parameter bytes. If none is provided a
	 *            valid Y will be recomputed. Note that the sign positive Y will
	 *            always be returned.
	 * 
	 * @return a OneKey representing the input material
	 */
	public static OneKey buildEcdsa256OneKey(byte[] privateKey, byte[] publicKeyX, byte[] publicKeyY) {

        // Attempt to recalculate Y value if missing
		if (publicKeyY == null) {
			try {
				publicKeyY = recomputeEcdsa256YFromX(publicKeyX, true);
			} catch (CoseException e) {
				System.err.println("Failed to recompute missing Y value: " + e);
			}
		}

		CBORObject keyMap = CBORObject.NewMap();
		
		keyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_256.AsCBOR());
		keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
		keyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
		keyMap.Add(KeyKeys.EC2_X.AsCBOR(), CBORObject.FromObject(publicKeyX));
		if (publicKeyY != null)
			keyMap.Add(KeyKeys.EC2_Y.AsCBOR(), CBORObject.FromObject(publicKeyY));
		if (privateKey != null)
			keyMap.Add(KeyKeys.EC2_D.AsCBOR(), CBORObject.FromObject(privateKey));

		OneKey key = null;
		try {
			key = new OneKey(keyMap);
		} catch (CoseException e) {
			System.err.println("Failed to generate COSE OneKey: " + e);
		}

		return key;
	}

	/**
	 * Takes an ECDSA_256 X coordinate and computes a valid Y value for that X.
	 * Will only only return one of the possible Y values.
	 * 
	 * Resources:
	 * https://github.com/conz27/crypto-test-vectors/blob/master/ecdh.py
	 * https://crypto.stackexchange.com/questions/8914/ecdsa-compressed-public-key-point-back-to-uncompressed-public-key-point
	 * https://asecuritysite.com/encryption/js08
	 * https://bitcoin.stackexchange.com/questions/44024/get-uncompressed-public-key-from-compressed-form
	 * http://www-cs-students.stanford.edu/~tjw/jsbn/ecdh.html
	 * https://tools.ietf.org/html/rfc6090#appendix-C
	 * https://math.stackexchange.com/questions/464253/square-roots-in-finite-fields-i-e-mod-pm
	 * http://hg.openjdk.java.net/jdk/jdk/rev/752e57845ad2#l1.97
	 * jdk.crypto.ec/sun.security.ec.ECDHKeyAgreement
	 * https://www.secg.org/sec1-v2.pdf
	 * 
	 * @param publicKeyX the public key X coordinate
	 * @param signY the sign of the Y coordinate to return
	 * 
	 * @return the recomputed Y value for that X
	 * @throws CoseException if recomputation fails
	 */
	static byte[] recomputeEcdsa256YFromX(byte[] publicKeyX, boolean signY) throws CoseException {

		BigInteger x = new BigInteger(1, publicKeyX);

		// secp256r1
		// y^2 = x^3 + ax + b -> y = +- sqrt(a x + b + x^3)
		BigInteger prime = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
		BigInteger A = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
		BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
		BigInteger three = new BigInteger("3");
		BigInteger two = new BigInteger("2");
		BigInteger zero = new BigInteger("0");
		BigInteger one = new BigInteger("1");

		BigInteger xPow3 = x.modPow(three, prime);
		BigInteger ax = (A.multiply(x)).mod(prime);
		BigInteger partial = ax.add(B).mod(prime);
		BigInteger combined = partial.add(xPow3).mod(prime);

		BigInteger root1 = squareMod(combined, prime);
		BigInteger root2 = root1.negate().mod(prime);

		// System.out.println("Root1: " +
		// StringUtil.byteArray2HexString(root1.toByteArray()));
		// System.out.println("Root2: " +
		// StringUtil.byteArray2HexString(root2.toByteArray()));

		// The size of the returned binary representation of a BigInteger will be
		// the minimum number of bytes required to represent that BigInteger.
		// Hence, left-padding with 0x00 byes may be needed to comply with the
		// expected size of the coordinates.
		
		byte[] root1Bytes = root1.toByteArray();
		byte[] root2Bytes = root2.toByteArray();
		
		if (root1Bytes.length < 32) {
			root1Bytes = leftPadByteArray(root1Bytes, 32 - root1Bytes.length);
			if (root1Bytes == null) {
				System.out.println("Error when computing the Y value.");
				return null;
			}
		}
		if (root1Bytes.length == 33) {
			root1Bytes = Arrays.copyOfRange(root1Bytes, 1, 33);
		}
		
		if (root2Bytes.length < 32) {
			root2Bytes = leftPadByteArray(root2Bytes, 32 - root2Bytes.length);
			if (root2Bytes == null) {
				System.out.println("Error when computing the Y value.");
				return null;
			}
		}
		if (root2Bytes.length == 33) {
			root2Bytes = Arrays.copyOfRange(root2Bytes, 1, 33);
		}

		byte[] xBytes = x.toByteArray();
		
		if (xBytes.length < 32) {
			xBytes = leftPadByteArray(xBytes, 32 - xBytes.length);
			if (xBytes == null) {
				System.out.println("Error when computing the Y value.");
				return null;
			}
		}
		if (xBytes.length == 33) {
			xBytes = Arrays.copyOfRange(xBytes, 1, 33);
		}
		
		// Now build 2 keys from the potential Y values
		OneKey possibleKey1 = null;
		OneKey possibleKey2 = null;
		try {
			possibleKey1 = SharedSecretCalculation.buildEcdsa256OneKey(null, xBytes, root1Bytes);
		} catch (Exception e) {
			// Failed to build key with this Y, so it won't be used
		}
		try {
			possibleKey2 = SharedSecretCalculation.buildEcdsa256OneKey(null, xBytes, root2Bytes);
		} catch (Exception e) {
			// Failed to build key with this Y, so it won't be used
		}

		// Check if on point (first y)
		// jdk.crypto.ec/sun.security.ec.ECDHKeyAgreement
		ECPublicKey keyToTest;
		BigInteger keyX;
		BigInteger keyY;
		BigInteger p = prime;
		EllipticCurve curve;
		BigInteger rhs;
		BigInteger lhs;

		if (possibleKey1 != null
				&& ((root1.mod(two).equals(zero) && signY == false) || (root1.mod(two).equals(one) && signY == true))) {
			keyToTest = (ECPublicKey) possibleKey1.AsPublicKey();
			keyX = keyToTest.getW().getAffineX();
			keyY = keyToTest.getW().getAffineY();
			p = prime;
			curve = keyToTest.getParams().getCurve();
			rhs = keyX.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
			lhs = keyY.modPow(BigInteger.valueOf(2), p).mod(p);
			if (!rhs.equals(lhs)) {
				System.out.println("Key using first Y not on curve!");
			} else {
				return possibleKey1.get(KeyKeys.EC2_Y).GetByteString();
			}
		}

		// Check if on point (second y)
		if (possibleKey2 != null) {
			keyToTest = (ECPublicKey) possibleKey2.AsPublicKey();
			keyX = keyToTest.getW().getAffineX();
			keyY = keyToTest.getW().getAffineY();
			curve = keyToTest.getParams().getCurve();
			rhs = keyX.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
			lhs = keyY.modPow(BigInteger.valueOf(2), p).mod(p);
			if (!rhs.equals(lhs)) {
				System.out.println("Key using second Y not on curve!");
			} else {
				return possibleKey2.get(KeyKeys.EC2_Y).GetByteString();
			}
		}
		System.out.println("Found no fitting Y value.");
		return null;
	}

	/**
	 * Takes an ECDSA_384 X coordinate and computes a valid Y value for that X.
	 * Will only only return one of the possible Y values.
	 * 
	 * https://neuromancer.sk/std/secg/secp384r1
	 * 
	 * @param publicKeyX the public key X coordinate
	 * @param signY the sign of the Y coordinate to return
	 * 
	 * @return the recomputed Y value for that X
	 * @throws CoseException if recomputation fails
	 */
	static byte[] recomputeEcdsa384YFromX(byte[] publicKeyX, boolean signY) throws CoseException {

		BigInteger x = new BigInteger(1, publicKeyX);

		// secp384r1
		// y^2 = x^3 + ax + b -> y = +- sqrt(a x + b + x^3)
		BigInteger prime = new BigInteger(
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16);
		BigInteger A = new BigInteger(
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16);
		BigInteger B = new BigInteger(
				"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16);
		BigInteger three = new BigInteger("3");
		BigInteger two = new BigInteger("2");
		BigInteger zero = new BigInteger("0");
		BigInteger one = new BigInteger("1");

		BigInteger xPow3 = x.modPow(three, prime);
		BigInteger ax = (A.multiply(x)).mod(prime);
		BigInteger partial = ax.add(B).mod(prime);
		BigInteger combined = partial.add(xPow3).mod(prime);

		BigInteger root1 = squareMod(combined, prime);
		BigInteger root2 = root1.negate().mod(prime);

		// The size of the returned binary representation of a BigInteger will be
		// the minimum number of bytes required to represent that BigInteger.
		// Hence, left-padding with 0x00 byes may be needed to comply with the
		// expected size of the coordinates.
		
		byte[] root1Bytes = root1.toByteArray();
		byte[] root2Bytes = root2.toByteArray();

		if (root1Bytes.length < 48) {
		    root1Bytes = leftPadByteArray(root1Bytes, 48 - root1Bytes.length);
		    if (root1Bytes == null) {
		        System.out.println("Error when computing the Y value.");
		        return null;
		    }
		}
		if (root1Bytes.length == 49) {
			root1Bytes = Arrays.copyOfRange(root1Bytes, 1, 49);
		}
		
		if (root2Bytes.length < 48) {
		    root2Bytes = leftPadByteArray(root2Bytes, 48 - root2Bytes.length);
		    if (root2Bytes == null) {
		        System.out.println("Error when computing the Y value.");
		        return null;
		    }
		}
		if (root2Bytes.length == 49) {
			root2Bytes = Arrays.copyOfRange(root2Bytes, 1, 49);
		}

		byte[] xBytes = x.toByteArray();
		
		if (xBytes.length < 48) {
			xBytes = leftPadByteArray(xBytes, 48 - xBytes.length);
		    if (xBytes == null) {
		        System.out.println("Error when computing the Y value.");
		        return null;
		    }
		}
		if (xBytes.length == 49) {
			xBytes = Arrays.copyOfRange(xBytes, 1, 49);
		}

		// System.out.println("Root1: " + StringUtil.byteArray2HexString(root1Bytes));
		// System.out.println("Root2: " + StringUtil.byteArray2HexString(root2Bytes));
		// System.out.println("X: " + StringUtil.byteArray2HexString(xBytes));

		// Now build 2 keys from the potential Y values
		OneKey possibleKey1 = null;
		OneKey possibleKey2 = null;
		try {
			possibleKey1 = SharedSecretCalculation.buildEcdsa384OneKey(null, xBytes, root1Bytes);
		} catch (Exception e) {
			// Failed to build key with this Y, so it won't be used
		}
		try {
			possibleKey2 = SharedSecretCalculation.buildEcdsa384OneKey(null, xBytes, root2Bytes);
		} catch (Exception e) {
			// Failed to build key with this Y, so it won't be used
		}

		// Check if on point (first y)
		// jdk.crypto.ec/sun.security.ec.ECDHKeyAgreement
		ECPublicKey keyToTest;
		BigInteger keyX;
		BigInteger keyY;
		BigInteger p = prime;
		EllipticCurve curve;
		BigInteger rhs;
		BigInteger lhs;

		if (possibleKey1 != null
				&& ((root1.mod(two).equals(zero) && signY == false) || (root1.mod(two).equals(one) && signY == true))) {
			keyToTest = (ECPublicKey) possibleKey1.AsPublicKey();
			keyX = keyToTest.getW().getAffineX();
			keyY = keyToTest.getW().getAffineY();
			p = prime;
			curve = keyToTest.getParams().getCurve();
			rhs = keyX.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
			lhs = keyY.modPow(BigInteger.valueOf(2), p).mod(p);
			if (!rhs.equals(lhs)) {
				System.out.println("Key using first Y not on curve!");
			} else {
				return possibleKey1.get(KeyKeys.EC2_Y).GetByteString();
			}
		}

		// Check if on point (second y)
		if (possibleKey2 != null) {
			keyToTest = (ECPublicKey) possibleKey2.AsPublicKey();
			keyX = keyToTest.getW().getAffineX();
			keyY = keyToTest.getW().getAffineY();
			curve = keyToTest.getParams().getCurve();
			rhs = keyX.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
			lhs = keyY.modPow(BigInteger.valueOf(2), p).mod(p);
			if (!rhs.equals(lhs)) {
				System.out.println("Key using second Y not on curve!");
			} else {
				return possibleKey2.get(KeyKeys.EC2_Y).GetByteString();
			}
		}
		System.out.println("Found no fitting Y value.");
		return null;
	}

    /**
     * Calculates prime roots in a field. Only works if p congruent 3 mod 4.
     * 
     * https://math.stackexchange.com/questions/464253/square-roots-in-finite-fields-i-e-mod-pm
     * 
     * @param val the value to square
     * @return one of the square roots
     */
	static BigInteger squareMod(BigInteger val, BigInteger prime) {

		BigInteger three = new BigInteger("3");
		BigInteger four = new BigInteger("4");
		if (!prime.mod(four).equals(three)) {
			System.err.println("Invalid prime! p must be congruent 3 mod 4");
		}

		BigInteger power = prime.add(BigInteger.ONE).divide(new BigInteger("4"));

		return val.modPow(power, prime);

	}

	/**
	 * Generates a shared secret for EdDSA (Ed25519) or ECDSA.
	 * 
	 * TODO: Add X448 support? (Would need a dedicated X448 method or
	 * modification of the existing)
	 * 
	 * @param privateKey the public/private key of the sender
	 * @param publicKey the public key of the recipient
	 * 
	 * @return the shared secret, or null in case of error
	 */
	static byte[] generateSharedSecret(OneKey privateKey, OneKey publicKey) {

		if (privateKey == null || publicKey == null) {
			System.err.println("Public key and/or private key not found.");
			return null;
		}
		
		// EC2 keys (P-256)
		
		CBORObject privateCurve = privateKey.get(KeyKeys.EC2_Curve);
		CBORObject publicCurve = publicKey.get(KeyKeys.EC2_Curve);

		if (privateCurve != publicCurve) {
			System.err.println("Public and private keys use different curves.");
			return null;
		}

		if (privateCurve == KeyKeys.EC2_P256 /*|| privateCurve == KeyKeys.EC2_P384 || privateCurve == KeyKeys.EC2_P521*/) {
			return generateSharedSecretECDSA(privateKey, publicKey);
		}

		
		// OKP keys (Curve25519)

		privateCurve = privateKey.get(KeyKeys.OKP_Curve);
		publicCurve = publicKey.get(KeyKeys.OKP_Curve);

		if (privateCurve != publicCurve) {
			System.err.println("Public and private keys use different curves.");
			return null;
		}

		// FIXME?: D is seed, not the private scalar
		byte[] privateScalar = privateKey.get(KeyKeys.OKP_D).GetByteString();
		// Take X value as U coordinate
		byte[] publicUCoordinate = publicKey.get(KeyKeys.OKP_X).GetByteString();

		if (privateCurve == KeyKeys.OKP_X25519 /*|| privateCurve == KeyKeys.OKP_X448*/) {
			// Use X25519 directly
			byte[] ret = null;
			byte[] check = new byte[] {0x00};

			ret = X25519(privateScalar, publicUCoordinate);
			for (int i = 0; i < ret.length; i++) {
			   check[0] |= ret[i];
			}
			if (check[0] == 0x00) {
			   // The shared secret is the all-zero value
			   System.err.println("The shared secret is the all-zero value.\n");
			   ret = null;
			}

			return ret;
		}
		
		System.err.println("Failed to generate shared secret.");

		return null;
		
	}

	/**
	 * Takes an input COSE OneKey and converts it from using Ed25519 to
	 * Curve25519 for X25519. Note that this new key will not have correct Java
	 * keys internally.
	 * 
	 * @return the generated COSE OneKey
	 * 
	 * @throws CoseException
	 */
	static OneKey convertEd25519ToCurve25519(OneKey initialKey) throws CoseException {

		FieldElement y = null;
		try {
			// Extract the y coordinate
			y = KeyRemapping.extractCOSE_y(initialKey);
		} catch (CoseException e) {
			System.err.println("Failed to generate Curve25519 key: " + e);
		}

		// Calculate the corresponding Curve25519 u coordinate
		FieldElement u = KeyRemapping.calcCurve25519_u(y);

		// Build the COSE OneKey

		OneKey key = new OneKey();
		
		// The private key
		if (initialKey.AsPrivateKey() != null) {
			EdDSAPrivateKey initialPrivKey = (EdDSAPrivateKey) initialKey.AsPrivateKey();
			byte[] rgbD_bad = initialKey.get(KeyKeys.OKP_D).GetByteString(); // FIXME
			byte[] privateHash = initialPrivKey.getH();
			byte[] privateScalar = Arrays.copyOf(privateHash, 32);
			byte[] rgbD = privateScalar;
			
			// System.out.println("D bad: " + StringUtil.byteArray2HexString(rgbD_bad));
			// System.out.println("D good: " + StringUtil.byteArray2HexString(rgbD));
			
			key.add(KeyKeys.OKP_D, CBORObject.FromObject(rgbD));
		}

		// The X value is the value of the u coordinate
		// FIXME: Compress
		byte[] rgbX = u.toByteArray();

		key.add(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
		key.add(KeyKeys.OKP_Curve, KeyKeys.OKP_X25519);
		key.add(KeyKeys.OKP_X, CBORObject.FromObject(rgbX));

		return key;
	}

	/**
	 * Generate a COSE OneKey using Curve25519 for X25519. Note that this key
	 * will be lacking the Java keys internally.
	 * 
	 * This method uses Ed25519 keys as a starting point.
	 * 
	 * @return the generated COSE OneKey
	 * @throws CoseException
	 */
	@Deprecated
	static OneKey generateCurve25519KeyOld() throws CoseException {

		// Start by generating a Ed25519 key pair
		OneKey initialKey = null;
		try {
			initialKey = OneKey.generateKey(KeyKeys.OKP_Ed25519);
		} catch (CoseException e) {
			System.err.println("Failed to generate Curve25519 key: " + e);
		}

		// Convert and return it as an Curve25519 key
		return convertEd25519ToCurve25519(initialKey);
	}

	/**
	 * Generate a shared secret when using ECDSA.
	 * 
	 * @param senderPrivateKey the public/private key of the sender
	 * @param recipientPublicKey the public key of the recipient
	 * @return the shared secret
	 */
	private static byte[] generateSharedSecretECDSA(OneKey senderPrivateKey, OneKey recipientPublicKey) {

		byte[] sharedSecret = null;

		try {
			ECPublicKey recipientPubKey = (ECPublicKey) recipientPublicKey.AsPublicKey();
			ECPrivateKey senderPrivKey = (ECPrivateKey) senderPrivateKey.AsPrivateKey();

			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
			keyAgreement.init(senderPrivKey);
			keyAgreement.doPhase(recipientPubKey, true);

			sharedSecret = keyAgreement.generateSecret();
		} catch (InvalidKeyException | NoSuchAlgorithmException | CoseException e) {
			System.err.println("Could not generate the shared secret: " + e);
		}

		return sharedSecret;
	}

	/**
	 * Generate a shared secret when using EdDSA.
	 * 
	 * @param senderPrivateKey the public/private key of the sender
	 * @param recipientPublicKey the public key of the recipient
	 * @return the shared secret
	 */
	private static byte[] generateSharedSecretEdDSA(OneKey senderPrivateKey, OneKey recipientPublicKey) {

		byte[] sharedSecret = null;
		try {
			sharedSecret = SharedSecretCalculation.calculateSharedSecret(recipientPublicKey, senderPrivateKey);
		} catch (CoseException e) {
			System.err.println("Could not generate the shared secret: " + e);
		}

		return sharedSecret;
	}

	/**
	 * Run a number of tests on the code.
	 * 
	 * @throws Exception on failure in one of the tests
	 */
	private static void runTests() throws Exception {
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

		System.out.println("Expected: " + StringUtil.byteArray2HexString(correctArray));
		System.out.println("Actual: " + StringUtil.byteArray2HexString(resArray));
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

		System.out.println("Expected: " + StringUtil.byteArray2HexString(correctArray));
		System.out.println("Actual: " + StringUtil.byteArray2HexString(resArray));
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

		System.out.println("R: " + StringUtil.byteArray2HexString(xresult));
		System.out.println("X25519 result is correct: " + Arrays.equals(c, xresult));

		/* Test X25519 test vectors */
		// See https://tools.ietf.org/html/rfc7748#section-5.2

		System.out.println("Test X25519 test vectors");

		// First X25519 test vector

		byte[] inputScalar = StringUtil.hex2ByteArray("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
		byte[] inputUCoordinate = StringUtil.hex2ByteArray("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
		byte[] outputUCoordinate = StringUtil.hex2ByteArray("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

		byte[] myResult = X25519(inputScalar, inputUCoordinate);
		System.out.println("First test vector works: " + Arrays.equals(myResult, outputUCoordinate));

		// Second X25519 test vector

		inputScalar = StringUtil.hex2ByteArray("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
		inputUCoordinate = StringUtil.hex2ByteArray("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
		outputUCoordinate = StringUtil.hex2ByteArray("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

		myResult = X25519(inputScalar, inputUCoordinate);
		System.out.println("Second test vector works: " + Arrays.equals(myResult, outputUCoordinate));

		// Third X25519 test vector (iterations)

		inputScalar = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		inputUCoordinate = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] resultIteration1 = StringUtil.hex2ByteArray("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

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

		byte[] resultIteration1000 = StringUtil.hex2ByteArray(
				"684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
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

			byte[] resultIteration1000000 = StringUtil.hex2ByteArray(
					"7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
			byte[] myResult_1000000 = tK;

			System.out.println("Third test vector works (1 000 000 iterations): "
					+ Arrays.equals(myResult_1000000, resultIteration1000000));
		}

		/* Test Diffie Hellman */
		// See https://tools.ietf.org/html/rfc7748#section-6.1

		byte[] private_key_a = StringUtil.hex2ByteArray("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
		byte[] public_key_KA = StringUtil.hex2ByteArray("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

		byte[] private_key_b = StringUtil.hex2ByteArray("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
		byte[] public_key_KB = StringUtil.hex2ByteArray("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

		byte[] nine = StringUtil.hex2ByteArray("0900000000000000000000000000000000000000000000000000000000000000");

		// Check public keys
		byte[] public_key_KA_calc = X25519(private_key_a, nine);
		byte[] public_key_KB_calc = X25519(private_key_b, nine);

		System.out.println("Public Key KA correct: " + Arrays.equals(public_key_KA_calc, public_key_KA));
		System.out.println("Public Key KB correct: " + Arrays.equals(public_key_KB_calc, public_key_KB));

		byte[] sharedSecret = StringUtil.hex2ByteArray("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

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

		System.out.println("H priv1: " + StringUtil.byteArray2HexString(privateKey1H));
		System.out.println("u from key one (public part): " + uuu1);
		// System.out.println("From key one (private part): " +
		// StringUtil.byteArray2HexString(privateKey1H));

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
		// StringUtil.byteArray2HexString(privateKey2H));

		// Calculated shared secrets
		// X25519(my private scalar, your public key U)
		byte[] sharedSecret1 = X25519(privateKey1H, publicKey2U);
		byte[] sharedSecret2 = X25519(privateKey2H, publicKey1U);

		System.out.println("Shared secret 1: " + StringUtil.byteArray2HexString(sharedSecret1));
		System.out.println("Shared secret 2: " + StringUtil.byteArray2HexString(sharedSecret2));
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
	 * TODO: Update to handle both Ed25519 and Curve25519 already here?
	 * 
	 * @param publicKey the public key (of the other party)
	 * @param privateKey the private key (your own)
	 * @return the shared secret calculated
	 * @throws CoseException on failure
	 */
	private static byte[] calculateSharedSecret(OneKey publicKey, OneKey privateKey) throws CoseException {

		/* Check that the keys are as expected (using Ed25519) */
		if (publicKey.get(KeyKeys.OKP_Curve) != KeyKeys.OKP_Ed25519
				|| privateKey.get(KeyKeys.OKP_Curve) != KeyKeys.OKP_Ed25519) {
			System.err.println(
					"Error: Keys for EdDSA shared secret calculation are not using Ed25519. Use X25519 directly.");
			return null;
		}
		
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

		System.out.println("Shared secret 1: " + StringUtil.byteArray2HexString(sharedSecret1));
		System.out.println("Shared secret 2: " + StringUtil.byteArray2HexString(sharedSecret2));
		System.out.println("Shared secrets match: " + Arrays.equals(sharedSecret1, sharedSecret2));

	}

	/**
	 * Wrapper for the X25519 function
	 * 
	 * @param k the private scalar k
	 * @param u the public u coordinate
	 * @return the shared secret
	 */
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

	/**
	 * Skips decoding the scalar k, since it may not be encoded in the first
	 * place. But in the end it seems decoding multiple times changes nothing.
	 * 
	 * @param k
	 * @param u
	 * @return
	 */
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

	// TODO: Make constant time
	static Tuple cswap(BigInteger swap, FieldElement a, FieldElement b) {

		if (swap.equals(BigInteger.ONE)) {
			return new Tuple(b, a);
		} else {
			return new Tuple(a, b);
		}

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
	
	/**
	 * Left-pad a byte array with 0x00 bytes 
	 * 
	 * @param input the input byte array to pad
	 * @param paddingSize the number of 0x00 bytes to use for padding
	 * @return the left-padded byte array, or null in case of invalid input
	 */
	private static byte[] leftPadByteArray(byte[] input, int paddingSize) {
		
		if (input == null || paddingSize < 0)
			return null;
		
		if (paddingSize == 0)
			return input;

		byte[] output = new byte[input.length + paddingSize];
		for (int i = 0; i < paddingSize; i++) {
			output[i] = (byte) 0x00;
		}
		System.arraycopy(input, 0, output, paddingSize, input.length);
		
		return output;
	}

}
