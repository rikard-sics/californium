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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
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

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;
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
			Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q(2^255-19)
			new BigIntegerLittleEndianEncoding());


	// public static void java15Curve25519generationGoodX()
	// throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
	// InvalidKeySpecException,
	// InvalidKeyException, IllegalStateException, CoseException {
	// OneKey initialKey = OneKey.generateKey(KeyKeys.OKP_Ed25519);
	//
	// // Now extract the y and x point coordinates
	// FieldElement yf = KeyRemapping.extractCOSE_y(initialKey);
	// FieldElement xf = KeyRemapping.extractCOSE_x(initialKey);
	//
	// // Calculate the corresponding Curve25519 u and v coordinates
	// FieldElement uf = KeyRemapping.calcCurve25519_u(yf);
	// FieldElement vf = KeyRemapping.calcCurve25519_v_alt(xf, uf);
	//
	// KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
	// NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
	// kpg.initialize(paramSpec); // equivalent to kpg.initialize(255)
	// // kpg = KeyPairGenerator.getInstance("X25519");
	// KeyPair kp = kpg.generateKeyPair();
	//
	// KeyFactory kf = KeyFactory.getInstance("XDH");
	// BigInteger u = new
	// BigInteger("1472384792374923478923892479237482379439478923789");
	// XECPublicKeySpec pubSpec = new XECPublicKeySpec(paramSpec, u);
	// PublicKey pubKey = kf.generatePublic(pubSpec);
	//
	// KeyAgreement ka = KeyAgreement.getInstance("XDH");
	// PrivateKey privKey = kp.getPrivate();
	// ka.init(privKey);
	// ka.doPhase(pubKey, true);
	//
	// byte[] privKeyBytes = Arrays.copyOfRange(privKey.getEncoded(),
	// privKey.getEncoded().length - 32,
	// privKey.getEncoded().length);
	//
	// byte[] secret = ka.generateSecret();
	// System.out.println("*Secret1 " + Utils.bytesToHex(secret));
	//
	// byte[] secret11 = X25519(privKeyBytes, invertArray(u.toByteArray()));
	// System.out.println("*Secret11 " + Utils.bytesToHex(secret11));
	//
	// System.out.println("---");
	// }

	// WIP
	public static void java15X25519(OneKey privKeyIn, OneKey pubKeyIn)
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			InvalidKeyException, IllegalStateException, CoseException {

		// Now extract the y coordinate
		FieldElement y = KeyRemapping.extractCOSE_y(pubKeyIn);

		// Calculate the corresponding Curve25519 u coordinate
		FieldElement u = KeyRemapping.calcCurve25519_u(y);
		BigInteger u_bi = new BigInteger(invertArray(u.toByteArray()));

		// Get the D parameter which must here be the private scalar
		byte[] d = privKeyIn.get(KeyKeys.OKP_D).GetByteString();

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
		NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
		kpg.initialize(paramSpec);

		KeyFactory kf = KeyFactory.getInstance("XDH");
		XECPublicKeySpec pubSpec = new XECPublicKeySpec(paramSpec, u_bi);
		PublicKey pubKey = kf.generatePublic(pubSpec);

		KeyAgreement ka = KeyAgreement.getInstance("XDH");
		byte[] privKeyBytesIn = d;
		XECPrivateKeySpec privSpec = new XECPrivateKeySpec(paramSpec, privKeyBytesIn);
		PrivateKey privKey = kf.generatePrivate(privSpec);

		ka.init(privKey);
		ka.doPhase(pubKey, true);

		byte[] privKeyEncoded = privKey.getEncoded();
		byte[] privKeyBytes = Arrays.copyOfRange(privKeyEncoded, privKeyEncoded.length - 32, privKeyEncoded.length);
		byte[] pubKeyEncoded = pubKey.getEncoded();
		byte[] pubKeyBytes = Arrays.copyOfRange(pubKeyEncoded, pubKeyEncoded.length - 32, pubKeyEncoded.length);

		byte[] secret = ka.generateSecret();
		System.out.println("*SecretReal " + Utils.bytesToHex(secret));

		byte[] secret11 = X25519(privKeyBytes, invertArray(u.toByteArray()));
		System.out.println("*SecretB " + Utils.bytesToHex(secret11));

		byte[] secret12 = X25519(privKeyBytes, (pubKeyBytes));
		System.out.println("*SecretC " + Utils.bytesToHex(secret12));

		// byte[] secret12 = X25519(privKeyBytes, (pubKeyBytes));
		// System.out.println("*SecretC " + Utils.bytesToHex(secret12));

		System.out.println("---");
		System.out.println("---");
		System.out.println("---");
		System.out.println("---");
	}

	public static OneKey java15Curve25519generation()
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			InvalidKeyException, IllegalStateException, CoseException {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
		NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
		kpg.initialize(paramSpec);
		KeyPair kp = kpg.generateKeyPair();

		PublicKey pubKey = kp.getPublic();
		PrivateKey privKey = kp.getPrivate();

		byte[] privKeyEncoded = privKey.getEncoded();
		byte[] privKeyBytes = Arrays.copyOfRange(privKeyEncoded, privKeyEncoded.length - 32, privKeyEncoded.length);
		byte[] pubKeyEncoded = pubKey.getEncoded();
		byte[] pubKeyBytes = Arrays.copyOfRange(pubKeyEncoded, pubKeyEncoded.length - 32, pubKeyEncoded.length);

		OneKey key = builCurve25519OneKey(privKeyBytes, pubKeyBytes);

		return key;
	}

	public static void java15Curve25519generationAndSharedSecret()
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			InvalidKeyException, IllegalStateException, CoseException {

		OneKey initialKey = OneKey.generateKey(KeyKeys.OKP_Ed25519);

		// Now extract the y and x point coordinates
		FieldElement y = KeyRemapping.extractCOSE_y(initialKey);
		// FieldElement x = KeyRemapping.extractCOSE_x(initialKey);

		// Calculate the corresponding Curve25519 u and v coordinates
		FieldElement u = KeyRemapping.calcCurve25519_u(y);
		BigInteger u_bi = new BigInteger((u.toByteArray()));
		// FieldElement v = KeyRemapping.calcCurve25519_v_alt(x, u);

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
		NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
		kpg.initialize(paramSpec);
		KeyPair kp = kpg.generateKeyPair();

		KeyFactory kf = KeyFactory.getInstance("XDH");
		// BigInteger u = new
		// BigInteger("1472384792374923478923892479237482379439478923789");
		XECPublicKeySpec pubSpec = new XECPublicKeySpec(paramSpec, u_bi);
		PublicKey pubKey = kf.generatePublic(pubSpec);

		KeyAgreement ka = KeyAgreement.getInstance("XDH");
		PrivateKey privKey = kp.getPrivate();
		ka.init(privKey);
		ka.doPhase(pubKey, true);

		byte[] privKeyEncoded = privKey.getEncoded();
		byte[] privKeyBytes = Arrays.copyOfRange(privKeyEncoded, privKeyEncoded.length - 32, privKeyEncoded.length);
		byte[] pubKeyEncoded = pubKey.getEncoded();
		byte[] pubKeyBytes = Arrays.copyOfRange(pubKeyEncoded, pubKeyEncoded.length - 32, pubKeyEncoded.length);

		byte[] secret = ka.generateSecret();
		System.out.println("*SecretA " + Utils.bytesToHex(secret));

		byte[] secret11 = X25519(privKeyBytes, invertArray(u.toByteArray()));
		System.out.println("*SecretB " + Utils.bytesToHex(secret11));

		byte[] secret12 = X25519(privKeyBytes, (pubKeyBytes));
		System.out.println("*SecretC " + Utils.bytesToHex(secret12));

		System.out.println("---");
		System.out.println("---");
		System.out.println("---");
		System.out.println("---");
	}
	//
	// public static void java15Curve25519generationOld()
	// throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
	// InvalidKeySpecException,
	// InvalidKeyException, IllegalStateException, CoseException {
	// OneKey initialKey = OneKey.generateKey(KeyKeys.OKP_Ed25519);
	//
	// // Now extract the y and x point coordinates
	// FieldElement y = KeyRemapping.extractCOSE_y(initialKey);
	// FieldElement x = KeyRemapping.extractCOSE_x(initialKey);
	//
	// // Calculate the corresponding Curve25519 u and v coordinates
	// // FieldElement u = KeyRemapping.calcCurve25519_u(y);
	// // FieldElement v = KeyRemapping.calcCurve25519_v_alt(x, u);
	//
	// System.out.println("Ed25519 y: " + Utils.bytesToHex(y.toByteArray()));
	// System.out.println("Ed25519 x: " + Utils.bytesToHex(x.toByteArray()));
	//
	// // System.out.println("Curve25519 u: " +
	// // Utils.bytesToHex(u.toByteArray()));
	// // System.out.println("Curve25519 v: " +
	// // Utils.bytesToHex(v.toByteArray()));
	// System.out.println("---");
	// // BigInteger u_bi = new BigInteger(invertArray(u.toByteArray()));
	//
	// //
	//
	// KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
	// NamedParameterSpec paramSpec = new NamedParameterSpec("X25519");
	// kpg.initialize(paramSpec); // equivalent to kpg.initialize(255)
	// // kpg = KeyPairGenerator.getInstance("X25519");
	// KeyPair kp = kpg.generateKeyPair();
	//
	// KeyFactory kf = KeyFactory.getInstance("XDH");
	// BigInteger u = new
	// BigInteger("1472384792374923478923892479237482379439478923789");
	// XECPublicKeySpec pubSpec = new XECPublicKeySpec(paramSpec, u);
	// PublicKey pubKey = kf.generatePublic(pubSpec);
	//
	// System.out.println("Encoded public key: " +
	// Utils.bytesToHex(pubKey.getEncoded()));
	//
	// KeyAgreement ka = KeyAgreement.getInstance("XDH");
	// byte[] privKeyBytesIn = new byte[32];
	// XECPrivateKeySpec privSpec = new XECPrivateKeySpec(paramSpec,
	// privKeyBytesIn);
	// PrivateKey privKey = kf.generatePrivate(privSpec);
	// // PrivateKey privKey = kp.getPrivate();
	// // ka.init(kp.getPrivate());
	// ka.init(privKey);
	// ka.doPhase(pubKey, true);
	//
	// System.out.println("Encoded private key: " +
	// Utils.bytesToHex(privKey.getEncoded()));
	//
	// byte[] privKeyBytes = Arrays.copyOfRange(pubKey.getEncoded(),
	// privKey.getEncoded().length - 32,
	// privKey.getEncoded().length);
	//
	// byte[] secret = ka.generateSecret();
	// System.out.println("*Secret1 " + Utils.bytesToHex(secret));
	//
	// byte[] pubKeyEncoded = pubKey.getEncoded();
	// byte[] pubKeyBytes = Arrays.copyOfRange(pubKey.getEncoded(),
	// pubKeyEncoded.length - 32, pubKeyEncoded.length);
	// byte[] secret2 = X25519(privKeyBytes, pubKeyBytes);
	// System.out.println("Secret2 " + Utils.bytesToHex(secret2));
	// byte[] secret3 = X25519(privKeyBytes, u.toByteArray());
	// System.out.println("Secret3 " + Utils.bytesToHex(secret3));
	// byte[] private_hash = ((EdDSAPrivateKey)
	// initialKey.AsPrivateKey()).getH();
	// byte[] private_scalar = Arrays.copyOf(private_hash, 32);
	// byte[] secret4 = X25519(private_scalar, u.toByteArray());
	// System.out.println("Secret4 " + Utils.bytesToHex(secret4));
	// byte[] secret5 = calculateSharedSecret(initialKey.PublicKey(),
	// initialKey);
	// System.out.println("Secret5 " + Utils.bytesToHex(secret5));
	//
	// byte[] secret6 = X25519(privKeyBytes, invertArray(u.toByteArray()));
	// System.out.println("*Secret6 " + Utils.bytesToHex(secret6));
	//
	// MessageDigest md = MessageDigest.getInstance("SHA-512");
	// byte[] bytesHash = md.digest(privKeyBytes);
	// byte[] pscalar = Arrays.copyOf(bytesHash, 32);
	// System.out.println("Priv scalar: " + Utils.bytesToHex(pscalar));
	//
	// byte[] secret7 = X25519(pscalar, (u.toByteArray()));
	// System.out.println("*Secret7 " + Utils.bytesToHex(secret7));
	//
	// byte[] secret8 = X25519(privKeyBytes, (u.toByteArray()));
	// System.out.println("*Secret8 " + Utils.bytesToHex(secret8));
	//
	// byte[] secret9 = X25519(pscalar, invertArray(u.toByteArray()));
	// System.out.println("*Secret9 " + Utils.bytesToHex(secret9));
	//
	// byte[] secret10 = X25519(privKeyBytes, invertArray(u.toByteArray()));
	// System.out.println("*Secret10 " + Utils.bytesToHex(secret10));
	//
	// byte[] secret11 = X25519(privKeyBytesIn, invertArray(u.toByteArray()));
	// System.out.println("*Secret11 " + Utils.bytesToHex(secret11));
	//
	// byte[] secret12 = X25519(privKeyBytesIn, (u.toByteArray()));
	// System.out.println("*Secret12 " + Utils.bytesToHex(secret12));
	//
	// System.out.println("---");
	//
	//
	// if (Arrays.equals(u.toByteArray(),
	// Arrays.copyOfRange(pubKey.getEncoded(), pubKeyEncoded.length - 32,
	// pubKeyEncoded.length))) {
	// System.out.println("Matching");
	// } else {
	// System.out.println("Not matching");
	// }
	// }

	// https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/math/ec/rfc7748/test/X25519Test.java
	public static void bouncyCastleKeyAgreement() {
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
	 * @return the COSE OneKey
	 */
	static OneKey generateCurve25519KeyTest() {

		// https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/ec/KeyPairGeneratorSpi.java#L251
		// https://stackoverflow.com/questions/57852431/how-to-generate-curve25519-key-pair-for-diffie-hellman-algorithm

		// Start by generating a Curve25519 key pair with BouncyCastle

		// MyRandom rand = new MyRandom();
		SecureRandom rand = new SecureRandom();

		X9ECParameters curveParams = CustomNamedCurves.getByName("Curve25519");
		byte[] seed = Utils.hexToBytes("1122334455667788112233445566778811223344556677881122334455667788");
		ECParameterSpec ecSpec = new ECParameterSpec(curveParams.getCurve(), curveParams.getG(), curveParams.getN(),
				curveParams.getH(), seed);

		System.out.println("Spec using seed: " + Utils.bytesToHex(ecSpec.getSeed()));

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

		System.out.println("D " + Utils.bytesToHex(privKey.getD().toByteArray()));
		System.out.println("Seed priv " + Utils.bytesToHex(privKey.getParameters().getSeed()));
		System.out.println("Seed pub " + Utils.bytesToHex(pubKey.getParameters().getSeed()));
		System.out.println();
		System.out.println("Q pub " + pubKey.getQ().toString());
		System.out.println("Q pub uncompressed " + Utils.bytesToHex(pubKey.getQ().getEncoded(false)));
		System.out.println("Q pub 1st half " + Utils.bytesToHex(Arrays.copyOf(pubKey.getQ().getEncoded(false), 32)));
		System.out.println("Q compressed   " + Utils.bytesToHex(pubKey.getQ().getEncoded(true)));
		System.out.println(
				"getAffineXCoord " + Utils.bytesToHex(pubKey.getQ().getAffineXCoord().toBigInteger().toByteArray()));
		System.out.println(
				"getAffineYCoord " + Utils.bytesToHex(pubKey.getQ().getAffineYCoord().toBigInteger().toByteArray()));
		System.out.println();
		System.out
				.println("getRawXCoord " + Utils.bytesToHex(pubKey.getQ().getRawXCoord().toBigInteger().toByteArray()));
		System.out
				.println("getRawYCoord " + Utils.bytesToHex(pubKey.getQ().getRawYCoord().toBigInteger().toByteArray()));
		System.out.println();
		System.out.println("getXCoord " + Utils.bytesToHex(pubKey.getQ().getXCoord().toBigInteger().toByteArray()));
		System.out.println("getYCoord " + Utils.bytesToHex(pubKey.getQ().getYCoord().toBigInteger().toByteArray()));
		System.out.println();
		System.out.println("Pubkey encoded: " + Utils.bytesToHex(pubKey.getEncoded()));
		System.out.println("Privkey encoded: " + Utils.bytesToHex(privKey.getEncoded()));
		System.out.println();
		System.out.println("S: " + Utils.bytesToHex(privKey.getS().toByteArray()));
		System.out.println();
		privKey.getParameters().getH();
		System.out.println("H: " + Utils.bytesToHex(privKey.getParameters().getH().toByteArray()));
		privKey.getParameters().getH();

		// Get the private D
		byte[] rgbD = privKey.getS().toByteArray();
		// Get the public point Q (compressed true)
		byte[] rgbX = Arrays.copyOf(pubKey.getQ().getEncoded(true), 32);

		// CBORObject keyMap = CBORObject.NewMap();
		//
		// keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
		// keyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_X25519);
		// keyMap.Add(KeyKeys.OKP_X.AsCBOR(), CBORObject.FromObject(rgbX));
		// keyMap.Add(KeyKeys.OKP_D.AsCBOR(), CBORObject.FromObject(rgbD));
		//
		// OneKey key = null;
		// try {
		// key = new OneKey(keyMap);
		// } catch (CoseException e) {
		// System.err.println("Failed to generate COSE OneKey: " + e);
		// }

		// System.out.println(key.AsCBOR());

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
	static OneKey buildEd25519OneKey(byte[] privateKey, byte[] publicKey) {
		byte[] rgbX = publicKey;
		byte[] rgbD = privateKey;

		CBORObject keyMap = CBORObject.NewMap();

		keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
		keyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
		keyMap.Add(KeyKeys.OKP_X.AsCBOR(), CBORObject.FromObject(rgbX));
		keyMap.Add(KeyKeys.OKP_D.AsCBOR(), CBORObject.FromObject(rgbD));

		OneKey key = null;
		try {
			key = new OneKey(keyMap);
		} catch (CoseException e) {
			System.err.println("Failed to generate COSE OneKey: " + e);
		}

		System.out.println(key.AsCBOR());

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
	static OneKey builCurve25519OneKey(byte[] privateKey, byte[] publicKey) {
		byte[] rgbX = publicKey;
		byte[] rgbD = privateKey;

		OneKey key = new OneKey();

		key.add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
		key.add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_X25519);
		key.add(KeyKeys.OKP_X.AsCBOR(), CBORObject.FromObject(rgbX));
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
		// KeyPairGenerator generator = new KeyPairGenerator();
		// SecureRandom secRand = new SecureRandom();
		byte[] seed = privateKey;
		EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(seed, spec);
		EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKeySpec.getA(), spec);

		EdDSAPublicKey pubKeyKey = new EdDSAPublicKey(pubKeySpec);
		// EdDSAPrivateKey privateKeyKey = new EdDSAPrivateKey(privKey);

		// System.out.println("A (public) " +
		// Utils.bytesToHex(pubKeyKey.getAbyte()));
		// System.out.println("Seed (private) " +
		// Utils.bytesToHex(privateKeyKey.getSeed()));

		return pubKeyKey.getAbyte();
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers ECDSA_256.
	 *
	 * @param privateKey the private key bytes
	 * @param publicKeyX the public key X parameter bytes
	 * @param publicKeyY the public key Y parameter bytes
	 * 
	 * @return a OneKey representing the input material
	 */
	static OneKey buildEcdsa256OneKey(byte[] privateKey, byte[] publicKeyX, byte[] publicKeyY) {
		byte[] rgbX = publicKeyX;
		byte[] rgbY = publicKeyY;
		byte[] rgbD = privateKey;

		CBORObject keyMap = CBORObject.NewMap();

		keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
		keyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
		keyMap.Add(KeyKeys.EC2_X.AsCBOR(), CBORObject.FromObject(rgbX));
		keyMap.Add(KeyKeys.EC2_Y.AsCBOR(), CBORObject.FromObject(rgbY));
		keyMap.Add(KeyKeys.EC2_D.AsCBOR(), CBORObject.FromObject(rgbD));

		OneKey key = null;
		try {
			key = new OneKey(keyMap);
		} catch (CoseException e) {
			System.err.println("Failed to generate COSE OneKey: " + e);
		}

		return key;
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
	 * @return the shared secret
	 */
	static byte[] generateSharedSecret(OneKey privateKey, OneKey publicKey) {

		// ECDSA

		CBORObject privateCurve = privateKey.get(KeyKeys.EC2_Curve);
		CBORObject publicCurve = publicKey.get(KeyKeys.EC2_Curve);

		if (privateCurve != publicCurve) {
			System.err.println("Public and private keys use different curves.");
			return null;
		}

		if (privateCurve == KeyKeys.EC2_P256 || privateCurve == KeyKeys.EC2_P384 || privateCurve == KeyKeys.EC2_P521) {
			return generateSharedSecretECDSA(privateKey, publicKey);
		}

		// EdDSA (Ed25519)

		privateCurve = privateKey.get(KeyKeys.OKP_Curve);
		publicCurve = publicKey.get(KeyKeys.OKP_Curve);

		if (privateCurve != publicCurve) {
			System.err.println("Public and private keys use different curves.");
			return null;
		}

		if (privateCurve == KeyKeys.OKP_Ed25519) {
			return generateSharedSecretEdDSA(privateKey, publicKey);
		}

		// EdDSA (Curve25519)

		// FIXME: D is seed, not the private scalar
		byte[] privateScalar = privateKey.get(KeyKeys.OKP_D).GetByteString();
		// Take X value as U coordinate (although it's compressed there)
		byte[] publicUCoordinate = publicKey.get(KeyKeys.OKP_X).GetByteString();

		if (privateCurve == KeyKeys.OKP_X25519) {
			// Use X25519 directly
			return X25519(privateScalar, publicUCoordinate);
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
	static OneKey ed25519ToCurve25519Key(OneKey initialKey) throws CoseException {

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

		// The private key
		EdDSAPrivateKey initialPrivKey = (EdDSAPrivateKey) initialKey.AsPrivateKey();
		byte[] rgbD_bad = initialKey.get(KeyKeys.OKP_D).GetByteString(); // FIXME
		byte[] privateHash = initialPrivKey.getH();
		byte[] privateScalar = Arrays.copyOf(privateHash, 32);
		byte[] rgbD = privateScalar;

		System.out.println("D bad: " + Utils.bytesToHex(rgbD_bad));
		System.out.println("D good: " + Utils.bytesToHex(rgbD));

		// The X value is the value of the u coordinate
		// FIXME: Compress
		byte[] rgbX = u.toByteArray();

		OneKey key = new OneKey();

		key.add(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
		key.add(KeyKeys.OKP_Curve, KeyKeys.OKP_X25519);
		key.add(KeyKeys.OKP_X, CBORObject.FromObject(rgbX));
		key.add(KeyKeys.OKP_D, CBORObject.FromObject(rgbD));

		return key;
	}

	/**
	 * Generate a COSE OneKey using Curve25519 for X25519. Note that this key
	 * will be lacking the Java keys internally.
	 * 
	 * @return the generated COSE OneKey
	 * @throws CoseException
	 */
	static OneKey generateCurve25519Key() throws CoseException {

		// Start by generating a Ed25519 key pair
		OneKey initialKey = null;
		try {
			initialKey = OneKey.generateKey(KeyKeys.OKP_Ed25519);
		} catch (CoseException e) {
			System.err.println("Failed to generate Curve25519 key: " + e);
		}

		// Convert and return it as an Curve25519 key
		return ed25519ToCurve25519Key(initialKey);
	}

	//
	// /**
	// * Generate a COSE OneKey using Curve25519 for X25519. Note that this key
	// * will be lacking the Java keys internally.
	// *
	// * https://cryptojedi.org/peter/data/pairing-20131122.pdf
	// *
	// * @return the COSE OneKey
	// *
	// * @throws CoseException
	// */
	// private static OneKey generateCurve25519KeyManual(OneKey initialKey)
	// throws CoseException {
	//
	// // // Start by generating a Ed25519 key pair
	// //
	// // EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
	// // KeyPairGenerator generator = new KeyPairGenerator();
	// // SecureRandom secRand = new SecureRandom();
	// // try {
	// // generator.initialize(spec, secRand);
	// // } catch (InvalidAlgorithmParameterException e) {
	// // System.err.println("Failed to generate key.");
	// // }
	// // KeyPair keyPair = generator.generateKeyPair();
	// //
	// // PublicKey publicKey = keyPair.getPublic();
	// // PrivateKey privateKey = keyPair.getPrivate();
	// //
	// // // Cast to format from library
	// //
	// // EdDSAPrivateKey privKey = (EdDSAPrivateKey) privateKey;
	// // EdDSAPublicKey pubKey = (EdDSAPublicKey) publicKey;
	//
	// // Start by generating a Ed25519 key (if not provided)
	// if (initialKey == null) {
	// initialKey = OneKey.generateKey(KeyKeys.OKP_Ed25519);
	// }
	//
	// // Now extract the y and x point coordinates
	// FieldElement y = KeyRemapping.extractCOSE_y(initialKey);
	// FieldElement x = KeyRemapping.extractCOSE_x(initialKey);
	//
	// // Calculate the corresponding Curve25519 u and v coordinates
	// FieldElement u = KeyRemapping.calcCurve25519_u(y);
	// FieldElement v = KeyRemapping.calcCurve25519_v_alt(x, u);
	//
	// System.out.println("Ed25519 y: " + Utils.bytesToHex(y.toByteArray()));
	// System.out.println("Ed25519 x: " + Utils.bytesToHex(x.toByteArray()));
	//
	// System.out.println("Curve25519 u: " + Utils.bytesToHex(u.toByteArray()));
	// System.out.println("Curve25519 v: " + Utils.bytesToHex(v.toByteArray()));
	//
	// BigIntegerFieldElement x_bif = KeyRemapping.ed25519ToBiginteger(x);
	// BigInteger x_bi = new BigInteger(invertArray(x_bif.toByteArray()));
	// System.out.println("BigIntegerFieldElement " + x_bif);
	// System.out.println("BigInteger " + x_bi);
	//
	// // BigIntegerFieldElement p = new BigIntegerFieldElement(ed25519Field,
	// // new BigInteger("2"));
	// // BigIntegerFieldElement power = new
	// // BigIntegerFieldElement(ed25519Field, new BigInteger("255"));
	// // BigIntegerFieldElement nineteen = new
	// // BigIntegerFieldElement(ed25519Field, new BigInteger("19"));
	// // p = (BigIntegerFieldElement) p.pow(power);
	// // p = (BigIntegerFieldElement) p.subtract(nineteen);
	//
	// BigInteger pow = new BigInteger("2").pow(255);
	// BigInteger p_bi = pow.subtract(new BigInteger("19"));
	// FieldElement p = new BigIntegerFieldElement(ed25519Field, p_bi);
	// BigIntegerFieldElement x_modulo = (BigIntegerFieldElement) x_bif.mod(p);
	// BigInteger x_modulo_bi = new
	// BigInteger(invertArray(x_modulo.toByteArray()));
	//
	// //
	//
	// BigInteger three = pow.subtract(new BigInteger("5"));
	// BigInteger four = pow.subtract(new BigInteger("8"));
	// BigInteger pminus = p_bi.subtract(three);
	// BigInteger result = pminus.mod(four);
	// System.out.println("Result : " + result);
	//
	// BigIntegerFieldElement y_bif = KeyRemapping.ed25519ToBiginteger(y);
	// BigInteger y_bi = new BigInteger(invertArray(y_bif.toByteArray()));
	// BigInteger two = new BigInteger("2");
	//
	// BigInteger root = bigIntSqRootFloor(x_modulo_bi);
	//
	// // BigInteger square = new BigInteger("101");
	// // BigInteger root = bigIntSqRootFloor(square);
	// BigInteger i = null;
	// if (root.multiply(root).equals(x_modulo_bi)) {
	// System.out.println("NO rounding happened.");
	// i = y_bi.mod(two);
	//
	// } else {
	// System.out.println("Rounding happened.");
	// // i = y_bi.divide(val);
	// }
	//
	// System.out.println("i " + i);
	//
	// // Build the COSE OneKey
	//
	// // byte[] rgbX = pubKey.getAbyte();
	//
	// // The private key / seed remains the same
	// byte[] rgbD = initialKey.get(KeyKeys.OKP_D).GetByteString();
	//
	// OneKey key = new OneKey();
	//
	// key.add(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
	// key.add(KeyKeys.OKP_Curve, KeyKeys.OKP_X25519);
	// // key.add(KeyKeys.OKP_X, CBORObject.FromObject(rgbX));
	// key.add(KeyKeys.OKP_D, CBORObject.FromObject(rgbD));
	//
	// return key;
	// }

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
		Security.insertProviderAt(EdDSA, 0);

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

		byte[] inputScalar = Utils.hexToBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
		byte[] inputUCoordinate = Utils.hexToBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
		byte[] outputUCoordinate = Utils.hexToBytes("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

		byte[] myResult = X25519(inputScalar, inputUCoordinate);
		System.out.println("First test vector works: " + Arrays.equals(myResult, outputUCoordinate));

		// Second X25519 test vector

		inputScalar = Utils.hexToBytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
		inputUCoordinate = Utils.hexToBytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
		outputUCoordinate = Utils.hexToBytes("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

		myResult = X25519(inputScalar, inputUCoordinate);
		System.out.println("Second test vector works: " + Arrays.equals(myResult, outputUCoordinate));

		// Third X25519 test vector (iterations)

		inputScalar = Utils.hexToBytes("0900000000000000000000000000000000000000000000000000000000000000");
		inputUCoordinate = Utils.hexToBytes("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] resultIteration1 = Utils.hexToBytes("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

		byte[] myResult_1 = X25519(inputScalar, inputUCoordinate);
		System.out.println("Third test vector works (1 iteration): " + Arrays.equals(myResult_1, resultIteration1));

		// 1000 iterations

		byte[] tU = Utils.hexToBytes("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] tK = Utils.hexToBytes("0900000000000000000000000000000000000000000000000000000000000000");
		byte[] tR = null;
		for (int i = 0; i < 1000; i++) {

			tR = X25519(tK.clone(), tU.clone()).clone();
			tU = tK;
			tK = tR;

		}

		byte[] resultIteration1000 = Utils
				.hexToBytes("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
		byte[] myResult_1000 = tK;

		System.out.println(
				"Third test vector works (1000 iterations): " + Arrays.equals(myResult_1000, resultIteration1000));

		// 1 000 000 iterations
		// Takes a very long time ~45 minutes

		boolean runMillionTest = false;

		if (runMillionTest) {

			tU = Utils.hexToBytes("0900000000000000000000000000000000000000000000000000000000000000");
			tK = Utils.hexToBytes("0900000000000000000000000000000000000000000000000000000000000000");
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

			byte[] resultIteration1000000 = Utils
					.hexToBytes("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
			byte[] myResult_1000000 = tK;

			System.out.println("Third test vector works (1 000 000 iterations): "
					+ Arrays.equals(myResult_1000000, resultIteration1000000));
		}

		/* Test Diffie Hellman */
		// See https://tools.ietf.org/html/rfc7748#section-6.1

		byte[] private_key_a = Utils.hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
		byte[] public_key_KA = Utils.hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

		byte[] private_key_b = Utils.hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
		byte[] public_key_KB = Utils.hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

		byte[] nine = Utils.hexToBytes("0900000000000000000000000000000000000000000000000000000000000000");

		// Check public keys
		byte[] public_key_KA_calc = X25519(private_key_a, nine);
		byte[] public_key_KB_calc = X25519(private_key_b, nine);

		System.out.println("Public Key KA correct: " + Arrays.equals(public_key_KA_calc, public_key_KA));
		System.out.println("Public Key KB correct: " + Arrays.equals(public_key_KB_calc, public_key_KB));

		byte[] sharedSecret = Utils.hexToBytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

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

		System.out.println("Shared secret 1: " + Utils.bytesToHex(sharedSecret1));
		System.out.println("Shared secret 2: " + Utils.bytesToHex(sharedSecret2));
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

}
