package org.eclipse.californium.oscore.ed25519sha256;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import org.junit.Assert;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.math.Curve;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding;
import net.i2p.crypto.eddsa.math.ed25519.Ed25519ScalarOps;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class Tester4 {

	public static void main(String[] args) throws InvalidAlgorithmParameterException, InvalidKeyException,
			NoSuchAlgorithmException, SignatureException {

		// Need to add own provider!
		Security.addProvider(new XYZProvider());

		// Install cryptographic provider for EDDSA itself
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

		// === Key generation preparation ===

		// String hash = "SHA-512";
		String hash = "XYZ";
		MessageDigest myDigest = MessageDigest.getInstance(hash);

		MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");

		KeyPairGenerator generator = new KeyPairGenerator();
		SecureRandom secRand = new SecureRandom();

		Field ed25519field = new Field(256, // b
				Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
				new Ed25519LittleEndianEncoding());

		Curve ed25519curve = new Curve(ed25519field,
				Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), // d
				ed25519field.fromByteArray(
						Utils.hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))); // I

		final String ED_25519 = "Ed25519";

		EdDSANamedCurveSpec ED_25519_TESTING_CURVE_SPEC = new EdDSANamedCurveSpec(ED_25519, ed25519curve, hash, // H
				new Ed25519ScalarOps(), // l
				ed25519curve.createPoint( // B
						Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"), true)); // Precompute

		EdDSANamedCurveSpec ED_25519_SHA512OWN_CURVE_SPEC = new EdDSANamedCurveSpec(ED_25519, ed25519curve, "Sha512Own", // H
				new Ed25519ScalarOps(), // l
				ed25519curve.createPoint( // B
						Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"), true)); // Precompute

		EdDSANamedCurveSpec ED_25519_SHA256_CURVE_SPEC = new EdDSANamedCurveSpec(ED_25519, ed25519curve, "Sha256Double", // H
				new Ed25519ScalarOps(), // l
				ed25519curve.createPoint( // B
						Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"), true)); // Precompute

		EdDSANamedCurveSpec spec = ED_25519_TESTING_CURVE_SPEC;
		generator.initialize(spec, secRand);

		// === Take keys from test vectors with SHA512 ===
		// https://tools.ietf.org/html/rfc8032#section-7.1 : Test 2

		System.out.println();
		System.out.println("Doing signature with Ed25519-SHA512 from test vectors:");

		byte[] privKeyBytes = Utils.hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
		EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(privKeyBytes, EdDSANamedCurveTable.getByName(ED_25519));
		EdDSAPrivateKey priv = new EdDSAPrivateKey(privSpec);

		byte[] pubKeyBytes = Utils.hexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
		EdDSAPublicKeySpec pubSpec = new EdDSAPublicKeySpec(pubKeyBytes, EdDSANamedCurveTable.getByName(ED_25519));
		EdDSAPublicKey pub = new EdDSAPublicKey(pubSpec);

		System.out.println("Public key hash algo: " + priv.getParams().getHashAlgorithm());
		System.out.println("Private key hash algo: " + pub.getParams().getHashAlgorithm());

		byte[] message = new byte[] { 0x72 };
		Signature sigSha512 = new EdDSAEngine(sha512Digest);
		sigSha512.initSign(priv);
		sigSha512.update(message);
		byte[] res = sigSha512.sign();
		System.out.println("Resulting signature w. SHA512: " + Utils.bytesToHex(res));

		byte[] correct = Utils.hexToBytes(
				"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
		Assert.assertArrayEquals(correct, res);

		// === Take keys from test vectors with my hash method (matching SHA512)
		// https://tools.ietf.org/html/rfc8032#section-7.1 : Test 2

		System.out.println();
		System.out.println("**Doing signature with Ed25519-SHA512 (my own version):");

		privKeyBytes = Utils.hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
		privSpec = new EdDSAPrivateKeySpec(privKeyBytes, ED_25519_SHA512OWN_CURVE_SPEC);
		priv = new EdDSAPrivateKey(privSpec);

		pubKeyBytes = Utils.hexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
		pubSpec = new EdDSAPublicKeySpec(pubKeyBytes, ED_25519_SHA512OWN_CURVE_SPEC);
		pub = new EdDSAPublicKey(pubSpec);

		System.out.println("Public key hash algo: " + priv.getParams().getHashAlgorithm());
		System.out.println("Private key hash algo: " + pub.getParams().getHashAlgorithm());
		System.out.println("Priv private scalar: " + Utils.bytesToHex(priv.getH()));
		System.out.println("Priv seed: " + Utils.bytesToHex(priv.getSeed()));
		System.out.println("Priv a: " + Utils.bytesToHex(priv.geta()));

		MessageDigest digest = MessageDigest.getInstance("Sha512Own");
		message = new byte[] { 0x72 };
		sigSha512 = new EdDSAEngine(digest);
		sigSha512.initSign(priv);
		sigSha512.update(message);
		res = sigSha512.sign();
		System.out.println("**Resulting signature w. SHA512 (my own version): " + Utils.bytesToHex(res));

		correct = Utils.hexToBytes(
				"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
		Assert.assertArrayEquals(correct, res);

		// === Generate keys w. my testing hash ===

		System.out.println();
		System.out.println("Doing signature with " + myDigest.getAlgorithm());

		KeyPair keyPair = generator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		// === Cast to format from library ===
		EdDSAPrivateKey privKey = (EdDSAPrivateKey) privateKey;
		EdDSAPublicKey pubKey = (EdDSAPublicKey) publicKey;

		System.out.println("Public key hash algo: " + pubKey.getParams().getHashAlgorithm());
		System.out.println("Private key hash algo: " + privKey.getParams().getHashAlgorithm());

		// === Signing w. my testing hash ===

		byte[] data = new byte[] { 0x72 };
		Signature sig = new EdDSAEngine(myDigest);
		sig.initSign(privKey);
		sig.update(data);

		byte[] signature = sig.sign();
		System.out.println("Resulting signature: " + Utils.bytesToHex(signature));

		// == Testing my hash that is 2 x SHA256 ===
		// https://www.di-mgt.com.au/sha_testvectors.html

		System.out.println();
		System.out.println("Testing Sha256 double hash");

		MessageDigest sha256Double = MessageDigest.getInstance("Sha256Double");
		byte[] input = new byte[] { 0x61, 0x62, 0x63 };
		byte[] resSha256Double = sha256Double.digest(input);
		System.out.println("Sha-256-double: " + Utils.bytesToHex(resSha256Double));

		correct = Utils.hexToBytes(
				"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015adba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
		Assert.assertArrayEquals(correct, resSha256Double);

		// === Generate keys with 2 x SHA256 hash ===

		System.out.println();
		System.out.println("Doing signature with " + sha256Double.getAlgorithm());

		EdDSANamedCurveSpec specSha256 = ED_25519_SHA256_CURVE_SPEC;
		generator.initialize(specSha256, secRand);

		keyPair = generator.generateKeyPair();
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();

		// === Cast to format from library ===
		privKey = (EdDSAPrivateKey) privateKey;
		pubKey = (EdDSAPublicKey) publicKey;

		System.out.println("Public key hash algo: " + pubKey.getParams().getHashAlgorithm());
		System.out.println("Private key hash algo: " + privKey.getParams().getHashAlgorithm());

		// === Signing with 2 x SHA256 hash ===

		data = new byte[] { 0x72 };
		sig = new EdDSAEngine(sha256Double);
		sig.initSign(privKey);
		sig.update(data);

		signature = sig.sign();
		System.out.println("Resulting signature: " + Utils.bytesToHex(signature));

		// === Now check that signature ===
		sig = new EdDSAEngine(sha256Double);
		sig.initVerify(pubKey);
		sig.update(data);
		boolean signatureCorrect = sig.verify(signature);
		System.out.println("Signature correct: " + signatureCorrect);

	}
}
