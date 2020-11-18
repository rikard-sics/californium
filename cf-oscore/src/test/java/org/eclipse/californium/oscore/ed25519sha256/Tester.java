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

public class Tester {

	public static void main(String[] args)
			throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException,
			SignatureException {
		// System.out.println("HELLO");
 
		// Need to add own provider!
		Security.addProvider(new XYZProvider());
		
		// Install cryptographic provider for EDDSA itself
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

		// Provider[] mine = Security.getProviders();
		// for(int i = 0 ; i < mine.length ; i++) {
		// System.out.println(mine[i].toString());
		// }
		//
		// MessageDigest myhash = null;
		// try {
		// myhash = MessageDigest.getInstance("XYZ");
		// } catch (NoSuchAlgorithmException e) {
		// // TODO Auto-generated catch block
		// e.printStackTrace();
		// }
		//
		// System.out.println("LEN: " + myhash.getDigestLength());

		// === Key generation preparation ===

		// String hash = "sha-512";
		String hash = "XYZ";
		MessageDigest myDigest = MessageDigest.getInstance(hash);

		KeyPairGenerator generator = new KeyPairGenerator();
		SecureRandom secRand = new SecureRandom();

		Field ed25519field = new Field(
				256, // b
				Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
				new Ed25519LittleEndianEncoding());

		Curve ed25519curve = new Curve(ed25519field,
				Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), // d
				ed25519field.fromByteArray(Utils.hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))); // I

		final String ED_25519 = "Ed25519";

		EdDSANamedCurveSpec ED_25519_SHA256_CURVE_SPEC = new EdDSANamedCurveSpec(
				ED_25519,
				ed25519curve,
				hash, // H - Hash to use
				new Ed25519ScalarOps(), // l
				ed25519curve.createPoint( // B
						Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"),
						true)); // Precompute tables for B

		EdDSANamedCurveSpec spec = ED_25519_SHA256_CURVE_SPEC;
		generator.initialize(spec, secRand);

		// === Generate keys ===
		KeyPair keyPair = generator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		// === Cast to format from library ===
		EdDSAPrivateKey privKey = (EdDSAPrivateKey) privateKey;
		EdDSAPublicKey pubKey = (EdDSAPublicKey) publicKey;

		System.out.println("Public key hash algo: " + pubKey.getParams().getHashAlgorithm());
		System.out.println("Private key hash algo: " + privKey.getParams().getHashAlgorithm());

		// === One way of signing ===

		// byte[] data = new byte[] { 0x11, 0x22, 0x33, 0x44 };
		// Signature sig = Signature.getInstance("NonewithEdDSA");
		// sig.initSign(privKey);
		// sig.update(data);
		//
		// byte[] signature = sig.sign();
		// System.out.println("Resulting signature: " +
		// Utils.bytesToHex(signature));

		// === Other way of signing ===

		byte[] data = new byte[] { 0x11, 0x22, 0x33, 0x44 };
		Signature sig = new EdDSAEngine(myDigest);
		sig.initSign(privKey);
		sig.update(data);

		byte[] signature = sig.sign();
		System.out.println("Resulting signature: " + Utils.bytesToHex(signature));

	}
}
