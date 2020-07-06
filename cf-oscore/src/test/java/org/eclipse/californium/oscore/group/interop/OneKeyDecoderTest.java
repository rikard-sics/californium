package org.eclipse.californium.oscore.group.interop;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.security.Provider;
import java.security.Security;
import java.util.Random;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.CounterSign1;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.OneKeyDecoder;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

/**
 * Test decoding functions for COSE OneKey.
 * 
 *
 */
public class OneKeyDecoderTest {

	static Random rand = new Random();

	/**
	 * Install crypto provider for EdDSA
	 */
	@BeforeClass
	public static void installCryptoProvider() {
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);
	}

	/**
	 * Decode ECDSA_256 OneKey from string with CBOR diagnostic notation.
	 * 
	 * @throws CoseException on failure to extract public/private parts
	 */
	@Test
	public void testDiagnosticDecodingEcdsa256() throws CoseException {
		// ECDSA_256
		OneKey ecdsaKey = OneKeyDecoder.parseDiagnostic(
				"{1: 2, -1: 1, -2: h’E2A7DC0C5D23831A4F52FBFF759EF01A6B3A7D58694774D6E8505B31A351D6C4’, -3: h’F8CA44FEDC6C322D0946FC69AE7482CD066AD11F34AA5F5C63F4EADB320FD941’, -4: h’469C76F26B8D9F286449F42566AB8B8BA1B3A8DC6E711A1E2A6B548DBE2A1578’}");

		// Check Algorithm, Key type & Curve
		// assertEquals(AlgorithmID.ECDSA_256.AsCBOR(),
		// ecdsaKey.get(KeyKeys.Algorithm));
		assertEquals(KeyKeys.KeyType_EC2, ecdsaKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.EC2_P256, ecdsaKey.get(KeyKeys.EC2_Curve));

		// Check that it contains both public and private key parts
		assertNotNull(ecdsaKey.AsPrivateKey());
		assertNotNull(ecdsaKey.AsPublicKey());

		// Attempt to sign using the key to see that it works
		byte[] signatureBytes = doCountersign(ecdsaKey);
		assertEquals(64, signatureBytes.length);
	}

	/**
	 * Decode ECDSA_256 OneKey from string with CBOR diagnostic notation. The
	 * string contains only the public key.
	 * 
	 * @throws CoseException on failure to extract public/private parts
	 */
	@Test
	public void testDiagnosticDecodingEcdsa256Public() throws CoseException {
		// ECDSA_256
		OneKey ecdsaPublicKey = OneKeyDecoder.parseDiagnostic(
				"{1: 2, -3: h'F8CA44FEDC6C322D0946FC69AE7482CD066AD11F34AA5F5C63F4EADB320FD941', -2: h'E2A7DC0C5D23831A4F52FBFF759EF01A6B3A7D58694774D6E8505B31A351D6C4', -1: 1, 3: -7}");

		// Check Algorithm, Key type & Curve
		assertEquals(AlgorithmID.ECDSA_256.AsCBOR(), ecdsaPublicKey.get(KeyKeys.Algorithm));
		assertEquals(KeyKeys.KeyType_EC2, ecdsaPublicKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.EC2_P256, ecdsaPublicKey.get(KeyKeys.EC2_Curve));

		// Check that it contains only the public key
		assertNull(ecdsaPublicKey.AsPrivateKey());
		assertNotNull(ecdsaPublicKey.AsPublicKey());
	}

	/**
	 * Decode EDDSA OneKey from string with CBOR diagnostic notation.
	 * 
	 * @throws CoseException on failure to extract public/private parts
	 */
	@Test
	public void testDiagnosticDecodingEddsa() throws CoseException {
		// EdDSA
		OneKey eddsaKey = OneKeyDecoder.parseDiagnostic(
				"{1: 1, -1: 6, -2: h’2A279191227491C92E9C5AEDCF72F5C73E78E19C7E77172B4FEFCE09018AEFD4’, -4: h’D744189028C8F2652EBBF3576B4CB740926B25DA087043E978AE570AAD333495’}");

		// Check Algorithm, Key type & Curve
		// assertEquals(AlgorithmID.EDDSA.AsCBOR(),
		// eddsaKey.get(KeyKeys.Algorithm));
		assertEquals(KeyKeys.KeyType_OKP, eddsaKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.OKP_Ed25519, eddsaKey.get(KeyKeys.OKP_Curve));

		// Check that it contains both public and private key parts
		assertNotNull(eddsaKey.AsPrivateKey());
		assertNotNull(eddsaKey.AsPublicKey());

		// Attempt to sign using the key to see that it works
		byte[] signatureBytes = doCountersign(eddsaKey);
		assertEquals(64, signatureBytes.length);
	}

	/**
	 * Decode EDDSA OneKey from string with CBOR diagnostic notation. The string
	 * contains only the public key.
	 * 
	 * @throws CoseException on failure to extract public/private parts
	 */
	@Test
	public void testDiagnosticKeyEddsaPublic() throws CoseException {
		// EdDSA public key only
		OneKey eddsaPublicKey = OneKeyDecoder.parseDiagnostic(
				"{1: 1, -2: h'2A279191227491C92E9C5AEDCF72F5C73E78E19C7E77172B4FEFCE09018AEFD4', -1: 6, 3: -8}");

		// Check Algorithm, Key type & Curve
		assertEquals(AlgorithmID.EDDSA.AsCBOR(), eddsaPublicKey.get(KeyKeys.Algorithm));
		assertEquals(KeyKeys.KeyType_OKP, eddsaPublicKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.OKP_Ed25519, eddsaPublicKey.get(KeyKeys.OKP_Curve));

		// Check that it contains only the public key
		assertNull(eddsaPublicKey.AsPrivateKey());
		assertNotNull(eddsaPublicKey.AsPublicKey());
	}

	/**
	 * Test building a OneKey from raw bytes representing a public key.
	 * 
	 * @throws CoseException on failure to extract public/private parts
	 */
	@Test
	public void testRawBytesEddsaPublic() throws CoseException {
		byte[] keyBytes = Utils.hexToBytes("508AFC1C29037EF3614D63AF87E1EA31D891D76B1F906098AF8FA39BBE874019");

		OneKey eddsaPublicKey = OneKeyDecoder.fromRawPublicBytes(AlgorithmID.EDDSA, keyBytes);

		// Check Algorithm, Key type & Curve
		assertEquals(AlgorithmID.EDDSA.AsCBOR(), eddsaPublicKey.get(KeyKeys.Algorithm));
		assertEquals(KeyKeys.KeyType_OKP, eddsaPublicKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.OKP_Ed25519, eddsaPublicKey.get(KeyKeys.OKP_Curve));

		// Check that it contains only the public key
		assertNull(eddsaPublicKey.AsPrivateKey());
		assertNotNull(eddsaPublicKey.AsPublicKey());
	}

	/**
	 * Attempts to sign some bytes as a countersignature with a OneKey.
	 * 
	 * @param signKey the key to sign with
	 * @return the bytes of the countersignature
	 * 
	 * @throws CoseException if signing fails
	 */
	public static byte[] doCountersign(OneKey signKey) throws CoseException {

		Encrypt0Message enc = new Encrypt0Message(false, true);

		byte[] confidential = Bytes.createBytes(rand, 20);
		enc.SetContent(confidential);

		byte[] aad = Bytes.createBytes(rand, 10);
		enc.setExternal(aad);

		byte[] nonce = Bytes.createBytes(rand, 13);
		enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
		enc.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND);

		OneKey senderPrivateKey = signKey;
		CounterSign1 sign = new CounterSign1(senderPrivateKey);

		CBORObject signAlg = OneKeyDecoder.getAlgFromCurve(signKey).AsCBOR();
		sign.addAttribute(HeaderKeys.Algorithm, signAlg, Attribute.DO_NOT_SEND);

		enc.setCountersign1(sign);

		byte[] signAad = Bytes.createBytes(rand, 15);
		sign.setExternal(signAad); // Set external AAD for signing

		byte[] key = Bytes.createBytes(rand, 16);
		enc.encrypt(key);

		CBORObject mySignature = enc.getUnprotectedAttributes().get(HeaderKeys.CounterSignature0.AsCBOR());
		byte[] countersignBytes = mySignature.GetByteString();

		return countersignBytes;
	}


}
