package org.eclipse.californium.edhoc;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

public class MessageProcessorTest {

	/**
	 * Tests identification of EDHOC messages. Based on messages from the EDHOC
	 * test vectors.
	 * 
	 */
	@Test
	public void testMessageType() {
		byte[] message1 = Utils
				.hexToBytes("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40");
		byte[] message2 = Utils.hexToBytes(
				"582071a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e13585099d53801a725bfd6a4e71d0484b755ec383df77a916ec0dbc02bba7c21a200807b4f585f728b671ad678a43aacd33b78ebd566cd004fc6f1d406f01d9704e705b21552a9eb28ea316ab65037d717862e");
		byte[] message3 = Utils.hexToBytes(
				"846a5369676e6174757265314ea11822822e485b786988439ebcf258895820a239a627ada3802db8dae51ec392bfeb926d393ef6eee4ddb32e4a27ce9358da5865fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda632c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b7485eefb885983c22d9");

		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(message1));
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(message2));
		Assert.assertEquals(Constants.EDHOC_MESSAGE_3, MessageProcessor.messageType(message3));

		// Error message is not from test vectors
		CBORObject cx = CBORObject.FromObject(new byte[] { (byte) 0x59, (byte) 0xe9 });
		CBORObject errMsg = CBORObject.FromObject("Something went wrong");
		CBORObject suitesR = CBORObject.FromObject(1);
		
		List<CBORObject> errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cx);
		errorMessageList.add(errMsg);
		errorMessageList.add(suitesR);
		byte[] errorMessage = Util.buildCBORSequence(errorMessageList);
		
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(errorMessage));
	}

	/* 
	 * The following covers the two test vectors available at
	 * https://github.com/lake-wg/edhoc/blob/master/test-vectors/vectors.txt
	 * 
	 * */
	
	/**
	 * Test writing of message 1 and compare to the test vector in B.1.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.1.1
	 */
	@Test
	public void testWriteMessage1B1() {
		// First set up the session to use
		boolean initiator = true;
		int methodCorr = 1;
		byte[] connectionId = Bytes.EMPTY;
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(0);
		OneKey ltk = Util.generateKeyPair(KeyKeys.OKP_Ed25519.AsInt32());
		byte[] ad1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		byte[] cred = Utils.hexToBytes("47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb28f9cf6180b5a6af31e80209a085cfbf95f3fdcf9b18b693d6c0e0d0ffb8e3f9a32a50859ecd0bfcff2c218");
		CBORObject idCred = Util.buildIdCredX5t(cred);
		
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionId, ltk, idCred, cred, cipherSuites);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("8f781a095372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35");
		byte[] publicEkeyBytes = Utils.hexToBytes("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ad1);

		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMessage1 = Utils
				.hexToBytes("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40");

		Assert.assertArrayEquals(expectedMessage1, message1);
	}
	
	/**
	 * Test writing of message 1 and compare to the test vector in B.2.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.2.1
	 */
	@Test
	public void testWriteMessage1B2() {
		// First set up the session to use
		boolean initiator = true;
		int methodCorr = 13;
		byte[] connectionId = new byte[] { 0x16 };
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(0);
		OneKey ltk = Util.generateKeyPair(KeyKeys.OKP_X25519.AsInt32());
		byte[] ad1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		byte[] idCredKid = new byte[] {(byte) 0x24};
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		byte[] cred = Util.buildCredRawPublicKey(ltk, "");

		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionId, ltk, idCred, cred, cipherSuites);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("ae11a0db863c0227e53992feb8f5924c50d0a7ba6eeab4ad1ff24572f4f57cfa");
		byte[] publicEkeyBytes = Utils.hexToBytes("8d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ad1);

		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMessage1 = Utils
				.hexToBytes("0d0058208d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c21");

		Assert.assertArrayEquals(expectedMessage1, message1);
		
	}
	
	/**
	 * Test writing of message 1 with ciphersuite 2 and method 3.
	 * 
	 */
	@Test
	public void testWriteMessage1Ciphersuite2Method3() {
		// First set up the session to use
		boolean initiator = true;
		int methodCorr = 13;
		byte[] connectionId = new byte[] { 0x16 };
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(2);
		OneKey ltk = Util.generateKeyPair(KeyKeys.EC2_P256.AsInt32());
		byte[] ad1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		byte[] idCredKid = new byte[] {(byte) 0x24};
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		byte[] cred = Util.buildCredRawPublicKey(ltk, "");

		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionId, ltk, idCred, cred, cipherSuites);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("0ae799775cb151bfc2548735f44acf1d9429cf9a95ddcd2a139e3a28d863a081");
		byte[] publicEkeyBytes = Utils.hexToBytes("475776f844979ad0b463c5a6a4343a663d17a3a80e38a81d3e3496f6061fd716");
		OneKey ek = SharedSecretCalculation.buildEcdsa256OneKey(privateEkeyBytes, publicEkeyBytes, null);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ad1);

		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMessage1 = Utils
				.hexToBytes("0d025820475776f844979ad0b463c5a6a4343a663d17a3a80e38a81d3e3496f6061fd71621");

		Assert.assertArrayEquals(expectedMessage1, message1);
		
	}
	
	/**
	 * Test writing of message 2 and compare to the test vector in B.1.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.1.2
	 */
	@Test
	public void testWriteMessage2B1() {

		boolean initiator = false;
		int methodCorr = 1;
		byte[] ad2 = null;
		
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x2b };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("DBD9DC8CD03FB7C3913511462BB23816477C6BD8D66EF5A1A070AC854ED73FD2");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The x509 certificate of the Responder
		byte[] serializedCert = Utils.hexToBytes("47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb28f9cf6180b5a6af31e80209a085cfbf95f3fdcf9b18b693d6c0e0d0ffb8e3f9a32a50859ecd0bfcff2c218");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCert);
		
		// Open point: the parsing of the certificate fails. Is it an actually valid x509 certificate ?
		/*
		ByteArrayInputStream inputStream = new ByteArrayInputStream(credR);
		try {
			System.out.println((Utils.bytesToHex(inputStream.readAllBytes())));
		} catch (IOException e) {
			fail("Error when printing the input bytes: " + e.getMessage());
			return;
		}
		
		CertificateFactory certFactory;
		X509Certificate cert;
		try {
			certFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			fail("Error when initializing the Certificate Factory: " + e.getMessage());
			return;
		}
		try {
			cert = (X509Certificate)certFactory.generateCertificate(inputStream);
		} catch (CertificateException e) {
			fail("Error when decoding the x509 certificate: " + e.getMessage());
			return;
		}
		if (cert == null) {
			fail("Decoded a null certificate");
			return;
		}
		PublicKey pk = cert.getPublicKey();
		
		OneKey publicKey;
		try {
			publicKey = new OneKey(pk, null);
		} catch (CoseException e) {
			fail("Error when rebuilding the COSE key from : " + e.getMessage());
			return;
		}
		byte[] publicPart = publicKey.AsCBOR().get(KeyKeys.OKP_X.AsCBOR()).GetByteString();
		identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicPart);
		*/
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("fd8cd877c9ea386e6af34ff7e606c4b64ca831c8ba33134fd4cd7167cabaecda");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("71a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);

		
		/* Initiator information*/
		
		// C_I, in plain binary format
		byte[] connectionIdInitiator = new byte[] {};

		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytes = Utils.hexToBytes("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, publicPeerEphemeralKeyBytes);
		
		
		/* Set up the session to use */
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites);

		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store the EDHOC Message 1
		byte[] message1 = Utils.hexToBytes("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40");
		session.setMessage1(message1);
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session, ad2);

		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMessage2 = Utils
				.hexToBytes("582071a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e13585099d53801a725bfd6a4e71d0484b755ec383df77a916ec0dbc02bba7c21a200807b4f585f728b671ad678a43aacd33b78ebd566cd004fc6f1d406f01d9704e705b21552a9eb28ea316ab65037d717862e");

		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	
	/**
	 * Test writing of message 2 and compare to the test vector in B.2.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.2.2
	 */
	@Test
	public void testWriteMessage2B2() {

		boolean initiator = false;
		int methodCorr = 13;
		byte[] ad2 = null;
		
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x20 };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("bb501aac67b9a95f97e0eded6b82a662934fbbfc7ad1b74c1fcad66a079422d0");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");
		OneKey identityKey = SharedSecretCalculation.buildCurve25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// ID_CRED_R for the identity key of the Responder
		byte[] idCredKid = new byte[] {(byte) 0x07};
		CBORObject idCredR = Util.buildIdCredKid(idCredKid);
		
		// CRED_R for the identity key of the Responder
		byte[] credR = Util.buildCredRawPublicKey(identityKey, "");
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("c646cddc58126e18105f01ce35056e5ebc35f4d4cc510749a3a5e069c116169a");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("52fba0bdc8d953dd86ce1ab2fd7c05a4658c7c30afdbfc3301047069451baf35");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);

		
		/* Initiator information*/
		
		// C_I, in plain binary format
		byte[] connectionIdInitiator = new byte[] { 0x16 };

		// The ephemeral key of the Initiator
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("8d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);
		
		
		/* Set up the session to use */
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites);

		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store the EDHOC Message 1
		byte[] message1 = Utils.hexToBytes("0d0058208d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c21");
		session.setMessage1(message1);
		
		
		// Now write EDHOC message 1
		byte[] message2 = MessageProcessor.writeMessage2(session, ad2);

		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMessage2 = Utils
				.hexToBytes("582052fba0bdc8d953dd86ce1ab2fd7c05a4658c7c30afdbfc3301047069451baf35084adcf6fe9c524c22454deb");

		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	/**
	 * Test writing of message 2 with ciphersuite 2 and method 3.
	 * 
	 */
	@Test
	public void testWriteMessage2Ciphersuite2Method3() {

		boolean initiator = false;
		int methodCorr = 13;
		byte[] ad2 = null;
		
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x20 };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("ec93c2f8a58f123daa982688e384f54c10c50a1d2c90c00304f648e58f14354c");
		byte[] publicIdentityKeyXBytes = Utils.hexToBytes("6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f");
		byte[] publicIdentityKeyYBytes = Utils.hexToBytes("C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800");
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyXBytes, publicIdentityKeyYBytes);
		
		// ID_CRED_R for the identity key of the Responder
		byte[] idCredKid = new byte[] {(byte) 0x07};
		CBORObject idCredR = Util.buildIdCredKid(idCredKid);
		
		// CRED_R for the identity key of the Responder
		byte[] credR = Util.buildCredRawPublicKey(identityKey, "");
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("7397ba34a7b60a4d98ef5e91563fc8549f3554494f1febd465360c4b90e74171");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("81df54b3756acfc8a1e9b08ba10de4e7e7dd934587a1ecdb21b92f8f22c3a38d");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes, null);

		
		/* Initiator information*/
		
		// C_I, in plain binary format
		byte[] connectionIdInitiator = new byte[] { 0x16 };

		// The ephemeral key of the Initiator
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("475776f844979ad0b463c5a6a4343a663d17a3a80e38a81d3e3496f6061fd716");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null, peerEphemeralPublicKeyBytes, null);
		
		
		/* Set up the session to use */
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites);

		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(2);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store the EDHOC Message 1
		byte[] message1 = Utils.hexToBytes("0d025820475776f844979ad0b463c5a6a4343a663d17a3a80e38a81d3e3496f6061fd71621");
		session.setMessage1(message1);
		
		
		// Now write EDHOC message 1
		byte[] message2 = MessageProcessor.writeMessage2(session, ad2);

		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMessage2 = Utils
				.hexToBytes("582081df54b3756acfc8a1e9b08ba10de4e7e7dd934587a1ecdb21b92f8f22c3a38d084a93b13712a0c0bc9f9f74");

		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	/**
	 * Test writing of message 3 and compare to the test vector in B.1.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.1.3
	 */
	@Test
	public void testWriteMessage3B1() {

		boolean initiator = true;
		int methodCorr = 1;
		byte[] ad3 = null;
		
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		/* Initiator information*/

		// C_I, in plain binary format
		byte[] connectionIdInitiator = new byte[] {};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("2ffce7a0b2b825d397d0cb54f746e3da3f27596ee06b5371481dc0e012bc34d7");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("38E5D54563C2B6A4BA26F3015F61BB706E5C2EFDB556D2E1690B97FC3C6DE149");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("8f781a095372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);
		
		// The x509 certificate of the Initiator
		byte[] serializedCert = Utils.hexToBytes("fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda632c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b7");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCert);
		
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x2b };
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("71a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);

		
		/* Status from after receiving EDHOC Message 2 */
		byte[] th2 = Utils.hexToBytes("b0dc6c1ba0bae6e2888610fa0b27bfc52e311a47b9cafb609de4f6a1760d6cf7");
		byte[] ciphertext2 = Utils.hexToBytes("99d53801a725bfd6a4e71d0484b755ec383df77a916ec0dbc02bba7c21a200807b4f585f728b671ad678a43aacd33b78ebd566cd004fc6f1d406f01d9704e705b21552a9eb28ea316ab65037d717862e");
		byte[] prk3e2m = Utils.hexToBytes("ec6292a067f137fc7f59629d226fbfc4e0688949f662a97fd82fbeb79971394a");
		
		
		/* Set up the session to use */
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdInitiator,
												identityKey, idCredI, credI, supportedCipherSuites);

		// Set the ephemeral keys, i.e. X and G_X for the initiator, as well as G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdResponder);
		
		// Set TH_2 from the previous protocol step
		session.setTH2(th2);
		
		// Set CIPHERTEXT_2 from the previous protocol step
		session.setCiphertext2(ciphertext2);
		
		// Set PRK_3e2m from the previous protocol step
		session.setPRK3e2m(prk3e2m);
		
		
		// Now write EDHOC message 3
		byte[] message3 = MessageProcessor.writeMessage3(session, ad3);

		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMessage3 = Utils
				.hexToBytes("1358582d88ff86da47482c0dfa559ac824a4a783d870c9dba47805e8aafbad6974c49646586503fa9bbf3e00012c037eaf56e45e301920839b813a53f6d4c557480f6c797d5b76f0e462f5f57a3db6d2b50c32319f340f4ac5af9a");

		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
        
		// From version -02 of the draft
		byte[] expectedMasterSecret = Utils.hexToBytes("EB9E7C0816374154C8ECD839845F2562");
		byte[] expectedMasterSalt = Utils.hexToBytes("BCE4BF914B707DC1");
        
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
	}
	
	
	/**
	 * Test writing of message 3 and compare to the test vector in B.2.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.2.3
	 */
	@Test
	public void testWriteMessage3B2() {

		boolean initiator = true;
		int methodCorr = 13;
		byte[] ad3 = null;
		
		
		/* Initiator information*/

		// C_I, in plain binary format
		byte[] connectionIdInitiator = new byte[] { 0x16 };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("2bbea655c23371c329cfbd3b1f02c6c062033837b8b59099a4436f666081b08e");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71");
		OneKey identityKey = SharedSecretCalculation.buildCurve25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// ID_CRED_I for the identity key of the Initiator
		byte[] idCredKid = new byte[] {(byte) 0x24};
		CBORObject idCredI = Util.buildIdCredKid(idCredKid);
		
		// CRED_I for the identity key of the Initiator
		byte[] credI = Util.buildCredRawPublicKey(identityKey, "");		
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("ae11a0db863c0227e53992feb8f5924c50d0a7ba6eeab4ad1ff24572f4f57cfa");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("8d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes,
				                                                                      publicEphemeralKeyBytes);
		
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x20 };
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("52fba0bdc8d953dd86ce1ab2fd7c05a4658c7c30afdbfc3301047069451baf35");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);

		
		/* Status from after receiving EDHOC Message 2 */
		byte[] th2 = Utils.hexToBytes("6a2878e84b2cc021cc1aeba2965253ef42f7fa300caf9c491a52e6836a2564ff");
		byte[] ciphertext2 = Utils.hexToBytes("dcf6fe9c524c22454deb");
		byte[] prk3e2m = Utils.hexToBytes("75077c691e35012d48bc24c84f2bab89f52fac03fedd813e438c93b10b399307");
		
		
		
		/* Set up the session to use */
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdInitiator,
												identityKey, idCredI, credI, supportedCipherSuites);

		// Set the ephemeral keys, i.e. X and G_X for the initiator, as well as G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdResponder);
		
		// Set TH_2 from the previous protocol step
		session.setTH2(th2);
		
		// Set CIPHERTEXT_2 from the previous protocol step
		session.setCiphertext2(ciphertext2);
		
		// Set PRK_3e2m from the previous protocol step
		session.setPRK3e2m(prk3e2m);
		
		
		// Now write EDHOC message 3
		byte[] message3 = MessageProcessor.writeMessage3(session, ad3);

		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMessage3 = Utils.hexToBytes("085253c3991999a5ffb86921e99b607c067770e0");

		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMasterSecret = Utils.hexToBytes("e7aeafdb28574a9f7970f059159dee68");
		byte[] expectedMasterSalt = Utils.hexToBytes("fb4c673029e2a0a1");
        
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
	}
	
	/**
	 * Test writing of message 3 with ciphersuite 2 and method 3.
	 * 
	 */
	@Test
	public void testWriteMessage3Ciphersuite2Method3() {

		boolean initiator = true;
		int methodCorr = 13;
		byte[] ad3 = null;
		
		
		/* Initiator information*/

		// C_I, in plain binary format
		byte[] connectionIdInitiator = new byte[] { 0x16 };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("04f347f2bead699adb247344f347f2bdac93c7f2bead6a9d2a9b24754a1e2b62");
		byte[] publicIdentityKeyXBytes = Utils.hexToBytes("cd4177ba62433375ede279b5e18e8b91bc3ed8f1e174474a26fc0edb44ea5373");
		byte[] publicIdentityKeyYBytes = Utils.hexToBytes("A0391DE29C5C5BADDA610D4E301EAAA18422367722289CD18CBE6624E89B9CFD");
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes,
																		 publicIdentityKeyXBytes, publicIdentityKeyYBytes);
		
		// ID_CRED_I for the identity key of the Initiator
		byte[] idCredKid = new byte[] {(byte) 0x24};
		CBORObject idCredI = Util.buildIdCredKid(idCredKid);
		
		// CRED_I for the identity key of the Initiator
		byte[] credI = Util.buildCredRawPublicKey(identityKey, "");		
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("0ae799775cb151bfc2548735f44acf1d9429cf9a95ddcd2a139e3a28d863a081");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("475776f844979ad0b463c5a6a4343a663d17a3a80e38a81d3e3496f6061fd716");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
				                                                          publicEphemeralKeyBytes, null);
		
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x20 };
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("81df54b3756acfc8a1e9b08ba10de4e7e7dd934587a1ecdb21b92f8f22c3a38d");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null, peerEphemeralPublicKeyBytes, null);

		
		/* Status from after receiving EDHOC Message 2 */
		byte[] th2 = Utils.hexToBytes("ce10ae2553fc703715bab97dcf211bfed0a2305c82093d5aa62954c4f7a9a8a3");
		byte[] ciphertext2 = Utils.hexToBytes("93b13712a0c0bc9f9f74");
		byte[] prk3e2m = Utils.hexToBytes("80f79d96d715f22481ee8e906aa7f4c1aaa25207437d9a26baee32e393ed72be");
		
		
		
		/* Set up the session to use */
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdInitiator,
												identityKey, idCredI, credI, supportedCipherSuites);

		// Set the ephemeral keys, i.e. X and G_X for the initiator, as well as G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(2);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdResponder);
		
		// Set TH_2 from the previous protocol step
		session.setTH2(th2);
		
		// Set CIPHERTEXT_2 from the previous protocol step
		session.setCiphertext2(ciphertext2);
		
		// Set PRK_3e2m from the previous protocol step
		session.setPRK3e2m(prk3e2m);
		
		
		// Now write EDHOC message 3
		byte[] message3 = MessageProcessor.writeMessage3(session, ad3);

		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMessage3 = Utils.hexToBytes("0852a7e2f47e7bce019e5bb810de9a6fe26d48a3");
		
		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
		
		// Compare with the expected value from the test vectors
		byte[] expectedMasterSecret = Utils.hexToBytes("63e8b8675f32571915e1d967103e85b3");
		byte[] expectedMasterSalt = Utils.hexToBytes("dca80650d73224e7");
        
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
	}
	
}
