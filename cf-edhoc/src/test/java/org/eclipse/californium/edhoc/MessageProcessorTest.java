package org.eclipse.californium.edhoc;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
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

import net.i2p.crypto.eddsa.Utils;

public class MessageProcessorTest {

	/**
	 * Tests identification of EDHOC messages. Based on messages from the EDHOC
	 * test vectors.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.1.1
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
		byte[] expectedMessage1 = Utils
				.hexToBytes("0d0058208d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c21");

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
		
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x2b };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");
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
		byte[] connectionIdIiniator = new byte[] {};

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
		session.setPeerConnectionId(connectionIdIiniator);
		
		// Store the EDHOC Message 1
		byte[] message1 = Utils.hexToBytes("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40");
		session.setMessage1(message1);
		
		
		// Now write EDHOC message 1
		byte[] message2 = MessageProcessor.writeMessage2(session, ad2);

		// Compare with the expected value from the test vectors
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
		byte[] connectionIdIiniator = new byte[] { 0x16 };

		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytes = Utils.hexToBytes("8d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c");
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
		session.setPeerConnectionId(connectionIdIiniator);
		
		// Store the EDHOC Message 1
		byte[] message1 = Utils.hexToBytes("0d0058208d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c21");
		session.setMessage1(message1);
		
		
		// Now write EDHOC message 1
		byte[] message2 = MessageProcessor.writeMessage2(session, ad2);

		// Compare with the expected value from the test vectors
		byte[] expectedMessage2 = Utils
				.hexToBytes("582052fba0bdc8d953dd86ce1ab2fd7c05a4658c7c30afdbfc3301047069451baf35084adcf6fe9c524c22454deb");

		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
}
