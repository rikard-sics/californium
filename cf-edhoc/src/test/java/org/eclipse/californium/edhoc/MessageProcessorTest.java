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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
	 * Tests identification of EDHOC messages. Based on messages from the EDHOC test vectors.
	 * 
	 */
	@Test
	public void testMessageType() {
		byte[] message1 = Utils
				.hexToBytes("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c2e");
		byte[] message2 = Utils.hexToBytes(
				"582071a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e3758500ff2ac2d7e87ae340e50bbde9f70e8a77f86bf659f43b024a73ee97b6a2b9c5592fd835a15178b7c28af5474a9758148647d3d98a8731e164c9c70528107f40f21463ba811bf039719e7cffaa7f2f440");
		byte[] message3 = Utils.hexToBytes(
				"375858f5f6debd8214051cd583c84096c4801debf35b15363dd16ebd8530dfdcfb34fcd2eb6cad1dac66a479fb38deaaf1d30a7e6817a22ab04f3d5b1e972a0d13ea86c66b60514c9657ea89c57b0401edc5aa8bbcab813cc5d6e7");

		Map<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		// Set the applicability statement
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		int methodCorr = 1;
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		/* Initiator information*/

		// C_I, in plain binary format
		byte[] connectionIdInitiator = new byte[] { 0x09 };
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytesInit = Utils.hexToBytes("2ffce7a0b2b825d397d0cb54f746e3da3f27596ee06b5371481dc0e012bc34d7");
		byte[] publicIdentityKeyBytesInit = Utils.hexToBytes("38e5d54563c2b6a4ba26f3015f61bb706e5c2efdb556d2e1690b97fc3c6de149");
		OneKey identityKeyInit = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytesInit, publicIdentityKeyBytesInit);
		
		// The x509 certificate of the Initiator
		byte[] serializedCertInit = Utils.hexToBytes("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda6");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCertInit).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCertInit);

		// Create the session for the Initiator (with only the minimal set of information required for this test)
		boolean initiator = true;
		KissEDP edp = new KissEDP();
		EdhocSession sessionInitiator = new EdhocSession(initiator, methodCorr, connectionIdInitiator,
												identityKeyInit, idCredI, credI, supportedCipherSuites, appStatement, edp);
		
		edhocSessions.put(CBORObject.FromObject(connectionIdInitiator), sessionInitiator);

		
		/* Responder information*/
		
		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x00 };
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytesResp = Utils.hexToBytes("df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94");
		byte[] publicIdentityKeyBytesResp = Utils.hexToBytes("dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2");
		OneKey identityKeyResp = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytesResp, publicIdentityKeyBytesResp);
		
		// The x509 certificate of the Responder
		byte[] serializedCertResp = Utils.hexToBytes("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb2");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCertResp).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCertResp);

		// Create the session for the Responder (with only the minimal set of information required for this test)
		initiator = false;
		KissEDP edp2 = new KissEDP();
		EdhocSession sessionResponder = new EdhocSession(initiator, methodCorr, connectionIdResponder,
												identityKeyResp, idCredR, credR, supportedCipherSuites, appStatement, edp2);
		
		edhocSessions.put(CBORObject.FromObject(connectionIdResponder), sessionResponder);
		
		
		// Test from the point of view of the Initiator as Client
		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(
				message1, true, edhocSessions, connectionIdInitiator, appStatement));
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(
				message2, false, edhocSessions,connectionIdInitiator, appStatement));
		sessionInitiator.setCurrentStep(Constants.EDHOC_AFTER_M3);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_3, MessageProcessor.messageType(
				message3, true, edhocSessions, connectionIdInitiator, appStatement));

		
		// Test from the point of view of the Responder as Server
		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(
				message1, true, edhocSessions, null, appStatement));
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(
				message2, false, edhocSessions, connectionIdResponder, appStatement));
		sessionResponder.setCurrentStep(Constants.EDHOC_SENT_M2);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_3, MessageProcessor.messageType(
				message3, true, edhocSessions, null, appStatement));
		
		
		// Error message is not from test vectors
		CBORObject cX = CBORObject.FromObject(new byte[] { (byte) 0x59, (byte) 0xe9 });
		CBORObject errMsg = CBORObject.FromObject("Something went wrong");
		CBORObject suitesR = CBORObject.FromObject(1);
		List<CBORObject> errorMessageList;
		
		// Test for an EDHOC error message as an incoming/outgoing response
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_UNSPECIFIED));
		errorMessageList.add(errMsg);
		byte[] errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            errorMessage, false, edhocSessions, connectionIdInitiator, appStatement));
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE));
		errorMessageList.add(suitesR);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            errorMessage, false, edhocSessions, connectionIdInitiator, appStatement));
		
		// Test for an EDHOC error message as an incoming/outgoing request
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cX);
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_UNSPECIFIED));
		errorMessageList.add(errMsg);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            errorMessage, true, edhocSessions, connectionIdInitiator, appStatement));
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cX);
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE));
		errorMessageList.add(suitesR);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            errorMessage, true, edhocSessions, connectionIdInitiator, appStatement));
		
	}

	/**
	 * Test writing of message 1 and compare to the test vector in B.1.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-05#appendix-B.1.1
	 */
	@Test
	public void testWriteMessage1B1() {
		// First set up the session to use
		boolean initiator = true;
		int methodCorr = 1;
		byte[] connectionId = new byte[] { 0x09 };
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(0);
		OneKey ltk = Util.generateKeyPair(KeyKeys.OKP_Ed25519.AsInt32());
		CBORObject[] ead1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		byte[] cred = Utils.hexToBytes("47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb28f9cf6180b5a6af31e80209a085cfbf95f3fdcf9b18b693d6c0e0d0ffb8e3f9a32a50859ecd0bfcff2c218");
		CBORObject idCred = Util.buildIdCredX5t(cred);
		
		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionId, ltk,
				                                idCred, cred, cipherSuites, appStatement, edp);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("8f781a095372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35");
		byte[] publicEkeyBytes = Utils.hexToBytes("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ead1);

		// Compare with the expected value from the test vectors

		byte[] expectedMessage1 = Utils
				.hexToBytes("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c2e");
		
		Assert.assertArrayEquals(expectedMessage1, message1);
	}
	
	/**
	 * Test writing of message 1 and compare to the test vector in B.2.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-05#appendix-B.2.1
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
		CBORObject[] ead1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		byte[] idCredKid = new byte[] {(byte) 0x24};
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		byte[] cred = Util.buildCredRawPublicKey(ltk, "");

		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionId, ltk,
				                                idCred, cred, cipherSuites, appStatement, edp);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("ae11a0db863c0227e53992feb8f5924c50d0a7ba6eeab4ad1ff24572f4f57cfa");
		byte[] publicEkeyBytes = Utils.hexToBytes("8d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ead1);

		// Compare with the expected value from the test vectors
		
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
		CBORObject[] ead1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		byte[] idCredKid = new byte[] {(byte) 0x23};
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		byte[] cred = Util.buildCredRawPublicKey(ltk, "");

		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionId, ltk,
				                                idCred, cred, cipherSuites, appStatement, edp);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("0ae799775cb151bfc2548735f44acf1d9429cf9a95ddcd2a139e3a28d863a081");
		byte[] publicEkeyBytes = Utils.hexToBytes("475776f844979ad0b463c5a6a4343a663d17a3a80e38a81d3e3496f6061fd716");
		OneKey ek = SharedSecretCalculation.buildEcdsa256OneKey(privateEkeyBytes, publicEkeyBytes, null);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ead1);

		// Compare with the expected value from the test vectors
		
		// Self-produced (test vectors are still missing)
		byte[] expectedMessage1 = Utils
				.hexToBytes("0d025820475776f844979ad0b463c5a6a4343a663d17a3a80e38a81d3e3496f6061fd71621");

		Assert.assertArrayEquals(expectedMessage1, message1);
		
	}
	
	/**
	 * Test writing of message 2 and compare to the test vector in B.1.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-05#appendix-B.1.2
	 */
	@Test
	public void testWriteMessage2B1() {

		boolean initiator = false;
		int methodCorr = 1;
		CBORObject[] ead2 = null;
		
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x00 };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The x509 certificate of the Responder
		byte[] serializedCert = Utils.hexToBytes("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb2");
		
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
		byte[] connectionIdInitiator = new byte[] { 0x09 };

		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytes = Utils.hexToBytes("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, publicPeerEphemeralKeyBytes);
		
		
		/* Set up the session to use */
		
		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites, appStatement, edp);

		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store the EDHOC Message 1
		byte[] message1 = Utils.hexToBytes("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c2e");
		session.setMessage1(message1);
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session, ead2);

		// Compare with the expected value from the test vectors
		
		byte[] expectedMessage2 = Utils
				.hexToBytes("582071a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e3758500ff2ac2d7e87ae340e50bbde9f70e8a77f86bf659f43b024a73ee97b6a2b9c5592fd835a15178b7c28af5474a9758148647d3d98a8731e164c9c70528107f40f21463ba811bf039719e7cffaa7f2f440");
		
		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	
	/**
	 * Test writing of message 2 and compare to the test vector in B.2.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-05#appendix-B.2.2
	 */
	@Test
	public void testWriteMessage2B2() {

		boolean initiator = false;
		int methodCorr = 13;
		CBORObject[] ead2 = null;
		
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x00 };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("bb501aac67b9a95f97e0eded6b82a662934fbbfc7ad1b74c1fcad66a079422d0");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");
		OneKey identityKey = SharedSecretCalculation.buildCurve25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// ID_CRED_R for the identity key of the Responder
		byte[] idCredKid = new byte[] {(byte) 0x05};
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
		
		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites, appStatement, edp);

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
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session, ead2);

		// Compare with the expected value from the test vectors
		
		byte[] expectedMessage2 = Utils
				.hexToBytes("582052fba0bdc8d953dd86ce1ab2fd7c05a4658c7c30afdbfc3301047069451baf35374aa3f1bd5d028d19cf3c99");

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
		CBORObject[] ead2 = null;
		
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x00 };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("ec93c2f8a58f123daa982688e384f54c10c50a1d2c90c00304f648e58f14354c");
		byte[] publicIdentityKeyXBytes = Utils.hexToBytes("6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f");
		byte[] publicIdentityKeyYBytes = Utils.hexToBytes("C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800");
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyXBytes, publicIdentityKeyYBytes);
		
		// ID_CRED_R for the identity key of the Responder
		byte[] idCredKid = new byte[] {(byte) 0x05};
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

		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites, appStatement, edp);

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
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session, ead2);

		// Compare with the expected value from the test vectors
		
		// Self-produced (test vectors are still missing)
		byte[] expectedMessage2 = Utils
				.hexToBytes("582081df54b3756acfc8a1e9b08ba10de4e7e7dd934587a1ecdb21b92f8f22c3a38d374adecc8c4895e398a6b9c8");

		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	/**
	 * Test writing of message 3 and compare to the test vector in B.1.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-05#appendix-B.1.3
	 */
	@Test
	public void testWriteMessage3B1() {

		boolean initiator = true;
		int methodCorr = 1;
		CBORObject[] ead3 = null;
		
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		/* Initiator information*/

		// C_I, in plain binary format
		byte[] connectionIdInitiator = new byte[] { 0x09 };
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("2ffce7a0b2b825d397d0cb54f746e3da3f27596ee06b5371481dc0e012bc34d7");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("38e5d54563c2b6a4ba26f3015f61bb706e5c2efdb556d2e1690b97fc3c6de149");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("8f781a095372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);
		
		// The x509 certificate of the Initiator
		byte[] serializedCert = Utils.hexToBytes("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda6");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCert);
		
		
		/* Responder information*/

		// C_R, in plain binary format
		byte[] connectionIdResponder = new byte[] { 0x00 };
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("71a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);

		
		/* Status from after receiving EDHOC Message 2 */
		byte[] th2 = Utils.hexToBytes("864e32b36a7b5f21f19e99f0c66d911e0ace9972d376d2c2c153c17f8e9629ff");
		byte[] ciphertext2 = Utils.hexToBytes("0ff2ac2d7e87ae340e50bbde9f70e8a77f86bf659f43b024a73ee97b6a2b9c5592fd835a15178b7c28af5474a9758148647d3d98a8731e164c9c70528107f40f21463ba811bf039719e7cffaa7f2f440");
		byte[] prk3e2m = Utils.hexToBytes("ec6292a067f137fc7f59629d226fbfc4e0688949f662a97fd82fbeb79971394a");
		
		
		/* Set up the session to use */
		
		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdInitiator,
												identityKey, idCredI, credI, supportedCipherSuites, appStatement, edp);

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
		byte[] message3 = MessageProcessor.writeMessage3(session, ead3);

		// Compare with the expected value from the test vectors
		
		byte[] expectedMessage3 = Utils
				.hexToBytes("375858f5f6debd8214051cd583c84096c4801debf35b15363dd16ebd8530dfdcfb34fcd2eb6cad1dac66a479fb38deaaf1d30a7e6817a22ab04f3d5b1e972a0d13ea86c66b60514c9657ea89c57b0401edc5aa8bbcab813cc5d6e7");

		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
        
		// From version -02 of the draft
		byte[] expectedMasterSecret = Utils.hexToBytes("96aa88ce865eba1ffaf38964132cc442");
		byte[] expectedMasterSalt = Utils.hexToBytes("5ec3ee417cfbbae9");
        
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
	}
	
	
	/**
	 * Test writing of message 3 and compare to the test vector in B.2.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-05#appendix-B.2.3
	 */
	@Test
	public void testWriteMessage3B2() {

		boolean initiator = true;
		int methodCorr = 13;
		CBORObject[] ead3 = null;
		
		
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
		byte[] idCredKid = new byte[] {(byte) 0x23};
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
		byte[] connectionIdResponder = new byte[] { 0x00 };
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("52fba0bdc8d953dd86ce1ab2fd7c05a4658c7c30afdbfc3301047069451baf35");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);

		
		/* Status from after receiving EDHOC Message 2 */
		byte[] th2 = Utils.hexToBytes("decfd64a3667640a0233b04aa8aa91f68956b8a536d0cf8c73a6e8a7c3621e26");
		byte[] ciphertext2 = Utils.hexToBytes("a3f1bd5d028d19cf3c99");
		byte[] prk3e2m = Utils.hexToBytes("75077c691e35012d48bc24c84f2bab89f52fac03fedd813e438c93b10b399307");
		
		
		
		/* Set up the session to use */
		
		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdInitiator,
												identityKey, idCredI, credI, supportedCipherSuites, appStatement, edp);

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
		byte[] message3 = MessageProcessor.writeMessage3(session, ead3);

		// Compare with the expected value from the test vectors
		
		byte[] expectedMessage3 = Utils.hexToBytes("3752d5535f3147e85f1cfacd9e78abf9e0a81bbf");

		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
		
		// From version -02 of the draft
		byte[] expectedMasterSecret = Utils.hexToBytes("c34a506d0ebfbd17030486135f9cb350");
		byte[] expectedMasterSalt = Utils.hexToBytes("c224349d9b34ca8c");
        
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
		CBORObject[] ead3 = null;
		
		
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
		byte[] idCredKid = new byte[] {(byte) 0x23};
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
		byte[] connectionIdResponder = new byte[] { 0x00 };
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("81df54b3756acfc8a1e9b08ba10de4e7e7dd934587a1ecdb21b92f8f22c3a38d");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null, peerEphemeralPublicKeyBytes, null);

		
		/* Status from after receiving EDHOC Message 2 */
		byte[] th2 = Utils.hexToBytes("d5672ca43b8a3e8ddab270174a4bb101772c5c206c12f435565c4748781152b5");
		byte[] ciphertext2 = Utils.hexToBytes("decc8c4895e398a6b9c8");
		byte[] prk3e2m = Utils.hexToBytes("80f79d96d715f22481ee8e906aa7f4c1aaa25207437d9a26baee32e393ed72be");
		
		
		/* Set up the session to use */
		
		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionIdInitiator,
												identityKey, idCredI, credI, supportedCipherSuites, appStatement, edp);

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
		byte[] message3 = MessageProcessor.writeMessage3(session, ead3);

		// Compare with the expected value from the test vectors
		
		// Self-produced (test vectors are still missing)
		byte[] expectedMessage3 = Utils.hexToBytes("37521055d4dada6efae005eb5e42ad37cc33c168");
		
		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
       
		// Self-produced (test vectors are still missing)
		byte[] expectedMasterSecret = Utils.hexToBytes("d03b2f9c614f80be341703aad3116084");
		byte[] expectedMasterSalt = Utils.hexToBytes("342ba2af96607d2d");
        
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
	}
	
}
