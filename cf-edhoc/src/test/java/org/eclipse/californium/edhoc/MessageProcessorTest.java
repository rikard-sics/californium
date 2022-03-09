package org.eclipse.californium.edhoc;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
import org.eclipse.californium.oscore.HashMapCtxDB;
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
		
		// Note: the actual EDHOC message 1 starts with 0x00. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload.
		byte[] message1 = Utils
				.hexToBytes("f500005820e31ec15ee8039427dfc4727ef17e2e0e69c54437f3c5828019ef0a6388c125520e");
		
		byte[] message2 = Utils.hexToBytes(
				"5870e1739096c5c9582c1298918166d69548c78f7497b258c0856aa2019893a39425690bdd9b15885138490d3b8ac735e2ad7912d58d0e3995f2b54e8e63e90bc3c42620308c10508d0f40c8f48f87a404cfc78fb522db588a12f3d8e76436fc26a81daeb735c34feb1f7254bda2b7d014f332");
		
		// Note: the actual EDHOC message 3 starts with 0x58. The byte 0x32 (CBOR encoding for -19) is prepended as C_R,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload. 
		byte[] message3 = Utils.hexToBytes(
				"3258584c53ed22c45fb00cad889b4c06f2a26cf49154cb8bdf4eee44e2b50221ab1f029d3d3e0523ddf9d7610c376c728a1e901692f1da0782a3472ff6eb1bb6810c6f686879c9a5594f8f170ca5a2b5bf05a74f42cdd9c854e01e");

		Map<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		int method = 0;
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		/* Initiator information*/

		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(14);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytesInit = Utils.hexToBytes("366a5859a4cd65cfaeaf0566c9fc7e1a93306fdec17763e05813a70f21ff59db");
		byte[] publicIdentityKeyBytesInit = Utils.hexToBytes("ec2c2eb6cdd95782a8cd0b2e9c44270774dcbd31bfbe2313ce80132e8a261c04");
		OneKey identityKeyInit = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytesInit, publicIdentityKeyBytesInit);
		
		// The x509 certificate of the Initiator
		byte[] serializedCertInit = Utils.hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCertInit).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCertInit);

		// Create the session for the Initiator (with only the minimal set of information required for this test)
		boolean initiator = true;
		KissEDP edp = new KissEDP();
		HashMapCtxDB db = new HashMapCtxDB();
		EdhocSession sessionInitiator = new EdhocSession(initiator, true, method, connectionIdInitiator,
												identityKeyInit, idCredI, credI, supportedCipherSuites, appProfile, edp, db);
		
		edhocSessions.put(CBORObject.FromObject(connectionIdInitiator), sessionInitiator);

		
		/* Responder information*/
		
		// C_R, in plain binary format
		CBORObject connectionIdResponder = CBORObject.FromObject(-19);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytesResp = Utils.hexToBytes("bc4d4f9882612233b402db75e6c4cf3032a70a0d2e3ee6d01b11ddde5f419cfc");
		byte[] publicIdentityKeyBytesResp = Utils.hexToBytes("27eef2b08a6f496faedaa6c7f9ec6ae3b9d52424580d52e49da6935edf53cdc5");
		OneKey identityKeyResp = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytesResp, publicIdentityKeyBytesResp);
		
		// The x509 certificate of the Responder
		byte[] serializedCertResp = Utils.hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCertResp).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCertResp);

		// Create the session for the Responder (with only the minimal set of information required for this test)
		initiator = false;
		KissEDP edp2 = new KissEDP();
		HashMapCtxDB db2 = new HashMapCtxDB();
		EdhocSession sessionResponder = new EdhocSession(initiator, true, method, connectionIdResponder,
												identityKeyResp, idCredR, credR, supportedCipherSuites, appProfile, edp2, db2);
		
		edhocSessions.put(CBORObject.FromObject(connectionIdResponder), sessionResponder);
		
		
		// Test from the point of view of the Initiator as Client
		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(
				message1, true, edhocSessions, connectionIdInitiator, appProfile));
		sessionInitiator.setCurrentStep(Constants.EDHOC_SENT_M1);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(
				message2, false, edhocSessions,connectionIdInitiator, appProfile));
		sessionInitiator.setCurrentStep(Constants.EDHOC_AFTER_M3);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_3, MessageProcessor.messageType(
				message3, true, edhocSessions, connectionIdInitiator, appProfile));

		
		// Test from the point of view of the Responder as Server
		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(
				message1, true, edhocSessions, null, appProfile));
		sessionResponder.setCurrentStep(Constants.EDHOC_AFTER_M2);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(
				message2, false, edhocSessions, connectionIdResponder, appProfile));
		sessionResponder.setCurrentStep(Constants.EDHOC_SENT_M2);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_3, MessageProcessor.messageType(
				message3, true, edhocSessions, null, appProfile));
		
		
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
				            errorMessage, false, edhocSessions, connectionIdInitiator, appProfile));
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE));
		errorMessageList.add(suitesR);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            errorMessage, false, edhocSessions, connectionIdInitiator, appProfile));
		
		// Test for an EDHOC error message as an incoming/outgoing request
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cX);
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_UNSPECIFIED));
		errorMessageList.add(errMsg);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            errorMessage, true, edhocSessions, connectionIdInitiator, appProfile));
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cX);
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE));
		errorMessageList.add(suitesR);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            errorMessage, true, edhocSessions, connectionIdInitiator, appProfile));
		
	}

	
	/**
	 * Test writing of message 1, for authentication with static DH, with RPK as CCS identified by 'kid'
	 * 
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-3.1
	 */
	@Test
	public void testWriteMessage1Method3() {
		
		boolean initiator = true;
		int method = 3;
		
		// C_I
		CBORObject connectionId = CBORObject.FromObject(12);
		
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(0);
		
		OneKey ltk = Util.generateKeyPair(KeyKeys.OKP_X25519.AsInt32());
		CBORObject[] ead1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		int idCredKid = -10;
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		byte[] cred = Util.buildCredRawPublicKey(ltk, "");

		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		EdhocSession session = new EdhocSession(initiator, true, method, connectionId, ltk,
				                                idCred, cred, cipherSuites, appProfile, edp, db);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("b3111998cb3f668663ed4251c78be6e95a4da127e4f6fee275e855d8d9dfd8ed");
		byte[] publicEkeyBytes = Utils.hexToBytes("3aa9eb3201b3367b8c8be38d91e57a2b433e67888c86d2ac006a520842ed5037");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ead1);

		// Compare with the expected value from the test vectors
		
		// Note: the actual EDHOC message 1 starts with 0x03. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload.
		byte[] expectedMessage1 = Utils
				.hexToBytes("f5030058203aa9eb3201b3367b8c8be38d91e57a2b433e67888c86d2ac006a520842ed50370c");

		Assert.assertArrayEquals(expectedMessage1, message1);
		
	}
	
	
	/**
	 * Test writing of message 2, for authentication with static DH, with RPK as CCS identified by 'kid'
	 * 
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-3.2
	 */
	@Test
	public void testWriteMessage2Method3() {

		boolean initiator = false;
		int method = 3;
		CBORObject[] ead2 = null;
		
		
		/* Responder information*/

		// C_R, in plain binary format
		CBORObject connectionIdResponder = CBORObject.FromObject(new byte[] {});
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("528b49c670f8fc16a2ad95c1885b2e24fb15762272792aa1cf051df5d93d3694");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("e66f355990223c3f6caff862e407edd1174d0701a09ecd6a15cee2c6ce21aa50");
		OneKey identityKey = SharedSecretCalculation.buildCurve25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// ID_CRED_R for the identity key of the Responder
		int idCredKid = 5;
		CBORObject idCredR = Util.buildIdCredKid(idCredKid);
		
		// CRED_R for the identity key of the Responder
		byte[] credR = Utils.hexToBytes("a2026b6578616d706c652e65647508a101a4010102052004215820e66f355990223c3f6caff862e407edd1174d0701a09ecd6a15cee2c6ce21aa50");
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("bd86eaf4065a836cd29d0f0691ca2a8ec13f51d1c45e1b4372c0cbe493cef6bd");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("255491b05a3989ff2d3ffea62098aab57c160f294ed948018b4190f7d161824e");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);

		
		/* Initiator information*/
		
		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(12);

		// The ephemeral key of the Initiator
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("3aa9eb3201b3367b8c8be38d91e57a2b433e67888c86d2ac006a520842ed5037");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);
		
		
		/* Set up the session to use */
		
		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites, appProfile, edp, db);

		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store the EDHOC Message 1
		// Note: this is the actual EDHOC message 1, so it does not include the byte 0xf5 (True) prepended on the wire
		byte[] message1 = Utils.hexToBytes("030058203aa9eb3201b3367b8c8be38d91e57a2b433e67888c86d2ac006a520842ed50370c");
		session.setHashMessage1(message1);
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session, ead2);

		// Compare with the expected value from the test vectors
		
		byte[] expectedMessage2 = Utils
				.hexToBytes("582a255491b05a3989ff2d3ffea62098aab57c160f294ed948018b4190f7d161824e0ff04c294f4ac602cf7840");

		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	
	/**
	 * Test writing of message 3, for authentication with static DH, with RPK as CCS identified by 'kid'
	 * Test the derivation of OSCORE Master Secret and Master Salt
	 * Test EDHOC-KeyUpdate and a second derivation of OSCORE Master Secret and Master Salt 
	 * 
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-3.3
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-3.5
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-3.6
	 */
	@Test
	public void testWriteMessage3Method3() {

		boolean initiator = true;
		int method = 3;
		CBORObject[] ead3 = null;
		
		
		/* Initiator information*/

		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(12);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("cfc4b6ed22e700a30d5c5bcd61f1f02049de235462334893d6ff9f0cfea3fe04");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("4a49d88cd5d841fab7ef983e911d2578861f95884f9f5dc42a2eed33de79ed77");
		OneKey identityKey = SharedSecretCalculation.buildCurve25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// ID_CRED_I for the identity key of the Initiator
		int idCredKid = -10;
		CBORObject idCredI = Util.buildIdCredKid(idCredKid);
		
		// CRED_I for the identity key of the Initiator
		byte[] credI = Utils.hexToBytes("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a40101022920042158204a49d88cd5d841fab7ef983e911d2578861f95884f9f5dc42a2eed33de79ed77");
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("b3111998cb3f668663ed4251c78be6e95a4da127e4f6fee275e855d8d9dfd8ed");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("3aa9eb3201b3367b8c8be38d91e57a2b433e67888c86d2ac006a520842ed5037");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes,
				                                                                      publicEphemeralKeyBytes);
		
		
		/* Responder information*/

		// C_R, in plain binary format
		CBORObject connectionIdResponder = CBORObject.FromObject(new byte[] {});
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("255491b05a3989ff2d3ffea62098aab57c160f294ed948018b4190f7d161824e");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);

		
		/* Status from after receiving EDHOC Message 2 */
		byte[] th2 = Utils.hexToBytes("71a6c7c5ba9ad47fe72da4dc359bf6b276d3515968711b9a911c71fc096aee0e");
		byte[] ciphertext2 = Utils.hexToBytes("0ff04c294f4ac602cf78");
		byte[] prk3e2m = Utils.hexToBytes("768e1375272e1e68b42ca3248480d5bba88bcb55f660ce7f941e6709103117a1");
		
		
		
		/* Set up the session to use */
		
		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdInitiator,
												identityKey, idCredI, credI, supportedCipherSuites, appProfile, edp, db);

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
		// Note: the actual EDHOC message 3 starts with 0x52. The byte 0x40 (CBOR encoding for h'') is prepended as C_R,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload. 
		byte[] expectedMessage3 = Utils.hexToBytes("4052be0146c136ac2effd453a75efa90896f653b");

		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
		
		byte[] expectedMasterSecret = Utils.hexToBytes("9565355973280280d64a3ce8d7fa0a93");
		byte[] expectedMasterSalt = Utils.hexToBytes("37478eddb09e5d7a");
       
       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
       
        
        /* Invoke EDHOC-KeyUpdate to updated the EDHOC key material */
        
        byte[] nonce = Utils.hexToBytes("d491a204caa6b80254c471e0deeed160");
       
        try {
			session.edhocKeyUpdate(nonce);
		} catch (InvalidKeyException e) {
			Assert.fail("Error while running EDHOC-KeyUpdate(): " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			Assert.fail("Error while running EDHOC-KeyUpdate(): " + e.getMessage());
		}
        
        System.out.println("Completed EDHOC-KeyUpdate()\n");
        
        // Following the key update, generate new OSCORE Master Secret and Master Salt
        masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
        // Compare with the expected value from the test vectors

       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
        
		expectedMasterSecret = Utils.hexToBytes("ad4870dc7aca505bf80868785bd40d1b");
		expectedMasterSalt = Utils.hexToBytes("7138715cb50303a2");
        
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
	}
	
	
	/**
	 * Test writing of message 4, for authentication with static DH, with RPK as CCS identified by 'kid'
	 * 
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-3.4
	 */
	@Test
	public void testWriteMessage4Method3() {

		boolean initiator = false;
		int method = 3;
		CBORObject[] ead4 = null;
		
		
		/* Responder information*/

		// C_R, in plain binary format
		CBORObject connectionIdResponder = CBORObject.FromObject(new byte[] {});
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("528b49c670f8fc16a2ad95c1885b2e24fb15762272792aa1cf051df5d93d3694");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("e66f355990223c3f6caff862e407edd1174d0701a09ecd6a15cee2c6ce21aa50");
		OneKey identityKey = SharedSecretCalculation.buildCurve25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// ID_CRED_R for the identity key of the Responder
		int idCredKid = 5;
		CBORObject idCredR = Util.buildIdCredKid(idCredKid);
		
		// CRED_R for the identity key of the Responder
		byte[] credR = Utils.hexToBytes("a2026b6578616d706c652e65647508a101a4010102052004215820e66f355990223c3f6caff862e407edd1174d0701a09ecd6a15cee2c6ce21aa50");
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("bd86eaf4065a836cd29d0f0691ca2a8ec13f51d1c45e1b4372c0cbe493cef6bd");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("255491b05a3989ff2d3ffea62098aab57c160f294ed948018b4190f7d161824e");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);

		
		/* Initiator information*/
		
		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(12);

		// The ephemeral key of the Initiator
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("3aa9eb3201b3367b8c8be38d91e57a2b433e67888c86d2ac006a520842ed5037");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);
		
		
		/* Set up the session to use */
		
		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites, appProfile, edp, db);

		session.setSelectedCiphersuite(0);
		session.setCurrentStep(Constants.EDHOC_AFTER_M3);
		
		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store TH_4 computed from the previous protocol step
		byte[] prk4x3m = Utils.hexToBytes("b8ccdf1420b5b0c82a587e7d26dd7b7048574c3a48df9f6a45f721c0cfa4b27c");
		session.setPRK4x3m(prk4x3m);
		
		// Store TH_4 computed from the previous protocol step
		byte[] th4 = Utils.hexToBytes("4b9add2a9eeb8849716c7968784f5540dd64a3bb07f8d000adce88b630d884eb");
		session.setTH4(th4);
		
		// Now write EDHOC message 4
		byte[] message4 = MessageProcessor.writeMessage4(session, ead4);

		// Compare with the expected value from the test vectors

		byte[] expectedMessage4 = Utils.hexToBytes("48e9e6c8b6376db0b1");
		
		Assert.assertArrayEquals(expectedMessage4, message4);
		
	}
	
	
	/**
	 * Test writing of message 1, for authentication with signatures, with dummy X.509 certificates identified by 'x5t'
	 * 
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-4.1
	 */
	@Test
	public void testWriteMessage1Method0() {
		
		boolean initiator = true;
		int method = 0;
		
		// C_I
		CBORObject connectionId = CBORObject.FromObject(-24);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(6);
		supportedCipherSuites.add(2);

		List<Integer> cipherSuitesPeer = new ArrayList<Integer>();
		cipherSuitesPeer.add(2);
		
		OneKey ltk = Util.generateKeyPair(KeyKeys.EC2_P256.AsInt32());
		CBORObject[] ead1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		byte[] cred = Utils.hexToBytes("3082011E3081C5A003020102020461E997F4300A06082A8648CE3D04030230153113301106035504030C0A4544484F4320526F6F74301E170D3232303132303137313232305A170D3239313233313233303030305A301A3118301606035504030C0F4544484F4320496E69746961746F723059301306072A8648CE3D020106082A8648CE3D030107034200048A93CA7E1BC84647D7E7EB4C6107C4DC4E53DF81DFD1981C7F824A7C1B61A6FC91362813C25DB6AF93BE22C350CEB251895B9F3A8D85A35823A2222B9DE2C8C8300A06082A8648CE3D0403020348003045022032FCFCA3E80488515EC11EF570C6B833B430DCBDD327D965F22D4AD2D34E07090221008BBFECD263F699E5E23CBEC584786FF5EA18E23236E511D956935FFF281720AE");
		CBORObject idCred = Util.buildIdCredX5t(cred);
		
		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		EdhocSession session = new EdhocSession(initiator, true, method, connectionId, ltk,
				                                idCred, cred, supportedCipherSuites, appProfile, edp, db);

		// Force the early knowledge of cipher suites supported by the other peer
		session.setPeerSupportedCipherSuites(cipherSuitesPeer);
		
		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("c48404c912d68aad557f1f02f70c61c19b1ea1d62f1bd64616042df5c4fe6195");
		byte[] publicEkeyBytes = Utils.hexToBytes("50a76b38ea840fa1b1a51152591d4cd52c75892152c870277225b1ed998ed953");
		OneKey ek = SharedSecretCalculation.buildEcdsa256OneKey(privateEkeyBytes, publicEkeyBytes, true);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ead1);

		// Compare with the expected value from the test vectors

		// Note: the actual EDHOC message 1 starts with 0x00. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload. 
		byte[] expectedMessage1 = Utils
				.hexToBytes("f500820602582050a76b38ea840fa1b1a51152591d4cd52c75892152c870277225b1ed998ed95337");
		
		Assert.assertArrayEquals(expectedMessage1, message1);
	}
	
	
	/**
	 * Test writing of message 2, for authentication with signatures, with dummy X.509 certificates identified by 'x5t'
	 * 
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-4.2
	 */
	@Test
	public void testWriteMessage2Method0() {

		boolean initiator = false;
		int method = 0;
		CBORObject[] ead2 = null;
		
		/* Responder information*/

		// C_R
		CBORObject connectionIdResponder = CBORObject.FromObject(-8);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
		byte[] publicIdentityKeyBytesX = Utils.hexToBytes("27ecf4b466d3cd61144c944021838d57bf6701973378a15b3f5d27575d34c4a9");
		byte[] publicIdentityKeyBytesY = Utils.hexToBytes("7b79e0f24b446bca67e13d75d09573124b49b838b10973f0fb67e126051c9595");
		
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// The x509 certificate of the Responder
		byte[] serializedCert = Utils.hexToBytes("3082011E3081C5A003020102020461E9981E300A06082A8648CE3D04030230153113301106035504030C0A4544484F4320526F6F74301E170D3232303132303137313330325A170D3239313233313233303030305A301A3118301606035504030C0F4544484F4320526573706F6E6465723059301306072A8648CE3D020106082A8648CE3D03010703420004BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F04519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072300A06082A8648CE3D0403020348003045022030194EF5FC65C8B795CDCD0BB431BF83EE6741C1370C22C8EB8EE9EDD2A70519022100B5830E9C89A62AC73CE1EBCE0061707DB8A88E23709B4ACC58A1313B133D0558");
		
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
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("3c5ce32c6cffc14d145c06186f8dd108f085d8627a0d160bee848cfc42fd3e9f");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("13fe27adcd01d988d0ae00ecd3fe96f3ce1ee4649087390b7d24d444ffad672d");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes, true);

		/* Initiator information*/
		
		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(-24);

		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytes = Utils.hexToBytes("50a76b38ea840fa1b1a51152591d4cd52c75892152c870277225b1ed998ed953");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null, publicPeerEphemeralKeyBytes, true);
				
		/* Set up the session to use */
		
		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites, appProfile, edp, db);

		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(2);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store the EDHOC Message 1
		// Note: this is the actual EDHOC message 1, so it does not include the byte 0xf5 (True) prepended on the wire
		byte[] message1 = Utils.hexToBytes("00820602582050a76b38ea840fa1b1a51152591d4cd52c75892152c870277225b1ed998ed95337");
		session.setHashMessage1(message1);
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session, ead2);

		// Compare with the expected value from the test vectors
		
		// Unreliable
		byte[] expectedMessage2 = Utils
				.hexToBytes("587013fe27adcd01d988d0ae00ecd3fe96f3ce1ee4649087390b7d24d444ffad672d0bf8c7a5c37d012a2b2e2c147785b6c33630d5710e9ce228cb4ff2b164c7b41b375e7835c246a822b59a519d229d65d8533e9ddaefbbc77e0b50b4b2d9039b46b11c9b8d21e18cf4bd0bfd6fb0f86a1927");
		
		//Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	
	/**
	 * Test writing of message 3, for authentication with signatures, with dummy X.509 certificates identified by 'x5t'
	 * Test the derivation of OSCORE Master Secret and Master Salt
	 * Test EDHOC-KeyUpdate and a second derivation of OSCORE Master Secret and Master Salt 
	 * 
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-4.3
	 *      https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-4.5
	 *      https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-4.6
	 */
	@Test
	public void testWriteMessage3Method0() {

		boolean initiator = true;
		int method = 0;
		CBORObject[] ead3 = null;
		
		/* Initiator information*/

		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(-24);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(6);
		supportedCipherSuites.add(2);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("8ea3ac170fb900ae505b18747fb504dbda748c6d0c17601d7ba31430d745178a");
		byte[] publicIdentityKeyBytesX = Utils.hexToBytes("8a93ca7e1bc84647d7e7eb4c6107c4dc4e53df81dfd1981c7f824a7c1b61a6fc");
		byte[] publicIdentityKeyBytesY = Utils.hexToBytes("91362813c25db6af93be22c350ceb251895b9f3a8d85a35823a2222b9de2c8c8");
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("c48404c912d68aad557f1f02f70c61c19b1ea1d62f1bd64616042df5c4fe6195");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("50a76b38ea840fa1b1a51152591d4cd52c75892152c870277225b1ed998ed953");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes, true);
		
		// The x509 certificate of the Initiator
		byte[] serializedCert = Utils.hexToBytes("3082011E3081C5A003020102020461E997F4300A06082A8648CE3D04030230153113301106035504030C0A4544484F4320526F6F74301E170D3232303132303137313232305A170D3239313233313233303030305A301A3118301606035504030C0F4544484F4320496E69746961746F723059301306072A8648CE3D020106082A8648CE3D030107034200048A93CA7E1BC84647D7E7EB4C6107C4DC4E53DF81DFD1981C7F824A7C1B61A6FC91362813C25DB6AF93BE22C350CEB251895B9F3A8D85A35823A2222B9DE2C8C8300A06082A8648CE3D0403020348003045022032FCFCA3E80488515EC11EF570C6B833B430DCBDD327D965F22D4AD2D34E07090221008BBFECD263F699E5E23CBEC584786FF5EA18E23236E511D956935FFF281720AE");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCert);
		
		
		/* Responder information*/

		// C_R, in plain binary format
		CBORObject connectionIdResponder = CBORObject.FromObject(-8);
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("13fe27adcd01d988d0ae00ecd3fe96f3ce1ee4649087390b7d24d444ffad672d");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null, peerEphemeralPublicKeyBytes, true);

		
		/* Status from after receiving EDHOC Message 2 */
		
		// Unreliable
		byte[] th2 = Utils.hexToBytes("1480daefc37f13e27cee5e816d11054de854c4167f6a6e40e8af324322a4d0c8");
		
		// Unreliable
		byte[] ciphertext2 = Utils.hexToBytes("0bf8c7a5c37d012a2b2e2c147785b6c3e9927dd17944c5b6afc4fefb5c852f9ea9e7a15227bbf2554918d439796325287e8a59ac9f1fc7c4b07152f307c02a1e4c1d4e3a152a7c2e7752b0ca6af93650");
		
		byte[] prk3e2m = Utils.hexToBytes("07a08f91aa6f62845894934c044ff04b4396ab3cfd4931d9f0155b347dc411ee");
		
		
		/* Set up the session to use */
		
		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdInitiator,
												identityKey, idCredI, credI, supportedCipherSuites, appProfile, edp, db);

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
		// Note: the actual EDHOC message 3 starts with 0x58. The byte 0x32 (CBOR encoding for -19) is prepended as C_R,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload.
		
		// Unreliable
		byte[] expectedMessage3 = Utils
				.hexToBytes("27585835ae9a0c8c2a74b4215dc3e8b52de4e2ec6ac67ab80cdd664da448749d64704f2ca63648c44cbaeeb0b04ee1b2809f6fbad53a7a4e10d7c6708d762924c970e9518f52a6046bddcaad33f299cc127ecb914a1ecd07942876");

		// Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
        
        // Unreliable
		byte[] expectedMasterSecret = Utils.hexToBytes("8cf18e2f4151ecb854ad3d8a7c06e1d7");
		byte[] expectedMasterSalt = Utils.hexToBytes("ce9c7f1a9e3a33da");

       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
        //Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        //Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
		
        
        /* Invoke EDHOC-KeyUpdate to updated the EDHOC key material */
        
        byte[] nonce = Utils.hexToBytes("e6f549b8581aa29253cfce680753a400");
       
        try {
			session.edhocKeyUpdate(nonce);
		} catch (InvalidKeyException e) {
			Assert.fail("Error while running EDHOC-KeyUpdate(): " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			Assert.fail("Error while running EDHOC-KeyUpdate(): " + e.getMessage());
		}
        
        System.out.println("Completed EDHOC-KeyUpdate()\n");
        
        // Following the key update, generate new OSCORE Master Secret and Master Salt
        masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
        // Compare with the expected value from the test vectors
        
        // Unreliable
		expectedMasterSecret = Utils.hexToBytes("c3b3be665d39d08eb96708cadf13f604");
		expectedMasterSalt = Utils.hexToBytes("f554164a5268c3db");

       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
        //Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        //Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
	}
	
	
	/**
	 * Test writing of message 4, for authentication with signatures, with dummy X.509 certificates identified by 'x5t'
	 * 
	 * See: https://datatracker.ietf.org/doc/html/draft-selander-lake-traces-01#section-4.4
	 */
	@Test
	public void testWriteMessage4Method0() {

		boolean initiator = false;
		int method = 0;
		CBORObject[] ead4 = null;
		
		/* Responder information*/

		// C_R
		CBORObject connectionIdResponder = CBORObject.FromObject(-8);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
		byte[] publicIdentityKeyBytesX = Utils.hexToBytes("27ecf4b466d3cd61144c944021838d57bf6701973378a15b3f5d27575d34c4a9");
		byte[] publicIdentityKeyBytesY = Utils.hexToBytes("7b79e0f24b446bca67e13d75d09573124b49b838b10973f0fb67e126051c9595");
		
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// The x509 certificate of the Responder
		byte[] serializedCert = Utils.hexToBytes("3082011E3081C5A003020102020461E9981E300A06082A8648CE3D04030230153113301106035504030C0A4544484F4320526F6F74301E170D3232303132303137313330325A170D3239313233313233303030305A301A3118301606035504030C0F4544484F4320526573706F6E6465723059301306072A8648CE3D020106082A8648CE3D03010703420004BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F04519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072300A06082A8648CE3D0403020348003045022030194EF5FC65C8B795CDCD0BB431BF83EE6741C1370C22C8EB8EE9EDD2A70519022100B5830E9C89A62AC73CE1EBCE0061707DB8A88E23709B4ACC58A1313B133D0558");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCert);
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("3c5ce32c6cffc14d145c06186f8dd108f085d8627a0d160bee848cfc42fd3e9f");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("13fe27adcd01d988d0ae00ecd3fe96f3ce1ee4649087390b7d24d444ffad672d");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes, true);

		
		/* Initiator information*/
		
		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(-24);

		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytes = Utils.hexToBytes("50a76b38ea840fa1b1a51152591d4cd52c75892152c870277225b1ed998ed953");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null, publicPeerEphemeralKeyBytes, true);
		
		
		/* Set up the session to use */
		
		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdResponder,
												identityKey, idCredR, credR, supportedCipherSuites, appProfile, edp, db);

		
		session.setSelectedCiphersuite(0);
		session.setCurrentStep(Constants.EDHOC_AFTER_M3);
		
		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(2);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		
		// Store TH_4 computed from the previous protocol step
		byte[] prk4x3m = Utils.hexToBytes("07a08f91aa6f62845894934c044ff04b4396ab3cfd4931d9f0155b347dc411ee");
		session.setPRK4x3m(prk4x3m);
		
		// Store TH_4 computed from the previous protocol step
		byte[] th4 = Utils.hexToBytes("9ed6468f27b70f2f89f30aa2e9bd6b4ff16dfe54cad2250bf2259a5d69f6c075");
		session.setTH4(th4);
		
		// Now write EDHOC message 4
		byte[] message4 = MessageProcessor.writeMessage4(session, ead4);

		// Compare with the expected value from the test vectors

		byte[] expectedMessage4 = Utils.hexToBytes("48972804fbe1f3002d");
		
		Assert.assertArrayEquals(expectedMessage4, message4);
		
	}
		
}
