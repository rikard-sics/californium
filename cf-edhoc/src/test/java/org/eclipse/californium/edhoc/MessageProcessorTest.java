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

		Map<Integer, OneKey> keyPairsI = new HashMap<Integer, OneKey>();
	    Map<Integer, CBORObject> credsI = new HashMap<Integer, CBORObject>();
	    Map<Integer, CBORObject> idCredsI = new HashMap<Integer, CBORObject>();
	    keyPairsI.put(Integer.valueOf(Constants.CURVE_Ed25519), identityKeyInit);
	    credsI.put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credI));
	    idCredsI.put(Integer.valueOf(Constants.CURVE_Ed25519), idCredI);

		// Create the session for the Initiator (with only the minimal set of information required for this test)
		boolean initiator = true;
		KissEDP edp = new KissEDP();
		HashMapCtxDB db = new HashMapCtxDB();
		EdhocSession sessionInitiator = new EdhocSession(initiator, true, method, connectionIdInitiator,
														 keyPairsI, idCredsI, credsI, supportedCipherSuites,
														 appProfile, edp, db);
		
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

		Map<Integer, OneKey> keyPairsR = new HashMap<Integer, OneKey>();
	    Map<Integer, CBORObject> credsR = new HashMap<Integer, CBORObject>();
	    Map<Integer, CBORObject> idCredsR = new HashMap<Integer, CBORObject>();
	    keyPairsR.put(Integer.valueOf(Constants.CURVE_Ed25519), identityKeyResp);
	    credsR.put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credR));
	    idCredsR.put(Integer.valueOf(Constants.CURVE_Ed25519), idCredR);
		
		// Create the session for the Responder (with only the minimal set of information required for this test)
		initiator = false;
		KissEDP edp2 = new KissEDP();
		HashMapCtxDB db2 = new HashMapCtxDB();
		EdhocSession sessionResponder = new EdhocSession(initiator, true, method, connectionIdResponder,
														 keyPairsR, idCredsR, credsR, supportedCipherSuites,
														 appProfile, edp2, db2);
		
		edhocSessions.put(CBORObject.FromObject(connectionIdResponder), sessionResponder);
		
		
		// Test from the point of view of the Initiator as Client
		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(
								message1, true, edhocSessions, connectionIdInitiator));
		sessionInitiator.setCurrentStep(Constants.EDHOC_SENT_M1);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(
								message2, false, edhocSessions,connectionIdInitiator));
		sessionInitiator.setCurrentStep(Constants.EDHOC_AFTER_M3);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_3, MessageProcessor.messageType(
								message3, true, edhocSessions, connectionIdInitiator));

		
		// Test from the point of view of the Responder as Server
		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(
								message1, true, edhocSessions, null));
		sessionResponder.setCurrentStep(Constants.EDHOC_AFTER_M2);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(
								message2, false, edhocSessions, connectionIdResponder));
		sessionResponder.setCurrentStep(Constants.EDHOC_SENT_M2);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_3, MessageProcessor.messageType(
								message3, true, edhocSessions, null));
		
		
		// Error message is not from test vectors
		CBORObject cX = CBORObject.FromObject(new byte[] { (byte) 0x59, (byte) 0xe9 });
		CBORObject errMsg = CBORObject.FromObject("Something went wrong");
		CBORObject suitesR = CBORObject.FromObject(1);
		List<CBORObject> errorMessageList;
		
		// Test for an EDHOC error message as an incoming/outgoing response
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_UNSPECIFIED_ERROR));
		errorMessageList.add(errMsg);
		byte[] errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            	errorMessage, false, edhocSessions, connectionIdInitiator));
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE));
		errorMessageList.add(suitesR);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            	errorMessage, false, edhocSessions, connectionIdInitiator));
		
		// Test for an EDHOC error message as an incoming/outgoing request
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cX);
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_UNSPECIFIED_ERROR));
		errorMessageList.add(errMsg);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            	errorMessage, true, edhocSessions, connectionIdInitiator));
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cX);
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE));
		errorMessageList.add(suitesR);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            	errorMessage, true, edhocSessions, connectionIdInitiator));
		
	}

	
	/**
	 * Test writing of message 1, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 * See: upcoming draft-ietf-lake-traces-01
	 */
	@Ignore
	@Test
	public void testWriteMessage1Ciphersuite0Method0() {
		
		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = true;
		int method = 0;
		
		
		// C_I
		CBORObject connectionId = CBORObject.FromObject(-14);
		
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(0);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		CBORObject[] ead1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		// The x509 certificate of the Initiator
		byte[] serializedCert = Utils.hexToBytes("3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] cred = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
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
		
		Map<Integer, OneKey> keyPairs = new HashMap<Integer, OneKey>();
		Map<Integer, CBORObject> creds = new HashMap<Integer, CBORObject>();
		Map<Integer, CBORObject> idCreds = new HashMap<Integer, CBORObject>();
		keyPairs.put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(cred));
		idCreds.put(Integer.valueOf(Constants.CURVE_Ed25519), idCred);
	    
		EdhocSession session = new EdhocSession(initiator, true, method, connectionId, keyPairs,
				                                idCreds, creds, cipherSuites, appProfile, edp, db);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03");
		byte[] publicEkeyBytes = Utils.hexToBytes("31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ead1);

		// Compare with the expected value from the test vectors
		
		// Note: the actual EDHOC message 1 starts with 0x00. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload.
		byte[] expectedMessage1 = Utils
				.hexToBytes("f50000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d");

		Assert.assertArrayEquals(expectedMessage1, message1);
		
	}
	
	
	/**
	 * Test writing of message 2, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 * See: upcoming draft-ietf-lake-traces-01
	 */
	@Ignore
	@Test
	public void testWriteMessage2Ciphersuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = false;
		int method = 0;
		CBORObject[] ead2 = null;
		
		
		/* Responder information*/

		// C_R, in plain binary format
		CBORObject connectionIdResponder = CBORObject.FromObject(23);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);

		
		// The x509 certificate of the Responder
		byte[] serializedCert = Utils.hexToBytes("3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323433365A170D3239313233313233303030305A30223120301E06035504030C174544484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C152CB02");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCert);
		
		
		// TODO Extract the public key from the certificate
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
		
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("ef140ff900b0ab03f0c08d879cbbd4b31ea71e6e7ee7ffcb7e7955777a332799");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("e69c23fbf81bc435942446837fe827bf206c8fa10a39db47449e5a813421e1e8");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);

		
		/* Initiator information*/
		
		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(-14);

		// The ephemeral key of the Initiator
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
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
		
		Map<Integer, OneKey> keyPairs = new HashMap<Integer, OneKey>();
		Map<Integer, CBORObject> creds = new HashMap<Integer, CBORObject>();
		Map<Integer, CBORObject> idCreds = new HashMap<Integer, CBORObject>();
		keyPairs.put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credR));
		idCreds.put(Integer.valueOf(Constants.CURVE_Ed25519), idCredR);
	    
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, appProfile, edp, db);

		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
    	session.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store the EDHOC Message 1
		// Note: this is the actual EDHOC message 1, so it does not include the byte 0xf5 (True) prepended on the wire
		byte[] message1 = Utils.hexToBytes("0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d");
		session.setHashMessage1(message1);
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session, ead2);

		// Compare with the expected value from the test vectors
		
		byte[] expectedMessage2 = Utils
				.hexToBytes("5870dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1ce912f9236086b02242ad56a988829c32a282fbd0c6c2d065479548ced626e8dc3b6d6ef2a588ff33fd2d01c00e189eb68ca9e717007aed62143dfae75622300e166ed3456cd9884b44b6963477aa3e1f17");

		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	
	/**
	 * Test writing of message 3, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * Test the derivation of OSCORE Master Secret and Master Salt
	 * Test EDHOC-KeyUpdate and a second derivation of OSCORE Master Secret and Master Salt 
	 * 
	 * See: upcoming draft-ietf-lake-traces-01
	 */
	@Ignore
	@Test
	public void testWriteMessage3Ciphersuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = true;
		int method = 0;
		CBORObject[] ead3 = null;
		
		
		/* Initiator information*/

		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(-14);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		
		// The x509 certificate of the Initiator
		byte[] serializedCert = Utils.hexToBytes("3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the Initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCert);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);
		
		
		/* Responder information*/

		// C_R, in plain binary format
		CBORObject connectionIdResponder = CBORObject.FromObject(23);
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);

		
		/* Status from after receiving EDHOC Message 2 */
		byte[] th2 = Utils.hexToBytes("3c3e0e79269592a2f4b3cce01642adca36728226d2221597fd8c7fe6b0e2ca75");
		byte[] ciphertext2 = Utils.hexToBytes("e912f9236086b02242ad56a988829c32a282fbd0c6c2d065479548ced626e8dc3b6d6ef2a588ff33fd2d01c00e189eb68ca9e717007aed62143dfae75622300e166ed3456cd9884b44b6963477aa3e1f");
		byte[] prk3e2m = Utils.hexToBytes("c576105d95b4d8c18e8f655f546880a854f2da106ce5a3a02d8b3ede7baabca6");
		
		
		
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
		
		Map<Integer, OneKey> keyPairs = new HashMap<Integer, OneKey>();
		Map<Integer, CBORObject> creds = new HashMap<Integer, CBORObject>();
		Map<Integer, CBORObject> idCreds = new HashMap<Integer, CBORObject>();
		keyPairs.put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credI));
		idCreds.put(Integer.valueOf(Constants.CURVE_Ed25519), idCredI);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdInitiator, keyPairs,
												idCreds, creds, supportedCipherSuites, appProfile, edp, db);

		// Set the ephemeral keys, i.e. X and G_X for the initiator, as well as G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
		
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
		// Note: the actual EDHOC message 3 starts with 0x58. The byte 0x17 (CBOR encoding for 23) is prepended as C_R,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload. 
		byte[] expectedMessage3 = Utils.hexToBytes("1758580a21aaaa204a69ece8ebc2a7b357ab5aaed04613898529912f2c8a6724cb114ec92cdd3dfee8c54c119236b4d1e846416ae78c25aa0f93df2de551aa13e31497cae661a5fd392acd4058254badf24dee9550387d7106434a");

		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
		
		byte[] expectedMasterSecret = Utils.hexToBytes("99313e45905e15f1290f7dd6f4583601");
		byte[] expectedMasterSalt = Utils.hexToBytes("a849e3e5d3fe5d90");
       
       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
       
        
        /* Invoke EDHOC-KeyUpdate to updated the EDHOC key material */
        
        byte[] nonce = Utils.hexToBytes("d6be169602b8bceaa01158fdb820890c");
       
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
        
		expectedMasterSecret = Utils.hexToBytes("3ff347134e74a6c655a1180b2bf23535");
		expectedMasterSalt = Utils.hexToBytes("28b608adbbfcaa2c");
        
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
	}
	
	
	/**
	 * Test writing of message 4, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 * See: upcoming draft-ietf-lake-traces-01
	 */
	@Ignore
	@Test
	public void testWriteMessage4Ciphersuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = false;
		int method = 0;
		CBORObject[] ead4 = null;
		
		
		/* Responder information*/

		// C_R, in plain binary format
		CBORObject connectionIdResponder = CBORObject.FromObject(23);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		
		// The x509 certificate of the Responder
		byte[] serializedCert = Utils.hexToBytes("3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323433365A170D3239313233313233303030305A30223120301E06035504030C174544484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C152CB02");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCert);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("ef140ff900b0ab03f0c08d879cbbd4b31ea71e6e7ee7ffcb7e7955777a332799");
		byte[] publicIdentityKeyBytes = Utils.hexToBytes("a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("e69c23fbf81bc435942446837fe827bf206c8fa10a39db47449e5a813421e1e8");
		byte[] publicEphemeralKeyBytes = Utils.hexToBytes("dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);

		
		/* Initiator information*/
		
		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(-14);

		// The ephemeral key of the Initiator
		byte[] peerEphemeralPublicKeyBytes = Utils.hexToBytes("31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
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
		
		Map<Integer, OneKey> keyPairs = new HashMap<Integer, OneKey>();
		Map<Integer, CBORObject> creds = new HashMap<Integer, CBORObject>();
		Map<Integer, CBORObject> idCreds = new HashMap<Integer, CBORObject>();
		keyPairs.put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credR));
		idCreds.put(Integer.valueOf(Constants.CURVE_Ed25519), idCredR);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, appProfile, edp, db);

		session.setCurrentStep(Constants.EDHOC_AFTER_M3);
		
		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(0);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store TH_4 computed from the previous protocol step
		byte[] prk4x3m = Utils.hexToBytes("c576105d95b4d8c18e8f655f546880a854f2da106ce5a3a02d8b3ede7baabca6");
		session.setPRK4x3m(prk4x3m);
		
		// Store TH_4 computed from the previous protocol step
		byte[] th4 = Utils.hexToBytes("993a2990963178043a151d1e10fa0ac968fd9c24e287c12d958f65d26fab56fa");
		session.setTH4(th4);
		
		// Now write EDHOC message 4
		byte[] message4 = MessageProcessor.writeMessage4(session, ead4);

		// Compare with the expected value from the test vectors

		byte[] expectedMessage4 = Utils.hexToBytes("4831d93d503ba3f95d");
		
		Assert.assertArrayEquals(expectedMessage4, message4);
		
	}
	
	
	/**
	 * Test writing of message 1, for static-static authentication with MACs, with X.509 certificates identified by 'x5t'
	 * 
	 * See: upcoming draft-ietf-lake-traces-01
	 */
	@Ignore
	@Test
	public void testWriteMessage1Ciphersuite2Method3() {
		
		boolean initiator = true;
		int method = 3;
		
		// C_I
		CBORObject connectionId = CBORObject.FromObject(-24);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(6);
		supportedCipherSuites.add(2);

		List<Integer> cipherSuitesPeer = new ArrayList<Integer>();
		cipherSuitesPeer.add(2);
		
		OneKey identityKey = Util.generateKeyPair(KeyKeys.EC2_P256.AsInt32());
		CBORObject[] ead1 = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		
		// ID_CRED_I for the identity key of the Initiator
		int idCredKid = -12;
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		
		// CRED_I for the identity key of the Initiator
		byte[] cred = Utils.hexToBytes("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a50102022b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
		
				
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
		
		Map<Integer, OneKey> keyPairs = new HashMap<Integer, OneKey>();
		Map<Integer, CBORObject> creds = new HashMap<Integer, CBORObject>();
		Map<Integer, CBORObject> idCreds = new HashMap<Integer, CBORObject>();
		keyPairs.put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(cred));
		idCreds.put(Integer.valueOf(Constants.CURVE_P256), idCred);
		
		EdhocSession session = new EdhocSession(initiator, true, method, connectionId, keyPairs,
				                                idCreds, creds, supportedCipherSuites, appProfile, edp, db);

		// Force the early knowledge of cipher suites supported by the other peer
		session.setPeerSupportedCipherSuites(cipherSuitesPeer);
		
		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
		byte[] publicEkeyBytesX = Utils.hexToBytes("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicEkeyBytesY = Utils.hexToBytes("51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
		OneKey ek = SharedSecretCalculation.buildEcdsa256OneKey(privateEkeyBytes, publicEkeyBytesX, publicEkeyBytesY);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ead1);

		// Compare with the expected value from the test vectors

		// Note: the actual EDHOC message 1 starts with 0x03. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload. 
		byte[] expectedMessage1 = Utils
				.hexToBytes("f50382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
		
		Assert.assertArrayEquals(expectedMessage1, message1);
	}
	
	
	/**
	 * Test writing of message 2, for static-static authentication with MACs, with X.509 certificates identified by 'x5t'
	 * 
	 * See: upcoming draft-ietf-lake-traces-01
	 */
	@Ignore
	@Test
	public void testWriteMessage2Ciphersuite2Method3() {

		boolean initiator = false;
		int method = 3;
		CBORObject[] ead2 = null;
		
		/* Responder information*/

		// C_R
		CBORObject connectionIdResponder = CBORObject.FromObject(-8);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
		byte[] publicIdentityKeyBytesX = Utils.hexToBytes("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
		byte[] publicIdentityKeyBytesY = Utils.hexToBytes("4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// ID_CRED_R for the identity key of the Responder
		int idCredKid = -19;
		CBORObject idCredR = Util.buildIdCredKid(idCredKid);
		
		// CRED_R for the identity key of the Responder
		byte[] credR = Utils.hexToBytes("a2026b6578616d706c652e65647508a101a5010202322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		
				
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418");
		byte[] publicEphemeralKeyBytesX = Utils.hexToBytes("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
		byte[] publicEphemeralKeyBytesY = Utils.hexToBytes("5e4f0dd8a3da0baa16b9d3ad56a0c1860a940af85914915e25019b402417e99d");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
																		  publicEphemeralKeyBytesX,
																		  publicEphemeralKeyBytesY);

		/* Initiator information*/
		
		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(-24);

		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytesX = Utils.hexToBytes("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicPeerEphemeralKeyBytesY = Utils.hexToBytes("51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null,
																					publicPeerEphemeralKeyBytesX,
																					publicPeerEphemeralKeyBytesY);
				
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
		
		Map<Integer, OneKey> keyPairs = new HashMap<Integer, OneKey>();
		Map<Integer, CBORObject> creds = new HashMap<Integer, CBORObject>();
		Map<Integer, CBORObject> idCreds = new HashMap<Integer, CBORObject>();
		keyPairs.put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credR));
		idCreds.put(Integer.valueOf(Constants.CURVE_P256), idCredR);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, appProfile, edp, db);

		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(2);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		// Store the EDHOC Message 1
		// Note: this is the actual EDHOC message 1, so it does not include the byte 0xf5 (True) prepended on the wire
		byte[] message1 = Utils.hexToBytes("0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
		session.setHashMessage1(message1);
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session, ead2);

		// Compare with the expected value from the test vectors
		
		byte[] expectedMessage2 = Utils
				.hexToBytes("582a419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d549cef36e229fff1e584927");
		
		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	
	/**
	 * Test writing of message 3, for static-static authentication with MACs, with X.509 certificates identified by 'x5t'
	 * Test the derivation of OSCORE Master Secret and Master Salt
	 * Test EDHOC-KeyUpdate and a second derivation of OSCORE Master Secret and Master Salt 
	 * 
	 * See: upcoming draft-ietf-lake-traces-01
	 */
	@Ignore
	@Test
	public void testWriteMessage3Ciphersuite2Method3() {

		boolean initiator = true;
		int method = 3;
		CBORObject[] ead3 = null;
		
		/* Initiator information*/

		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(-24);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(6);
		supportedCipherSuites.add(2);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
		byte[] publicIdentityKeyBytesX = Utils.hexToBytes("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
		byte[] publicIdentityKeyBytesY = Utils.hexToBytes("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// ID_CRED_I for the identity key of the Initiator
		int idCredKid = -12;
		CBORObject idCredI = Util.buildIdCredKid(idCredKid);
		
		// CRED_I for the identity key of the Initiator
		byte[] credI = Utils.hexToBytes("a2027734322d35302d33312d46462d45462d33372d33322d333908a101a50102022b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
		byte[] publicEphemeralKeyBytesX = Utils.hexToBytes("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicEphemeralKeyBytesY = Utils.hexToBytes("51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
																		  publicEphemeralKeyBytesX,
																		  publicEphemeralKeyBytesY);
		
		
		/* Responder information*/

		// C_R, in plain binary format
		CBORObject connectionIdResponder = CBORObject.FromObject(-8);
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytesX = Utils.hexToBytes("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
		byte[] peerEphemeralPublicKeyBytesY = Utils.hexToBytes("5e4f0dd8a3da0baa16b9d3ad56a0c1860a940af85914915e25019b402417e99d");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null,
																					peerEphemeralPublicKeyBytesX,
																					peerEphemeralPublicKeyBytesY);

		
		/* Status from after receiving EDHOC Message 2 */
		
		byte[] th2 = Utils.hexToBytes("9b99cfd7afdcbcc9950a6373507f2a81013319625697e4f9bf7a448fc8e633ca");
		
		byte[] ciphertext2 = Utils.hexToBytes("49cef36e229fff1e5849");
		
		byte[] prk3e2m = Utils.hexToBytes("af4b5918682adf4c96fd7305b69f8fb78efc9a230dd21f4c61be7d3c109446b3");
		
		
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
		
		Map<Integer, OneKey> keyPairs = new HashMap<Integer, OneKey>();
		Map<Integer, CBORObject> creds = new HashMap<Integer, CBORObject>();
		Map<Integer, CBORObject> idCreds = new HashMap<Integer, CBORObject>();
		keyPairs.put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credI));
		idCreds.put(Integer.valueOf(Constants.CURVE_P256), idCredI);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdInitiator, keyPairs,
												idCreds, creds, supportedCipherSuites, appProfile, edp, db);

		// Set the ephemeral keys, i.e. X and G_X for the initiator, as well as G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(2);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
		
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
		// Note: the actual EDHOC message 3 starts with 0x52. The byte 0x27 (CBOR encoding for -8) is prepended as C_R,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload.
		
		byte[] expectedMessage3 = Utils.hexToBytes("2752885c63fd0b17f2c3f8f10bc8bf3f470ec8a1");

		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
        
		byte[] expectedMasterSecret = Utils.hexToBytes("af845589beb99d0a2bf4427ffa8dbbbc");
		byte[] expectedMasterSalt = Utils.hexToBytes("7bc09af254a65929");

       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
		
        
        /* Invoke EDHOC-KeyUpdate to updated the EDHOC key material */
        
        byte[] nonce = Utils.hexToBytes("05bd1ffd85c546da863c970a34b743a3");
       
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
        
		expectedMasterSecret = Utils.hexToBytes("782be7486316b80d89b6b732a34e0e43");
		expectedMasterSalt = Utils.hexToBytes("1dfc7174b02c1e14");

       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
	}
	
	
	/**
	 * Test writing of message 4, for static-static authentication with MACs, with X.509 certificates identified by 'x5t'
	 * 
	 * See: upcoming draft-ietf-lake-traces-01
	 */
	@Ignore
	@Test
	public void testWriteMessage4Ciphersuite2Method3() {

		boolean initiator = false;
		int method = 3;
		CBORObject[] ead4 = null;
		
		/* Responder information*/

		// C_R
		CBORObject connectionIdResponder = CBORObject.FromObject(-8);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = Utils.hexToBytes("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
		byte[] publicIdentityKeyBytesX = Utils.hexToBytes("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
		byte[] publicIdentityKeyBytesY = Utils.hexToBytes("4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// ID_CRED_R for the identity key of the Responder
		int idCredKid = -19;
		CBORObject idCredR = Util.buildIdCredKid(idCredKid);
		
		// CRED_R for the identity key of the Responder
		byte[] credR = Utils.hexToBytes("a2026b6578616d706c652e65647508a101a5010202322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = Utils.hexToBytes("e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418");
		byte[] publicEphemeralKeyBytesX = Utils.hexToBytes("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
		byte[] publicEphemeralKeyBytesY = Utils.hexToBytes("5e4f0dd8a3da0baa16b9d3ad56a0c1860a940af85914915e25019b402417e99d");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
																		  publicEphemeralKeyBytesX,
																		  publicEphemeralKeyBytesY);

		
		/* Initiator information*/
		
		// C_I, in plain binary format
		CBORObject connectionIdInitiator = CBORObject.FromObject(-24);

		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytesX = Utils.hexToBytes("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicPeerEphemeralKeyBytesY = Utils.hexToBytes("51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null,
																					publicPeerEphemeralKeyBytesX,
																					publicPeerEphemeralKeyBytesY);
		
		
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
		
		Map<Integer, OneKey> keyPairs = new HashMap<Integer, OneKey>();
		Map<Integer, CBORObject> creds = new HashMap<Integer, CBORObject>();
		Map<Integer, CBORObject> idCreds = new HashMap<Integer, CBORObject>();
		keyPairs.put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credR));
		idCreds.put(Integer.valueOf(Constants.CURVE_P256), idCredR);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, appProfile, edp, db);

		session.setCurrentStep(Constants.EDHOC_AFTER_M3);
		
		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCiphersuite(2);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdInitiator);
		
		
		// Store PRK_4x3m computed from the previous protocol step
		byte[] prk4x3m = Utils.hexToBytes("4a40f2aca7e1d9dbaf2b276bce75f0ce6d513f75a95af8905f2a14f2493b2477");
		session.setPRK4x3m(prk4x3m);
		
		// Store TH_4 computed from the previous protocol step
		byte[] th4 = Utils.hexToBytes("ba682e7165e9d484bd2ebb031c09da1ea5b82eb332439c4c7ec73c2c239e3450");
		session.setTH4(th4);
		
		// Now write EDHOC message 4
		byte[] message4 = MessageProcessor.writeMessage4(session, ead4);

		// Compare with the expected value from the test vectors

		byte[] expectedMessage4 = Utils.hexToBytes("48b78d9639ae797b08");
		
		Assert.assertArrayEquals(expectedMessage4, message4);
		
	}
		
}
