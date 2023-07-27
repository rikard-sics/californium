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
import java.util.Set;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class MessageProcessorTest {

	/**
	 * Tests identification of EDHOC messages. Based on messages from the EDHOC test vectors.
	 * 
	 */
	@Test
	public void testMessageType() {
		
		// Note: the actual EDHOC message 1 starts with 0x00. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload.
		byte[] message1 = StringUtil.hex2ByteArray(
				"f500005820e31ec15ee8039427dfc4727ef17e2e0e69c54437f3c5828019ef0a6388c125520e");
		
		byte[] message2 = StringUtil.hex2ByteArray(
				"5870e1739096c5c9582c1298918166d69548c78f7497b258c0856aa2019893a39425690bdd9b15885138490d3b8ac735e2ad7912d58d0e3995f2b54e8e63e90bc3c42620308c10508d0f40c8f48f87a404cfc78fb522db588a12f3d8e76436fc26a81daeb735c34feb1f7254bda2b7d014f332");
		
		// Note: the actual EDHOC message 3 starts with 0x58. The byte 0x32 (CBOR encoding for -19) is prepended as C_R,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload. 
		byte[] message3 = StringUtil.hex2ByteArray(
				"3258584c53ed22c45fb00cad889b4c06f2a26cf49154cb8bdf4eee44e2b50221ab1f029d3d3e0523ddf9d7610c376c728a1e901692f1da0782a3472ff6eb1bb6810c6f686879c9a5594f8f170ca5a2b5bf05a74f42cdd9c854e01e");

		HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		
		int method = 0;
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		/* Initiator information*/

		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x0e};
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytesInit = StringUtil.hex2ByteArray(
				"366a5859a4cd65cfaeaf0566c9fc7e1a93306fdec17763e05813a70f21ff59db");
		byte[] publicIdentityKeyBytesInit = StringUtil.hex2ByteArray(
				"ec2c2eb6cdd95782a8cd0b2e9c44270774dcbd31bfbe2313ce80132e8a261c04");
		OneKey identityKeyInit = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytesInit, publicIdentityKeyBytesInit);
		
		// The x509 certificate of the Initiator
		byte[] serializedCertInit = StringUtil.hex2ByteArray(
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCertInit).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCertInit);

		HashMap<Integer, HashMap<Integer, OneKey>> keyPairsI = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> credsI = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCredsI = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairsI.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		credsI.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCredsI.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
	    keyPairsI.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
	    		  put(Integer.valueOf(Constants.CURVE_Ed25519), identityKeyInit);
	    credsI.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
	    	      put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credI));
	    idCredsI.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
	    		  put(Integer.valueOf(Constants.CURVE_Ed25519), idCredI);

		// Create the session for the Initiator (with only the minimal set of information required for this test)
		boolean initiator = true;
		int trustModel = Constants.TRUST_MODEL_STRICT;
		HashMapCtxDB db = new HashMapCtxDB();
		EdhocSession sessionInitiator = new EdhocSession(initiator, true, method, connectionIdentifierInitiator,
														 keyPairsI, idCredsI, credsI, supportedCipherSuites,
														 peerSupportedCipherSuites, supportedEADs, appProfile, trustModel, db);
		
		edhocSessions.put(CBORObject.FromObject(connectionIdentifierInitiator), sessionInitiator);

		
		/* Responder information*/
		
		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x32};
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytesResp = StringUtil.hex2ByteArray(
				"bc4d4f9882612233b402db75e6c4cf3032a70a0d2e3ee6d01b11ddde5f419cfc");
		byte[] publicIdentityKeyBytesResp = StringUtil.hex2ByteArray(
				"27eef2b08a6f496faedaa6c7f9ec6ae3b9d52424580d52e49da6935edf53cdc5");
		OneKey identityKeyResp = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytesResp, publicIdentityKeyBytesResp);
		
		// The x509 certificate of the Responder
		byte[] serializedCertResp = StringUtil.hex2ByteArray(
				"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCertResp).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCertResp);

		HashMap<Integer, HashMap<Integer, OneKey>> keyPairsR = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> credsR = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCredsR = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairsR.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		credsR.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCredsR.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
	    keyPairsR.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
	    		  put(Integer.valueOf(Constants.CURVE_Ed25519), identityKeyResp);
	    credsR.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
	    	      put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credR));
	    idCredsR.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
	    		  put(Integer.valueOf(Constants.CURVE_Ed25519), idCredR);
		
		// Create the session for the Responder (with only the minimal set of information required for this test)
		initiator = false;
		HashMapCtxDB db2 = new HashMapCtxDB();
		EdhocSession sessionResponder = new EdhocSession(initiator, true, method, connectionIdentifierResponder,
														 keyPairsR, idCredsR, credsR, supportedCipherSuites,
														 peerSupportedCipherSuites, supportedEADs, appProfile, trustModel, db2);
		
		edhocSessions.put(CBORObject.FromObject(connectionIdentifierResponder), sessionResponder);
		
		
		// Test from the point of view of the Initiator as Client
		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(
								message1, true, edhocSessions, connectionIdentifierInitiator));
		sessionInitiator.setCurrentStep(Constants.EDHOC_SENT_M1);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(
								message2, false, edhocSessions, connectionIdentifierInitiator));
		sessionInitiator.setCurrentStep(Constants.EDHOC_AFTER_M3);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_3, MessageProcessor.messageType(
								message3, true, edhocSessions, connectionIdentifierInitiator));

		
		// Test from the point of view of the Responder as Server
		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(
								message1, true, edhocSessions, null));
		sessionResponder.setCurrentStep(Constants.EDHOC_AFTER_M2);
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(
								message2, false, edhocSessions, connectionIdentifierResponder));
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
				            	errorMessage, false, edhocSessions, connectionIdentifierInitiator));
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE));
		errorMessageList.add(suitesR);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            	errorMessage, false, edhocSessions, connectionIdentifierInitiator));
		
		// Test for an EDHOC error message as an incoming/outgoing request
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cX);
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_UNSPECIFIED_ERROR));
		errorMessageList.add(errMsg);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            	errorMessage, true, edhocSessions, connectionIdentifierInitiator));
		errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cX);
		errorMessageList.add(CBORObject.FromObject(Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE));
		errorMessageList.add(suitesR);
		errorMessage = Util.buildCBORSequence(errorMessageList);
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(
				            	errorMessage, true, edhocSessions, connectionIdentifierInitiator));
		
	}

	/**
	 * Tests writing EDHOC error messages
	 * 
	 */
	@Test
	public void testWriteErrorMessage() {
		
		// EDHOC error message as a CoAP response to EDHOC message_1; C_I is encoded as 0x00 on the wire
		
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x00};
				
		// ERR_CODE: 1 (Unspecified error)
		// ERR_INFO: "Error while processing EDHOC message_1"
		byte[] expectedErrorMessage = StringUtil.hex2ByteArray("0178264572726f72207768696c652070726f63657373696e67204544484f43206d6573736167655f31");
		byte[] errorMessage = MessageProcessor.writeErrorMessage(1, 1, false, connectionIdentifierInitiator,
																 "Error while processing EDHOC message_1", null);
		Assert.assertArrayEquals(expectedErrorMessage, errorMessage);
		
		// ERR_CODE: 2 (Wrong selected cipher suite)
		// ERR_INFO: 6 (The responder supports cipher suite 6)
		CBORObject SUITE_R = CBORObject.FromObject(6);
		expectedErrorMessage = StringUtil.hex2ByteArray("0206");
		errorMessage = MessageProcessor.writeErrorMessage(2, 1, false, connectionIdentifierInitiator, null, SUITE_R);
		Assert.assertArrayEquals(expectedErrorMessage, errorMessage);
		
		// ERR_CODE: 2 (Wrong selected cipher suite)
		// ERR_INFO: [5, 6] (The responder supports cipher suites 5 and 6)
		SUITE_R = CBORObject.NewArray();
		SUITE_R.Add(5);
		SUITE_R.Add(6);
		expectedErrorMessage = StringUtil.hex2ByteArray("02820506");
		errorMessage = MessageProcessor.writeErrorMessage(2, 1, false, connectionIdentifierInitiator, null, SUITE_R);
		Assert.assertArrayEquals(expectedErrorMessage, errorMessage);
		
		// Invalid EDHOC error message
		// ERR_CODE: 2 (Wrong selected cipher suite)
		// ERR_INFO: 6 (The responder supports cipher suite 6)
		SUITE_R = CBORObject.NewArray();
		SUITE_R.Add(true);
		SUITE_R.Add(false);
		errorMessage = MessageProcessor.writeErrorMessage(2, 1, false, connectionIdentifierInitiator,
														  "This should not happen", SUITE_R);
		Assert.assertNull(errorMessage);
		
	}
	
	
	/**
	 * Tests reading EDHOC error messages
	 * 
	 */
	@Test
	public void testReadErrorMessage() {
		
		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = true;
		int method = 0;
		
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x00};
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8");
		byte[] publicIdentityKeyBytes = StringUtil.hex2ByteArray(
				"ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The x509 certificate of the Initiator
		byte[] serializedCert = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the Initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCert);
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credI));
		idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), idCredI);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		// Set up an EDHOC session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);
		session.setCurrentStep(Constants.EDHOC_SENT_M1);
		
		HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		edhocSessions.put(CBORObject.FromObject(connectionIdentifierInitiator), session);
		
		
		
		// ERR_CODE: 1 (Unspecified error)
		// ERR_INFO: "Error while processing EDHOC message_1"
		byte[] errorMessage = StringUtil.hex2ByteArray("0178264572726f72207768696c652070726f63657373696e67204544484f43206d6573736167655f31");
		
		CBORObject[] expectedObjects = new CBORObject[2];
		expectedObjects[0] = CBORObject.FromObject(1);
		expectedObjects[1] = CBORObject.FromObject("Error while processing EDHOC message_1");
		
		CBORObject[] returnedObjects = MessageProcessor.readErrorMessage(errorMessage, connectionIdentifierInitiator, edhocSessions);
		Assert.assertArrayEquals(expectedObjects, returnedObjects);
		
		
		// ERR_CODE: 2 (Wrong selected cipher suite)
		// ERR_INFO: 6 (The responder supports cipher suite 6)
		errorMessage = StringUtil.hex2ByteArray("0206");
		
		expectedObjects = new CBORObject[2];
		expectedObjects[0] = CBORObject.FromObject(2);
		expectedObjects[1] = CBORObject.FromObject(6);
		
		returnedObjects = MessageProcessor.readErrorMessage(errorMessage, connectionIdentifierInitiator, edhocSessions);
		Assert.assertArrayEquals(expectedObjects, returnedObjects);
		
		
		// ERR_CODE: 2 (Wrong selected cipher suite)
		// ERR_INFO: [5, 6] (The responder supports cipher suites 5 and 6)
		errorMessage = StringUtil.hex2ByteArray("02820506");
		
		expectedObjects = new CBORObject[2];
		expectedObjects[0] = CBORObject.FromObject(2);
		CBORObject SUITE_R = CBORObject.NewArray();
		SUITE_R.Add(5);
		SUITE_R.Add(6);
		expectedObjects[1] = SUITE_R;
		returnedObjects = MessageProcessor.readErrorMessage(errorMessage, connectionIdentifierInitiator, edhocSessions);
		Assert.assertArrayEquals(expectedObjects, returnedObjects);
		
		
		// Invalid EDHOC error message
		// ERR_CODE: 2 (Wrong selected cipher suite)
		// ERR_INFO: [true, false] (invalid types for cipher suites)
		errorMessage = StringUtil.hex2ByteArray("0282f5f4");
		
		expectedObjects = new CBORObject[2];
		expectedObjects[0] = CBORObject.FromObject(2);
		SUITE_R = CBORObject.NewArray();
		SUITE_R.Add(true);
		SUITE_R.Add(false);
		expectedObjects[1] = SUITE_R;
		returnedObjects = MessageProcessor.readErrorMessage(errorMessage, connectionIdentifierInitiator, edhocSessions);
		Assert.assertNull(returnedObjects);
		
	}
	
	/**
	 * Test writing of message 1, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 * See: draft-ietf-lake-traces
	 */
	@Test
	public void testWriteMessage1CipherSuite0Method0() {
		
		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = true;
		int method = 0;
		
		
		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x2d};
		
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(0);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8");
		byte[] publicIdentityKeyBytes = StringUtil.hex2ByteArray(
				"ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		// The x509 certificate of the Initiator
		byte[] serializedCert = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B");
		
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
			     put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(cred));
		idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), idCred);
	    
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator,
												keyPairs, idCreds, creds, cipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		sideProcessor.setEdhocSession(session);
		
		
		// Force a specific ephemeral key
		byte[] privateEkeyBytes = StringUtil.hex2ByteArray(
				"892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03");
		byte[] publicEkeyBytes = StringUtil.hex2ByteArray(
				"31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session);

		// Compare with the expected value from the test vectors
		
		// Note: the actual EDHOC message 1 starts with 0x00. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload.
		byte[] expectedMessage1 = StringUtil.hex2ByteArray(
				"f5" + "0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d");

		Assert.assertArrayEquals(expectedMessage1, message1);
		
	}
	
	/**
	 * Tests reading EDHOC message_1, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 */
	@Test
	public void testReadMessage1CipherSuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		
		int trustModel = Constants.TRUST_MODEL_STRICT;
		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		
		// Note: the actual EDHOC message 1 starts with 0x00. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to enable the reading of the message as the first one in a new EDHOC session
		byte[] message1 = StringUtil.hex2ByteArray(
				"f5" + "0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d");
		
		List<CBORObject> output = MessageProcessor.readMessage1(message1, true, supportedCipherSuites,
																supportedEADs, appProfile, sideProcessor);
		
		CBORObject expectedOutput = CBORObject.FromObject(new byte[0]);
		
		Assert.assertEquals(1, output.size());
		Assert.assertEquals(expectedOutput, output.get(0));
		
	}
	
	/**
	 * Test writing of message 2, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 * See: draft-ietf-lake-traces
	 */
	@Test
	public void testWriteMessage2CipherSuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = false;
		int method = 0;
		
		
		/* Responder information*/

		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x18};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);

		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The x509 certificate of the Responder
		byte[] serializedCert = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323433365A170D3239313233313233303030305A30223120301E06035504030C174544484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C152CB02");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCert);
		
		
		// TODO Extract the public key from the certificate
		/*
		ByteArrayInputStream inputStream = new ByteArrayInputStream(credR);
		try {
			System.out.println((StringUtil.byteArray2HexString(inputStream.readAllBytes())));
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
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"ef140ff900b0ab03f0c08d879cbbd4b31ea71e6e7ee7ffcb7e7955777a332799");
		byte[] publicIdentityKeyBytes = StringUtil.hex2ByteArray(
				"a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"e69c23fbf81bc435942446837fe827bf206c8fa10a39db47449e5a813421e1e8");
		byte[] publicEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);

		
		/* Initiator information*/
		
		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x2d};

		// The ephemeral key of the Initiator
		byte[] peerEphemeralPublicKeyBytes = StringUtil.hex2ByteArray(
				"31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
			     put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credR));
		idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), idCredR);
	    
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(0);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
    	session.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdentifierInitiator);
		
		// Store the EDHOC Message 1
		// Note: this is the actual EDHOC message 1, so it does not include the byte 0xf5 (True) prepended on the wire
		byte[] message1 = StringUtil.hex2ByteArray(
				"0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d");
		session.setHashMessage1(message1);
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session);

		// Compare with the expected value from the test vectors
		
		byte[] expectedMessage2 = StringUtil.hex2ByteArray(
				"5872dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1cbc26dd270fe9c02c44ce3934794b1cc62ba2ad5669fc0755c2a16b7e42ed14225fef1e451e453c21421d4d373f256b81b1937f5b199d67330521d025a0be4d26a3c20b828e9e0ef565a9343d81d9bbbda988");

		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	/**
	 * Test reading of message 2, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 */
	@Test
	public void testReadMessage2CipherSuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = true;
		int method = 0;
				
		
		/* Initiator information*/

		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x2d};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The x509 certificate of the Initiator
		byte[] serializedCert = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the Initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCert);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8");
		byte[] publicIdentityKeyBytes = StringUtil.hex2ByteArray(
				"ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03");
		byte[] publicEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);
		
		
		/* Responder information*/
		
		// The x509 certificate of the Responder
		byte[] serializedCertResponder = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323433365A170D3239313233313233303030305A30223120301E06035504030C174544484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C152CB02");
		
		byte[] responderPublicKeyBinary = StringUtil.hex2ByteArray("a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359");
		OneKey responderPublicKey =  SharedSecretCalculation.buildEd25519OneKey(null, responderPublicKeyBinary);
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] responderCred = CBORObject.FromObject(serializedCertResponder).EncodeToBytes();
		
		
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credI));
		idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), idCredI);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		edhocSessions.put(CBORObject.FromObject(connectionIdentifierInitiator), session);
		
		Set<CBORObject> usedConnectionIds = new HashSet<>();
		usedConnectionIds.add(CBORObject.FromObject(connectionIdentifierInitiator));
		
		HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
		HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
		
		CBORObject responderIdCred = Util.buildIdCredX5t(serializedCertResponder); // ID_CRED as 'x5t'
		peerPublicKeys.put(responderIdCred, responderPublicKey);
		peerCredentials.put(responderIdCred, CBORObject.FromObject(responderCred));
		
		Set<CBORObject> ownIdCreds = new HashSet<>();
		CBORObject idCred = Util.buildIdCredX5t(serializedCert);
		ownIdCreds.add(idCred);
		
		SideProcessor sideProcessor = new SideProcessor(trustModel, peerCredentials, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys of the initiator, i.e., X and G_X
		session.setEphemeralKey(ephemeralKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(0);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
				
		// Store the hash of EDHOC Message 1
		// Note: this is the actual EDHOC message 1, so it does not include the byte 0xf5 (True) prepended on the wire
		byte[] message1 = StringUtil.hex2ByteArray(
				"0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d");
		session.setHashMessage1(message1);
		
		session.setCurrentStep(Constants.EDHOC_SENT_M1);
		
		
		
		byte[] message2 = StringUtil.hex2ByteArray(
				"5872dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1cbc26dd270fe9c02c44ce3934794b1cc62ba2ad5669fc0755c2a16b7e42ed14225fef1e451e453c21421d4d373f256b81b1937f5b199d67330521d025a0be4d26a3c20b828e9e0ef565a9343d81d9bbbda988");

		List<CBORObject> output = MessageProcessor.readMessage2(message2, false, connectionIdentifierInitiator,
                												edhocSessions, peerPublicKeys, peerCredentials,
                												usedConnectionIds, ownIdCreds);

		CBORObject expectedOutput = CBORObject.FromObject(new byte[0]);
		
		Assert.assertEquals(1, output.size());
		Assert.assertEquals(expectedOutput, output.get(0));
		
	}
	
	/**
	 * Test writing of message 3, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * Test the derivation of OSCORE Master Secret and Master Salt
	 * Test EDHOC-KeyUpdate and a second derivation of OSCORE Master Secret and Master Salt 
	 * 
	 * See: draft-ietf-lake-traces
	 */
	@Test
	public void testWriteMessage3CipherSuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = true;
		int method = 0;

		
		/* Initiator information*/

		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x2d};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The x509 certificate of the Initiator
		byte[] serializedCert = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the Initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCert);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8");
		byte[] publicIdentityKeyBytes = StringUtil.hex2ByteArray(
				"ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03");
		byte[] publicEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);
		
		
		/* Responder information*/

		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x18};
		
		// The x509 certificate of the Responder
		byte[] serializedCertResponder = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323433365A170D3239313233313233303030305A30223120301E06035504030C174544484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C152CB02");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCertResponder).EncodeToBytes();
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = StringUtil.hex2ByteArray(
				"dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildCurve25519OneKey(null, peerEphemeralPublicKeyBytes);

		
		/* Status from after receiving EDHOC Message 2 */
		byte[] th2 = StringUtil.hex2ByteArray(
				"c6405c154c567466ab1df20369500e540e9f14bd3a796a0652cae66c9061688d");
		byte[] prk3e2m = StringUtil.hex2ByteArray(
				"d584ac2e5dad5a77d14b53ebe72ef1d5daa8860d399373bf2c240afa7ba804da");
		
		
		
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credI));
		idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), idCredI);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys, i.e., X and G_X for the initiator, as well as G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(0);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdentifierResponder);
		
		// Set TH_2 from the previous protocol step
		session.setTH2(th2);

		// Set PLAINTEXT_2 from the previous protocol step
		byte[] plaintext2 = StringUtil.hex2ByteArray(
				"4118a11822822e4879f2a41b510c1f9b584041e691275b840424255acb87e633d75dda71502da2e3da5fceeec4e3f76074486f87e66f2acaa1bbd48ce0e66a5d64389154482f9a5e572270633159f2b17e0e");
		session.setPlaintext2(plaintext2);
		
		// Set PRK_3e2m from the previous protocol step
		session.setPRK3e2m(prk3e2m);
		
		// Set CRED_R from the previous protocol step
		session.setPeerCred(credR);
		
		
		// Now write EDHOC message 3
		byte[] message3 = MessageProcessor.writeMessage3(session);

		// Compare with the expected value from the test vectors
		// Note: the actual EDHOC message 3 starts with 0x58. The bytes 0x4118 (CBOR encoding for h'18') is prepended as C_R,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload. 
		byte[] expectedMessage3 = StringUtil.hex2ByteArray(
				"4118" + "5858aa966a1aa4fa449a172a160b96e644f6a33329f27c6af5bbefc61158d0addd99069b9a197ff7c90e62f3b55664c583747b9a402ccd68907fe458b16ad52d63a00e5a85df95ee7b1b498ac98342008c0471c1ae8d75825044");

		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
		
		byte[] expectedMasterSecret = StringUtil.hex2ByteArray("fc9cfb0563ca3e28f880483b9c06bd03");
		byte[] expectedMasterSalt = StringUtil.hex2ByteArray("0ec09d453b089834");
       
       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
       
        
        /* Invoke EDHOC-KeyUpdate to updated the EDHOC key material */
        
        byte[] nonce = StringUtil.hex2ByteArray("d6be169602b8bceaa01158fdb820890c");
       
        try {
			session.edhocKeyUpdate(CBORObject.FromObject(nonce));
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
        
		expectedMasterSecret = StringUtil.hex2ByteArray("50486d75823a592d1efd286a707fe87d");
		expectedMasterSalt = StringUtil.hex2ByteArray("6195cbb1ce031cae");
        
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
	}
	
	
	
	/**
	 * Test reading of message 3, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 */
	@Test
	public void testReadMessage3CipherSuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = false;
		int method = 0;
		
		
		/* Responder information*/

		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x18};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);

		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The x509 certificate of the Responder
		byte[] serializedCert = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323433365A170D3239313233313233303030305A30223120301E06035504030C174544484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C152CB02");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCert);
				
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"ef140ff900b0ab03f0c08d879cbbd4b31ea71e6e7ee7ffcb7e7955777a332799");
		byte[] publicIdentityKeyBytes = StringUtil.hex2ByteArray(
				"a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"e69c23fbf81bc435942446837fe827bf206c8fa10a39db47449e5a813421e1e8");
		byte[] publicEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);
		
		
		/* Initiator information*/
		
		// The x509 certificate of the Initiator
		byte[] serializedCertInitiator = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B");
		
		byte[] initiatorPublicKeyBinary = StringUtil.hex2ByteArray("ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e");
		OneKey initiatorPublicKey = SharedSecretCalculation.buildEd25519OneKey(null, initiatorPublicKeyBinary);
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] initiatorCred = CBORObject.FromObject(serializedCertInitiator).EncodeToBytes();
		
		// The ephemeral key of the Initiator
		byte[] peerEphemeralPublicKeyBytes = StringUtil.hex2ByteArray(
				"31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credR));
		idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), idCredR);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		edhocSessions.put(CBORObject.FromObject(connectionIdentifierResponder), session);
		
		Set<CBORObject> usedConnectionIds = new HashSet<>();
		usedConnectionIds.add(CBORObject.FromObject(connectionIdentifierResponder));
		
		HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
		HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
		
		
		
		
		CBORObject initiatorIdCred = Util.buildIdCredX5t(serializedCertInitiator); // ID_CRED as 'x5t'
		peerPublicKeys.put(initiatorIdCred, initiatorPublicKey);
		peerCredentials.put(initiatorIdCred, CBORObject.FromObject(initiatorCred));
		
		Set<CBORObject> ownIdCreds = new HashSet<>();
		CBORObject idCred = Util.buildIdCredX5t(serializedCert);
		ownIdCreds.add(idCred);
		
		SideProcessor sideProcessor = new SideProcessor(trustModel, peerCredentials, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys of the responder, i.e., Y and G_Y
		session.setEphemeralKey(ephemeralKey);
		
		// Set the ephemeral keys of the initiator, i.e., X and G_X
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(0);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Responder to use in this session
		session.setAuthenticationCredential();
		
		// Set TH_2 from the previous protocol step
		byte[] th2 = StringUtil.hex2ByteArray(
				"c6405c154c567466ab1df20369500e540e9f14bd3a796a0652cae66c9061688d");
		session.setTH2(th2);

		// Set PRK_3e2m from the previous protocol step
		byte[] prk3e2m = StringUtil.hex2ByteArray(
		        "d584ac2e5dad5a77d14b53ebe72ef1d5daa8860d399373bf2c240afa7ba804da");
		session.setPRK3e2m(prk3e2m);
		
		// Set PLAINTEXT_2 from the previous protocol step
		byte[] plaintext2 = StringUtil.hex2ByteArray(
				"4118a11822822e4879f2a41b510c1f9b584041e691275b840424255acb87e633d75dda71502da2e3da5fceeec4e3f76074486f87e66f2acaa1bbd48ce0e66a5d64389154482f9a5e572270633159f2b17e0e");
		session.setPlaintext2(plaintext2);
		
		session.setCurrentStep(Constants.EDHOC_SENT_M2);
		
		
		// Compare with the expected value from the test vectors
		// Note: the actual EDHOC message 3 starts with 0x58. The bytes 0x4118 (CBOR encoding for h'18') is prepended as C_R,
		//       in order to enable the reading of the message as the first one in a new EDHOC session
		byte[] message3 = StringUtil.hex2ByteArray(
				"4118" + "5858aa966a1aa4fa449a172a160b96e644f6a33329f27c6af5bbefc61158d0addd99069b9a197ff7c90e62f3b55664c583747b9a402ccd68907fe458b16ad52d63a00e5a85df95ee7b1b498ac98342008c0471c1ae8d75825044");

		List<CBORObject> output = MessageProcessor.readMessage3(message3, true, connectionIdentifierResponder,
																edhocSessions, peerPublicKeys, peerCredentials, usedConnectionIds);

		CBORObject expectedOutputElement1 = CBORObject.FromObject(new byte[0]);
		CBORObject expectedOutputElement2 = CBORObject.FromObject(connectionIdentifierResponder);
		
		Assert.assertEquals(2, output.size());
		Assert.assertEquals(expectedOutputElement1, output.get(0));
		Assert.assertEquals(expectedOutputElement2, output.get(1));
		
	}
	
	/**
	 * Test writing of message 4, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 * See: draft-ietf-lake-traces
	 */
	@Test
	public void testWriteMessage4CipherSuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = false;
		int method = 0;
		
		
		/* Responder information*/

		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x18};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The x509 certificate of the Responder
		byte[] serializedCert = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323433365A170D3239313233313233303030305A30223120301E06035504030C174544484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C152CB02");
		
		// CRED_R, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credR = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_R for the identity key of the Responder, built from the x509 certificate using x5t
		CBORObject idCredR = Util.buildIdCredX5t(serializedCert);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"ef140ff900b0ab03f0c08d879cbbd4b31ea71e6e7ee7ffcb7e7955777a332799");
		byte[] publicIdentityKeyBytes = StringUtil.hex2ByteArray(
				"a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"e69c23fbf81bc435942446837fe827bf206c8fa10a39db47449e5a813421e1e8");
		byte[] publicEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);

		
		/* Initiator information*/
		
		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x2d};

		// The ephemeral key of the Initiator
		byte[] peerEphemeralPublicKeyBytes = StringUtil.hex2ByteArray(
				"31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
			     put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credR));
		idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), idCredR);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		sideProcessor.setEdhocSession(session);
		
		session.setCurrentStep(Constants.EDHOC_AFTER_M3);
		
		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(0);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdentifierInitiator);
		
		// Store PRK_4e3m computed from the previous protocol step
		byte[] prk4e3m = StringUtil.hex2ByteArray("d584ac2e5dad5a77d14b53ebe72ef1d5daa8860d399373bf2c240afa7ba804da");
		session.setPRK4e3m(prk4e3m);
		
		// Store TH_4 computed from the previous protocol step
		byte[] th4 = StringUtil.hex2ByteArray("6b13325a49bd9f970d3191ee317962df1d4438c66415eaa4cedd62b5b49d7bb7");
		session.setTH4(th4);
		
		// Now write EDHOC message 4
		byte[] message4 = MessageProcessor.writeMessage4(session);

		// Compare with the expected value from the test vectors

		byte[] expectedMessage4 = StringUtil.hex2ByteArray("48ee120e8b5e2a008f");
		
		Assert.assertArrayEquals(expectedMessage4, message4);
		
	}
	
	
	
	
	/**
	 * Test reading of message 4, for authentication with signatures, with x.509 certificates identified by 'x5t'
	 * 
	 */
	@Test
	public void testReadMessage4CipherSuite0Method0() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		
		boolean initiator = true;
		int method = 0;
				
		
		/* Initiator information*/

		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x2d};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(0);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The x509 certificate of the Initiator
		byte[] serializedCert = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B");
		
		// CRED_I, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] credI = CBORObject.FromObject(serializedCert).EncodeToBytes();
		
		// ID_CRED_I for the identity key of the Initiator, built from the x509 certificate using x5t
		CBORObject idCredI = Util.buildIdCredX5t(serializedCert);
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8");
		byte[] publicIdentityKeyBytes = StringUtil.hex2ByteArray(
				"ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes, publicIdentityKeyBytes);
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03");
		byte[] publicEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
		OneKey ephemeralKey = SharedSecretCalculation.buildCurve25519OneKey(privateEphemeralKeyBytes, publicEphemeralKeyBytes);
		
		
		/* Responder information*/
		
		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x18};
		
		// The x509 certificate of the Responder
		byte[] serializedCertResponder = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323433365A170D3239313233313233303030305A30223120301E06035504030C174544484F4320526573706F6E6465722045643235353139302A300506032B6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3AC55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB4ABC949565D86DCE51CFAE52AB82C152CB02");
		
		byte[] responderPublicKeyBinary = StringUtil.hex2ByteArray("a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359");
		OneKey responderPublicKey =  SharedSecretCalculation.buildEd25519OneKey(null, responderPublicKeyBinary);
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		byte[] responderCred = CBORObject.FromObject(serializedCertResponder).EncodeToBytes();
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytes = StringUtil.hex2ByteArray(
				"dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c");
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
		boolean useMessage4 = true;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), identityKey);
		creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credI));
		idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				 put(Integer.valueOf(Constants.CURVE_Ed25519), idCredI);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		edhocSessions.put(CBORObject.FromObject(connectionIdentifierInitiator), session);
		
		Set<CBORObject> usedConnectionIds = new HashSet<>();
		usedConnectionIds.add(CBORObject.FromObject(connectionIdentifierInitiator));
		
		HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
		HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
		
		CBORObject responderIdCred = Util.buildIdCredX5t(serializedCertResponder); // ID_CRED as 'x5t'
		peerPublicKeys.put(responderIdCred, responderPublicKey);
		peerCredentials.put(responderIdCred, CBORObject.FromObject(responderCred));
		
		Set<CBORObject> ownIdCreds = new HashSet<>();
		CBORObject idCred = Util.buildIdCredX5t(serializedCert);
		ownIdCreds.add(idCred);
		
		SideProcessor sideProcessor = new SideProcessor(trustModel, peerCredentials, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys of the initiator, i.e., X and G_X
		session.setEphemeralKey(ephemeralKey);
		
		// Set the ephemeral keys of the responder, i.e., Y and G_Y
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(0);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdentifierResponder);
		
		// Store PRK_4e3m computed from the previous protocol step
		byte[] prk4e3m = StringUtil.hex2ByteArray("d584ac2e5dad5a77d14b53ebe72ef1d5daa8860d399373bf2c240afa7ba804da");
		session.setPRK4e3m(prk4e3m);
		
		// Store TH_4 computed from the previous protocol step
		byte[] th4 = StringUtil.hex2ByteArray("6b13325a49bd9f970d3191ee317962df1d4438c66415eaa4cedd62b5b49d7bb7");
		session.setTH4(th4);
				
		session.setCurrentStep(Constants.EDHOC_SENT_M3);
		
		
		
		byte[] message4 = StringUtil.hex2ByteArray("48ee120e8b5e2a008f");

		List<CBORObject> output = MessageProcessor.readMessage4(message4, false, connectionIdentifierInitiator,
															   edhocSessions, usedConnectionIds);

		CBORObject expectedOutput = CBORObject.FromObject(new byte[0]);
		
		Assert.assertEquals(1, output.size());
		Assert.assertEquals(expectedOutput, output.get(0));
		
	}
	
	/**
	 * Test writing of message 1, for static-static authentication with MACs, with CCS identified by 'kid'
	 * 
	 * See: draft-ietf-lake-traces
	 */
	@Test
	public void testWriteMessage1CipherSuite2Method3() {
		
		boolean initiator = true;
		int method = 3;
		
		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x37};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(6);
		supportedCipherSuites.add(2);
		
		Set<Integer> supportedEADs = new HashSet<>();

		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		// Force the early knowledge of cipher suites supported by the other peer
		peerSupportedCipherSuites.add(2);
		
		OneKey identityKey = Util.generateKeyPair(KeyKeys.EC2_P256.AsInt32());
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		
		// ID_CRED_I for the identity key of the Initiator
		byte[] idCredKid = new byte[] {(byte) 0x2b};
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		
		// CRED_I for the identity key of the Initiator
		byte[] cred = StringUtil.hex2ByteArray(
				"A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
		
				
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(cred));
		idCreds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), idCred);
		
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator, keyPairs,
				                                idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
				                                supportedEADs, appProfile, trustModel, db);

		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		sideProcessor.setEdhocSession(session);
		
		// Force a specific ephemeral key
		byte[] privateEkeyBytes = StringUtil.hex2ByteArray(
				"368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
		byte[] publicEkeyBytesX = StringUtil.hex2ByteArray(
				"8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicEkeyBytesY = StringUtil.hex2ByteArray(
				"51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
		OneKey ek = SharedSecretCalculation.buildEcdsa256OneKey(privateEkeyBytes, publicEkeyBytesX, publicEkeyBytesY);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session);

		// Compare with the expected value from the test vectors

		// Note: the actual EDHOC message 1 starts with 0x03. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload. 
		byte[] expectedMessage1 = StringUtil.hex2ByteArray(
				"f5" + "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
		
		Assert.assertArrayEquals(expectedMessage1, message1);
	}
	
	/**
	 * Tests reading EDHOC message_1, for static-static authentication with MACs, with CCS identified by 'kid'
	 * 
	 */
	@Test
	public void testReadMessage1CipherSuite2Method3() {
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		
		int trustModel = Constants.TRUST_MODEL_STRICT;
		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		
				
		// Note: the actual EDHOC message 1 starts with 0x00. The byte 0xf5 (CBOR simple value True) is prepended,
		//       in order to enable the reading of the message as the first one in a new EDHOC session
		byte[] message1 = StringUtil.hex2ByteArray(
				"f5" + "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
		
		List<CBORObject> output = MessageProcessor.readMessage1(message1, true, supportedCipherSuites,
																supportedEADs, appProfile, sideProcessor);
		
		CBORObject expectedOutput = CBORObject.FromObject(new byte[0]);
		
		Assert.assertEquals(1, output.size());
		Assert.assertEquals(expectedOutput, output.get(0));
		
	}
	
	/**
	 * Test writing of message 2, for static-static authentication with MACs, with CCS identified by 'kid'
	 * 
	 * See: draft-ietf-lake-traces
	 */
	@Test
	public void testWriteMessage2CipherSuite2Method3() {

		boolean initiator = false;
		int method = 3;

		
		/* Responder information*/

		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x27};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
		byte[] publicIdentityKeyBytesX = StringUtil.hex2ByteArray(
				"bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
		byte[] publicIdentityKeyBytesY = StringUtil.hex2ByteArray("4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes,
																		 publicIdentityKeyBytesX,
																		 publicIdentityKeyBytesY);
		
		// ID_CRED_R for the identity key of the Responder
		byte[] idCredKid = {(byte) 0x32};
		CBORObject idCredR = Util.buildIdCredKid(idCredKid);
		
		// CRED_R for the identity key of the Responder
		byte[] credR = StringUtil.hex2ByteArray("A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
		
				
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418");
		byte[] publicEphemeralKeyBytesX = StringUtil.hex2ByteArray(
				"419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
		byte[] publicEphemeralKeyBytesY = StringUtil.hex2ByteArray(
				"5e4f0dd8a3da0baa16b9d3ad56a0c1860a940af85914915e25019b402417e99d");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
																		  publicEphemeralKeyBytesX,
																		  publicEphemeralKeyBytesY);

		/* Initiator information*/
		
		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x37};

		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytesX = StringUtil.hex2ByteArray(
				"8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicPeerEphemeralKeyBytesY = StringUtil.hex2ByteArray(
				"51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
				
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credR));
		idCreds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), idCredR);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(2);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdentifierInitiator);
		
		// Store the hash of EDHOC Message 1
		// Note: this is the actual EDHOC message 1, so it does not include the byte 0xf5 (True) prepended on the wire
		byte[] message1 = StringUtil.hex2ByteArray(
				"0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
		session.setHashMessage1(message1);
		
		
		// Now write EDHOC message 2
		byte[] message2 = MessageProcessor.writeMessage2(session);

		// Compare with the expected value from the test vectors
		
		byte[] expectedMessage2 = StringUtil.hex2ByteArray(
				"582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a11de42a95d785386a");
		
		Assert.assertArrayEquals(expectedMessage2, message2);
		
	}
	
	/**
	 * Test reading of message 2, for static-static authentication with MACs, with CCS identified by 'kid'
	 * 
	 */
	@Test
	public void testReadMessage2CipherSuite2Method3() {

		boolean initiator = true;
		int method = 3;

		
		/* Initiator information*/

		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x37};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(6);
		supportedCipherSuites.add(2);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
				
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
		byte[] publicIdentityKeyBytesX = StringUtil.hex2ByteArray(
				"ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
		byte[] publicIdentityKeyBytesY = StringUtil.hex2ByteArray(
				"6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// ID_CRED_I for the identity key of the Initiator
		byte[] idCredKid = {(byte) 0x2b};
		CBORObject idCredI = Util.buildIdCredKid(idCredKid);
		
		// CRED_I for the identity key of the Initiator
		byte[] credI = StringUtil.hex2ByteArray(
				"A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
		byte[] publicEphemeralKeyBytesX = StringUtil.hex2ByteArray(
				"8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicEphemeralKeyBytesY = StringUtil.hex2ByteArray(
				"51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
																		  publicEphemeralKeyBytesX,
																		  publicEphemeralKeyBytesY);
		
		/* Responder information*/
		
		byte[] responderPublicKeyBinary = StringUtil.hex2ByteArray("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
		byte[] responderPublicKeyBinaryY = StringUtil.hex2ByteArray("4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		OneKey responderPublicKey =  SharedSecretCalculation.buildEcdsa256OneKey(null, responderPublicKeyBinary, responderPublicKeyBinaryY);
		
		// ID_CRED_R for the identity key of the Responder
		byte[] idCredKidResponder = {(byte) 0x32};
		
		// CRED_R for the identity key of the Responder
		byte[] credR = StringUtil.hex2ByteArray("A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
		
		
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credI));
		idCreds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), idCredI);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		edhocSessions.put(CBORObject.FromObject(connectionIdentifierInitiator), session);
		
		Set<CBORObject> usedConnectionIds = new HashSet<>();
		usedConnectionIds.add(CBORObject.FromObject(connectionIdentifierInitiator));
		
		HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
		HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
		
		CBORObject responderIdCred = Util.buildIdCredKid(idCredKidResponder); // ID_CRED as 'kid'
		peerPublicKeys.put(responderIdCred, responderPublicKey);
		peerCredentials.put(responderIdCred, CBORObject.FromObject(credR));
		
		Set<CBORObject> ownIdCreds = new HashSet<>();
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		ownIdCreds.add(idCred);
		
		SideProcessor sideProcessor = new SideProcessor(trustModel, peerCredentials, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys of the initiator, i.e., X and G_X
		session.setEphemeralKey(ephemeralKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(2);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
				
		// Store the hash of EDHOC Message 1
		// Note: this is the actual EDHOC message 1, so it does not include the byte 0xf5 (True) prepended on the wire
		byte[] message1 = StringUtil.hex2ByteArray(
				"0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637");
		session.setHashMessage1(message1);
		
		session.setCurrentStep(Constants.EDHOC_SENT_M1);
		
		
		
		byte[] message2 = StringUtil.hex2ByteArray(
				"582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a11de42a95d785386a");

		List<CBORObject> output = MessageProcessor.readMessage2(message2, false, connectionIdentifierInitiator,
                												edhocSessions, peerPublicKeys, peerCredentials,
                												usedConnectionIds, ownIdCreds);

		CBORObject expectedOutput = CBORObject.FromObject(new byte[0]);
		
		Assert.assertEquals(1, output.size());
		Assert.assertEquals(expectedOutput, output.get(0));
		
	}
	
	/**
	 * Test writing of message 3, for static-static authentication with MACs, with CCS identified by 'kid'
	 * Test the derivation of OSCORE Master Secret and Master Salt
	 * Test EDHOC-KeyUpdate and a second derivation of OSCORE Master Secret and Master Salt 
	 * 
	 * See: draft-ietf-lake-traces
	 */
	@Test
	public void testWriteMessage3CipherSuite2Method3() {

		boolean initiator = true;
		int method = 3;

		
		/* Initiator information*/

		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x37};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(6);
		supportedCipherSuites.add(2);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
		byte[] publicIdentityKeyBytesX = StringUtil.hex2ByteArray(
				"ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
		byte[] publicIdentityKeyBytesY = StringUtil.hex2ByteArray(
				"6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// ID_CRED_I for the identity key of the Initiator
		byte[] idCredKid = {(byte) 0x2b};
		CBORObject idCredI = Util.buildIdCredKid(idCredKid);
		
		// CRED_I for the identity key of the Initiator
		byte[] credI = StringUtil.hex2ByteArray(
				"A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
		byte[] publicEphemeralKeyBytesX = StringUtil.hex2ByteArray(
				"8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicEphemeralKeyBytesY = StringUtil.hex2ByteArray(
				"51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
																		  publicEphemeralKeyBytesX,
																		  publicEphemeralKeyBytesY);
		
		
		/* Responder information*/

		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x27};
		
		// CRED_R for the identity key of the Responder
		byte[] credR = StringUtil.hex2ByteArray("A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
		
		// The ephemeral key of the Responder
		byte[] peerEphemeralPublicKeyBytesX = StringUtil.hex2ByteArray(
				"419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
		byte[] peerEphemeralPublicKeyBytesY = StringUtil.hex2ByteArray(
				"5e4f0dd8a3da0baa16b9d3ad56a0c1860a940af85914915e25019b402417e99d");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null,
																					peerEphemeralPublicKeyBytesX,
																					peerEphemeralPublicKeyBytesY);

		
		/* Status from after receiving EDHOC Message 2 */
		
		byte[] th2 = StringUtil.hex2ByteArray("356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084b");
		
		byte[] prk3e2m = StringUtil.hex2ByteArray("0ca3d3398296b3c03900987620c11f6fce70781c1d1219720f9ec08c122d8434");
		
		
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
				
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credI));
		idCreds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), idCredI);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys, i.e., X and G_X for the initiator, as well as G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(2);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdentifierResponder);
		
		// Set TH_2 from the previous protocol step
		session.setTH2(th2);

		// Set PLAINTEXT_2 from the previous protocol step
		byte[] plaintext2 = StringUtil.hex2ByteArray("273248fa5efa2ebf920bf3");
		session.setPlaintext2(plaintext2);
		
		// Set PRK_3e2m from the previous protocol step
		session.setPRK3e2m(prk3e2m);
		
		// Set CRED_R from the previous protocol step
		session.setPeerCred(credR);
		
		
		// Now write EDHOC message 3
		byte[] message3 = MessageProcessor.writeMessage3(session);

		// Compare with the expected value from the test vectors
		// Note: the actual EDHOC message 3 starts with 0x52. The byte 0x27 (CBOR encoding for -8) is prepended as C_R,
		//       in order to pass the check against what returned by the EDHOC engine, to be sent as a CoAP request payload.
		
		byte[] expectedMessage3 = StringUtil.hex2ByteArray("27" + "52473dd16077dd71d65b56e6bd71e7a49d6012");

		Assert.assertArrayEquals(expectedMessage3, message3);
		
		
        /* Invoke EDHOC-Exporter to produce OSCORE input material */
		
        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
        
		// Compare with the expected value from the test vectors
        
		byte[] expectedMasterSecret = StringUtil.hex2ByteArray("8c409a332223ad900e44f3434d2d2ce3");
		byte[] expectedMasterSalt = StringUtil.hex2ByteArray("6163f44be862adfa");

       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
		
        
        /* Invoke EDHOC-KeyUpdate to updated the EDHOC key material */
        
        byte[] nonce = StringUtil.hex2ByteArray("a01158fdb820890cd6be169602b8bcea");
       
        try {
			session.edhocKeyUpdate(CBORObject.FromObject(nonce));
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
        
		expectedMasterSecret = StringUtil.hex2ByteArray("c91b164c810b29a63fcb73e51bc455f3");
		expectedMasterSalt = StringUtil.hex2ByteArray("73ce792459403680");

       	Util.nicePrint("OSCORE Master Secret", masterSecret);
        Util.nicePrint("OSCORE Master Salt", masterSalt);
		
        Assert.assertArrayEquals(expectedMasterSecret, masterSecret);
        Assert.assertArrayEquals(expectedMasterSalt, masterSalt);
        
	}
	
	/**
	 * Test reading of message 3, for static-static authentication with MACs, with CCS identified by 'kid'
	 * 
	 */
	@Test
	public void testReadMessage3CipherSuite2Method3() {
		
		boolean initiator = false;
		int method = 3;
		
		
		/* Responder information*/

		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x27};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();

		// CRED_R for the identity key of the Responder
		byte[] credR = StringUtil.hex2ByteArray("A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");

		// ID_CRED_R for the identity key of the Responder
		byte[] idCredKid = {(byte) 0x32};
		CBORObject idCredR = Util.buildIdCredKid(idCredKid);
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
		byte[] publicIdentityKeyBytesX = StringUtil.hex2ByteArray(
				"bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
		byte[] publicIdentityKeyBytesY = StringUtil.hex2ByteArray("4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes,
																		 publicIdentityKeyBytesX,
																		 publicIdentityKeyBytesY);
				
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418");
		byte[] publicEphemeralKeyBytesX = StringUtil.hex2ByteArray(
				"419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
		byte[] publicEphemeralKeyBytesY = StringUtil.hex2ByteArray(
				"5e4f0dd8a3da0baa16b9d3ad56a0c1860a940af85914915e25019b402417e99d");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
																		  publicEphemeralKeyBytesX,
																		  publicEphemeralKeyBytesY);
		
		
		/* Initiator information*/
		
		// Connection Identifier of the Initiator
		
		byte[] initiatorPublicKeyBinary = StringUtil.hex2ByteArray("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
		byte[] initiatorPublicKeyBinaryY = StringUtil.hex2ByteArray("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
		OneKey initiatorPublicKey =  SharedSecretCalculation.buildEcdsa256OneKey(null, initiatorPublicKeyBinary, initiatorPublicKeyBinaryY);

		// ID_CRED_I for the identity key of the Initiator
		byte[] idCredKidInitiator = {(byte) 0x2b};
		
		// CRED_I for the identity key of the Initiator
		byte[] credI = StringUtil.hex2ByteArray(
				"A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
		
		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytesX = StringUtil.hex2ByteArray(
				"ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
		byte[] publicPeerEphemeralKeyBytesY = StringUtil.hex2ByteArray(
				"6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credR));
		idCreds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), idCredR);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		edhocSessions.put(CBORObject.FromObject(connectionIdentifierResponder), session);
		
		Set<CBORObject> usedConnectionIds = new HashSet<>();
		usedConnectionIds.add(CBORObject.FromObject(connectionIdentifierResponder));
		
		HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
		HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
		
		
		CBORObject initiatorIdCred = Util.buildIdCredKid(idCredKidInitiator); // ID_CRED as 'kid'
		peerPublicKeys.put(initiatorIdCred, initiatorPublicKey);
		peerCredentials.put(initiatorIdCred, CBORObject.FromObject(credI));
		
		Set<CBORObject> ownIdCreds = new HashSet<>();
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		ownIdCreds.add(idCred);
		
		SideProcessor sideProcessor = new SideProcessor(trustModel, peerCredentials, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys of the responder, i.e., Y and G_Y
		session.setEphemeralKey(ephemeralKey);
		
		// Set the ephemeral keys of the initiator, i.e., X and G_X
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(2);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Responder to use in this session
		session.setAuthenticationCredential();
		
		// Set TH_2 from the previous protocol step
		byte[] th2 = StringUtil.hex2ByteArray(
				"356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084b");
		session.setTH2(th2);

		// Set PRK_3e2m from the previous protocol step
		byte[] prk3e2m = StringUtil.hex2ByteArray(
		        "0ca3d3398296b3c03900987620c11f6fce70781c1d1219720f9ec08c122d8434");
		session.setPRK3e2m(prk3e2m);
		
		// Set PLAINTEXT_2 from the previous protocol step
		byte[] plaintext2 = StringUtil.hex2ByteArray(
				"273248fa5efa2ebf920bf3");
		session.setPlaintext2(plaintext2);
		
		session.setCurrentStep(Constants.EDHOC_SENT_M2);
		
		
		// Note: the actual EDHOC message 3 starts with 0x52. The byte 0x27 (CBOR encoding for -8) is prepended as C_R,
		//       in order to enable the reading of the message as the first one in a new EDHOC session
		byte[] message3 = StringUtil.hex2ByteArray("27" + "52473dd16077dd71d65b56e6bd71e7a49d6012");

		List<CBORObject> output = MessageProcessor.readMessage3(message3, true, connectionIdentifierResponder,
																edhocSessions, peerPublicKeys, peerCredentials, usedConnectionIds);

		CBORObject expectedOutputElement1 = CBORObject.FromObject(new byte[0]);
		CBORObject expectedOutputElement2 = CBORObject.FromObject(connectionIdentifierResponder);
		
		Assert.assertEquals(2, output.size());
		Assert.assertEquals(expectedOutputElement1, output.get(0));
		Assert.assertEquals(expectedOutputElement2, output.get(1));
		
	}
	
	/**
	 * Test writing of message 4, for static-static authentication with MACs, with CCS identified by 'kid'
	 * 
	 * See: draft-ietf-lake-traces
	 */
	@Test
	public void testWriteMessage4CipherSuite2Method3() {

		boolean initiator = false;
		int method = 3;

		
		/* Responder information*/

		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x27};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(2);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		
		// The identity key of the Responder
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
		byte[] publicIdentityKeyBytesX = StringUtil.hex2ByteArray(
				"bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
		byte[] publicIdentityKeyBytesY = StringUtil.hex2ByteArray(
				"4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// ID_CRED_R for the identity key of the Responder
		byte[] idCredKid = new byte[] {(byte) 0x32};
		CBORObject idCredR = Util.buildIdCredKid(idCredKid);
		
		// CRED_R for the identity key of the Responder
		byte[] credR = StringUtil.hex2ByteArray(
				"A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
		
		
		// The ephemeral key of the Responder
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418");
		byte[] publicEphemeralKeyBytesX = StringUtil.hex2ByteArray(
				"419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
		byte[] publicEphemeralKeyBytesY = StringUtil.hex2ByteArray(
				"5e4f0dd8a3da0baa16b9d3ad56a0c1860a940af85914915e25019b402417e99d");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
																		  publicEphemeralKeyBytesX,
																		  publicEphemeralKeyBytesY);

		
		/* Initiator information*/
		
		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x37};

		// The ephemeral key of the Initiator
		byte[] publicPeerEphemeralKeyBytesX = StringUtil.hex2ByteArray(
				"8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicPeerEphemeralKeyBytesY = StringUtil.hex2ByteArray(
				"51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
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
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credR));
		idCreds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), idCredR);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierResponder, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);
		
		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		sideProcessor.setEdhocSession(session);
		
		session.setCurrentStep(Constants.EDHOC_AFTER_M3);
		
		// Set the ephemeral keys, i.e. G_X for the initiator, as well as Y and G_Y for the Responder
		session.setEphemeralKey(ephemeralKey);
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(2);
		
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdentifierInitiator);
		
		
		// Store PRK_4e3m computed from the previous protocol step
		byte[] prk4e3m = StringUtil.hex2ByteArray("e9cb832a240095d3d0643dbe12e9e2e7b18f0360a3172cea7ac0013ee240e072");
		session.setPRK4e3m(prk4e3m);
		
		// Store TH_4 computed from the previous protocol step
		byte[] th4 = StringUtil.hex2ByteArray("baf60adbc500fce789af25b108ada2275575056c52c1c2036a2da4a643891cb4");
		session.setTH4(th4);
		
		// Now write EDHOC message 4
		byte[] message4 = MessageProcessor.writeMessage4(session);

		// Compare with the expected value from the test vectors

		byte[] expectedMessage4 = StringUtil.hex2ByteArray("488907436470a6e19f");
		
		Assert.assertArrayEquals(expectedMessage4, message4);
		
	}
	
	/**
	 * Test reading of message 4, for static-static authentication with MACs, with CCS identified by 'kid'
	 * 
	 */
	@Test
	public void testReadMessage4CipherSuite2Method3() {

		boolean initiator = true;
		int method = 3;

		
		/* Initiator information*/

		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] {(byte) 0x37};
		
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(6);
		supportedCipherSuites.add(2);
		
		Set<Integer> supportedEADs = new HashSet<>();
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
				
		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = StringUtil.hex2ByteArray(
				"fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
		byte[] publicIdentityKeyBytesX = StringUtil.hex2ByteArray(
				"ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
		byte[] publicIdentityKeyBytesY = StringUtil.hex2ByteArray(
				"6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
		OneKey identityKey = SharedSecretCalculation.buildEcdsa256OneKey(privateIdentityKeyBytes, publicIdentityKeyBytesX, publicIdentityKeyBytesY);
		
		// ID_CRED_I for the identity key of the Initiator
		byte[] idCredKid = {(byte) 0x2b};
		CBORObject idCredI = Util.buildIdCredKid(idCredKid);
		
		// CRED_I for the identity key of the Initiator
		byte[] credI = StringUtil.hex2ByteArray(
				"A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
		
		// The ephemeral key of the Initiator
		byte[] privateEphemeralKeyBytes = StringUtil.hex2ByteArray(
				"368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525");
		byte[] publicEphemeralKeyBytesX = StringUtil.hex2ByteArray(
				"8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6");
		byte[] publicEphemeralKeyBytesY = StringUtil.hex2ByteArray(
				"51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3");
		OneKey ephemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(privateEphemeralKeyBytes,
																		  publicEphemeralKeyBytesX,
																		  publicEphemeralKeyBytesY);
		
		/* Responder information*/
		
		// Connection Identifier of the Responder
		byte[] connectionIdentifierResponder = new byte[] {(byte) 0x27};
		
		byte[] responderPublicKeyBinary = StringUtil.hex2ByteArray("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
		byte[] responderPublicKeyBinaryY = StringUtil.hex2ByteArray("4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		OneKey responderPublicKey =  SharedSecretCalculation.buildEcdsa256OneKey(null, responderPublicKeyBinary, responderPublicKeyBinaryY);
		
		// ID_CRED_R for the identity key of the Responder
		byte[] idCredKidResponder = {(byte) 0x32};
		
		// CRED_R for the identity key of the Responder
		byte[] credR = StringUtil.hex2ByteArray("A2026B6578616D706C652E65647508A101A501020241322001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
		
		// The ephemeral key of the Responder
		byte[] publicEphemeralPublicKeyBytesX = StringUtil.hex2ByteArray(
				"419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5");
		byte[] publicEphemeralPublicKeyBytesY = StringUtil.hex2ByteArray(
				"5e4f0dd8a3da0baa16b9d3ad56a0c1860a940af85914915e25019b402417e99d");
		OneKey peerEphemeralPublicKey = SharedSecretCalculation.buildEcdsa256OneKey(null,
																					publicEphemeralPublicKeyBytesX,
																					publicEphemeralPublicKeyBytesY);
		
		
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
		boolean useMessage4 = true;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;
		
		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();
		
		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		
		keyPairs.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), identityKey);
		creds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credI));
		idCreds.get(Integer.valueOf(Constants.ECDH_KEY)).
				 put(Integer.valueOf(Constants.CURVE_P256), idCredI);
		
		// Create the session
		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator, keyPairs,
												idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												supportedEADs, appProfile, trustModel, db);

		HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
		edhocSessions.put(CBORObject.FromObject(connectionIdentifierInitiator), session);
		
		Set<CBORObject> usedConnectionIds = new HashSet<>();
		usedConnectionIds.add(CBORObject.FromObject(connectionIdentifierInitiator));
		
		HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
		HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
		
		CBORObject responderIdCred = Util.buildIdCredKid(idCredKidResponder); // ID_CRED as 'kid'
		peerPublicKeys.put(responderIdCred, responderPublicKey);
		peerCredentials.put(responderIdCred, CBORObject.FromObject(credR));
		
		Set<CBORObject> ownIdCreds = new HashSet<>();
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		ownIdCreds.add(idCred);
		
		SideProcessor sideProcessor = new SideProcessor(trustModel, peerCredentials, null);
		sideProcessor.setEdhocSession(session);
		
		// Set the ephemeral keys of the initiator, i.e., X and G_X
		session.setEphemeralKey(ephemeralKey);
		
		// Set the ephemeral keys of the responder, i.e., Y and G_Y
		session.setPeerEphemeralPublicKey(peerEphemeralPublicKey);

		// Set the selected cipher suite
		session.setSelectedCipherSuite(2);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
		session.setAuthenticationCredential();
				
		// Set the Connection Identifier of the peer
		session.setPeerConnectionId(connectionIdentifierResponder);
		
		// Store PRK_4e3m computed from the previous protocol step
		byte[] prk4e3m = StringUtil.hex2ByteArray("e9cb832a240095d3d0643dbe12e9e2e7b18f0360a3172cea7ac0013ee240e072");
		session.setPRK4e3m(prk4e3m);
		
		// Store TH_4 computed from the previous protocol step
		byte[] th4 = StringUtil.hex2ByteArray("baf60adbc500fce789af25b108ada2275575056c52c1c2036a2da4a643891cb4");
		session.setTH4(th4);
				
		session.setCurrentStep(Constants.EDHOC_SENT_M3);
		
		
		
		byte[] message4 = StringUtil.hex2ByteArray("488907436470a6e19f");

		List<CBORObject> output = MessageProcessor.readMessage4(message4, false, connectionIdentifierInitiator,
				   edhocSessions, usedConnectionIds);

		CBORObject expectedOutput = CBORObject.FromObject(new byte[0]);
		
		Assert.assertEquals(1, output.size());
		Assert.assertEquals(expectedOutput, output.get(0));
		
	}
	
}
