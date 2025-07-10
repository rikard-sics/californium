/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * This class is based on org.eclipse.californium.examples.HelloWorldServer
 * 
 * Contributors:
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class EdhocServer extends CoapServer {

	static {
	    CoapConfig.register();
	}
	
	private static final int COAP_PORT = Configuration.getStandard().get(CoapConfig.COAP_PORT);

	private final static Provider EdDSA = new EdDSASecurityProvider();
	
	// The authentication method to include in EDHOC message_1 (relevant only when Initiator)
	private static int authenticationMethod = Constants.EDHOC_AUTH_METHOD_0;
	
    // The type of the authentication credential of this peer (same type for all its credentials)
    // Possible values: CRED_TYPE_CWT ; CRED_TYPE_CCS ; CRED_TYPE_X509
    private static int credType = Constants.CRED_TYPE_X509;
    
    // The type of the credential identifier to use as ID_CRED_R in EDHOC message_2 or as ID_CRED_I in EDHOC message_3,
    // i.e., for this peer to indicate its own authentication credential to the other peer.
    // Possible values: ID_CRED_TYPE_KID ; ID_CRED_TYPE_CWT ; ID_CRED_TYPE_CCS ;
    //                  ID_CRED_TYPE_X5T ; ID_CRED_TYPE_X5U ; ID_CRED_TYPE_X5CHAIN
    private static int idCredType = Constants.ID_CRED_TYPE_X5T;
    
    // The trust model used to validate authentication credentials of other peers
    private static int trustModel = Constants.TRUST_MODEL_NO_LEARNING;
    
    
    // Authentication credentials of this peer 
    //
    // At the top level, authentication credentials are sorted by key usage of the authentication keys.
    // The outer map has label SIGNATURE_KEY or ECDH_KEY for distinguishing the two key usages. 
    
    // The asymmetric key pairs of this peer (one per supported curve)
	private static HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
    
    // The identifiers of the authentication credentials of this peer
	private static HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
    
    // The authentication credentials of this peer (one per supported curve)
	private static HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
    
	// Each element is the ID_CRED_X used for an authentication credential associated to this peer
	private static Set<CBORObject> ownIdCreds = new HashSet<>();
	
	
	// Authentication credentials of other peers
	// 
	// The map label is a CBOR Map used as ID_CRED_X
	private static HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
	
	// Authentication credentials of other peers
	// 
	// The map label is a CBOR Map used as ID_CRED_X
	// The map value is a CBOR Byte String, with value the serialization of CRED_X
	private static HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
	
	// Existing EDHOC Sessions, including completed ones
	// The map label is C_X, i.e. the connection identifier offered to the other peer
	private static HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
	
	// Each element is a used Connection Identifier offered to the other peers.
	// Connection Identifiers are stored as CBOR byte strings
	private static Set<CBORObject> usedConnectionIds = new HashSet<>();
	
	// List of supported cipher suites, in decreasing order of preference.
	private static List<Integer> supportedCipherSuites = new ArrayList<Integer>();

	// Set of supported EAD items, identified by their EAD label
	private static Set<Integer> supportedEADs = new HashSet<>();
	
	// The collection of application profiles - The lookup key is the full URI of the EDHOC resource
	private static HashMap<String, AppProfile> appProfiles = new HashMap<String, AppProfile>();
	
	// The database of OSCORE Security Contexts
	private final static HashMapCtxDB db = new HashMapCtxDB();
	
	// Lookup identifier to be associated with the OSCORE Security Context
	private final static String uriLocal = "coap://localhost";
	
	// The size of the Replay Window to use in an OSCORE Recipient Context
	private static final int OSCORE_REPLAY_WINDOW = 32;
	
	// The size to consider for MAX_UNFRAGMENTED SIZE
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;
	
	/*
	 * Application entry point.
	 */
	public static void main(String[] args) {
		
		// Insert EdDSA security provider
		Security.insertProviderAt(EdDSA, 1);

		// Enable EDHOC stack with EDHOC and OSCORE layers
		EdhocCoapStackFactory.useAsDefault(db, edhocSessions, peerPublicKeys, peerCredentials,
				                           usedConnectionIds, OSCORE_REPLAY_WINDOW, MAX_UNFRAGMENTED_SIZE);

		// Add the supported cipher suites
		setupSupportedCipherSuites();

		// Add the supported cipher suites
		setupSupportedEADs();
		
		// Set up the authentication credentials for this peer and the other peer
		setupOwnAuthenticationCredentials();

		// Set up the authentication credentials for the other peers 
		setupPeerAuthenticationCredentials();
		
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
		boolean supportCombinedRequest = true; // If set to true, it overrides the ID conversion method to CONVERSION_ID_CORE
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		
		appProfiles.put("/.well-known/edhoc", appProfile);
		
		try {
			// create server
			boolean udp = true;

			EdhocServer server = new EdhocServer();
			// add endpoints on all IP addresses
			server.addEndpoints(udp);
			server.start();
						
		} catch (SocketException e) {
			System.err.println("Failed to initialize server: " + e.getMessage());
		}
				
		// Use to dynamically generate a key pair
		// keyPair = Util.generateKeyPair(keyCurve);
		    	
    	// Uncomment to run tests of different cryptographic operations
		// runTests();		
	}

	/**
	 * Add individual endpoints listening on default CoAP port on all IPv4
	 * addresses of all network interfaces.
	 */
	private void addEndpoints(boolean udp) {
		Configuration config = Configuration.getStandard();
		for (InetAddress addr : NetworkInterfacesUtil.getNetworkInterfaces()) {
			InetSocketAddress bindToAddress = new InetSocketAddress(addr, COAP_PORT);
			if (udp) {
				CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
				builder.setInetSocketAddress(bindToAddress);
				builder.setConfiguration(config);
				addEndpoint(builder.build());
			}

		}
	}

	/*
	 * Constructor for a new server. Here, the resources of the server are initialized.
	 */
	public EdhocServer() throws SocketException {

		// provide an instance of a Hello-World resource
		add(new HelloWorldResource());
		
		// provide an instance of a .well-known resource
		CoapResource wellKnownResource = new WellKnown();
		add(wellKnownResource);
		
		// If EAD items have to be produced for outgoing EDHOC messages (irrespective of the consumption of EAD items
		// in incoming EDHOC message, this data structure specifies instructions on how to produce those.
		//
		// The outer map key indicates the outgoing EDHOC message in question.
		//
		// Each inner list specifies a sequence of element pairs (CBOR integer, CBOR map).
		// The CBOR integer specifies the ead_label in case of non-critical EAD item,
		// or the corresponding negative value in case of critical EAD item.
		// The CBOR map provides input on how to produce the EAD item,
		// with the map keys from a namespace specific of the ead_label.
		HashMap<Integer, List<CBORObject>> eadProductionInput = null;
		
		// prepare the set of information for this EDHOC endpoint
		EdhocEndpointInfo edhocEndpointInfo = new EdhocEndpointInfo(idCreds, creds, keyPairs, peerPublicKeys,
																	peerCredentials, edhocSessions, usedConnectionIds,
																	supportedCipherSuites, supportedEADs, eadProductionInput,
																	trustModel, db, uriLocal, OSCORE_REPLAY_WINDOW,
																	MAX_UNFRAGMENTED_SIZE, appProfiles);
		
		// provide an instance of a .well-known/edhoc resource
		CoapResource edhocResource = new EdhocResource("edhoc", edhocEndpointInfo, ownIdCreds);
		
		wellKnownResource.add(edhocResource);

	}
		
	/*
	 * Definition of the Hello-World Resource
	 */
	class HelloWorldResource extends CoapResource {

		public HelloWorldResource() {

			// set resource identifier
			super("helloWorld");

			// set display name
			getAttributes().setTitle("Hello-World Resource");
		}

		@Override
		public void handleGET(CoapExchange exchange) {

			// respond to the request
			exchange.respond("Hello World!");
		}
	}
	
	/*
	 * Definition of the .well-known Resource
	 */
	class WellKnown extends CoapResource {

		public WellKnown() {

			// set resource identifier
			super(".well-known");

			// set display name
			getAttributes().setTitle(".well-known");

		}

		@Override
		public void handleGET(CoapExchange exchange) {

			// respond to the request
			exchange.respond(".well-known");
		}
	}
	
	private static void runTests() {
		// Test a hash computation
		System.out.println("=======================");
		System.out.println("Test a hash computation");
		byte[] inputHash = new byte[] {(byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c};
		try {
			System.out.println("Hash input: " + StringUtil.byteArray2HexString(inputHash));
			byte[] resultHash = Util.computeHash(inputHash, "SHA-256");
			System.out.println("Hash output: " + StringUtil.byteArray2HexString(resultHash));
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Hash algorithm not supported");
		}
		System.out.println();
		

		// Test a signature computation and verification
		System.out.println("=======================");
		System.out.println("Test a signature computation and verification");
		byte[] payloadToSign = new byte[] {(byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c};
		byte[] externalData = new byte[] {(byte) 0xef, (byte) 0xde, (byte) 0xac, (byte) 0x75, (byte) 0x0f, (byte) 0xc5};
		byte[] kid = new byte[] {(byte) 0x01};
		CBORObject idCredX = CBORObject.NewMap();
		idCredX.Add(HeaderKeys.KID.AsCBOR(), kid);
		CBORObject emptyMap = CBORObject.NewMap();
		
		byte[] mySignature = null;
		try {
			mySignature = Util.computeSignature(idCredX, externalData, payloadToSign,
												keyPairs.get(Constants.SIGNATURE_KEY).
												         get(Integer.valueOf(Constants.CURVE_Ed25519)));
	        System.out.println("Signing completed");
		} catch (CoseException e) {
			System.err.println("Error while computing the signature: " +  e.getMessage());
		}
		
		boolean verified = false;
		try {
			verified = Util.verifySignature(mySignature, idCredX, externalData, payloadToSign,
											keyPairs.get(Constants.SIGNATURE_KEY).
													 get(Integer.valueOf(Constants.CURVE_Ed25519)));
		} catch (CoseException e) {
			System.err.println("Error while verifying the signature: " + e.getMessage());
		}
		System.out.println("Signature validity: " + verified);
		System.out.println();
		
		
		// Test an encryption and decryption
		System.out.println("=======================");
		System.out.println("Test an encryption and decryption");
		byte[] payloadToEncrypt = new byte[] {(byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c};
		byte[] symmetricKey =  new byte[] {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
				                           (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x10, (byte) 0x11,
				                           (byte) 0x12, (byte) 0x013, (byte) 0x14, (byte) 0x15};
		byte[] iv = {(byte) 0xc5, (byte) 0xb7, (byte) 0x17, (byte) 0x0e, (byte) 0x65, (byte) 0xd5, (byte) 0x4f,
				     (byte) 0x1a, (byte) 0xe0, (byte) 0x5d, (byte) 0x10, (byte) 0xaf, (byte) 0x56,};
		AlgorithmID encryptionAlg = AlgorithmID.AES_CCM_16_64_128;
		
		
		System.out.println("Plaintext: " + StringUtil.byteArray2HexString(payloadToEncrypt));
		byte[] myCiphertext = null;
		try {
			myCiphertext = Util.encrypt(emptyMap, externalData, payloadToEncrypt, encryptionAlg, iv, symmetricKey);
			System.out.println("Encryption completed");
		} catch (CoseException e) {
			System.err.println("Error while encrypting: " + e.getMessage());
		}
		byte[] myPlaintext = null;
		try {
			myPlaintext = Util.decrypt(emptyMap, externalData, myCiphertext, encryptionAlg, iv, symmetricKey);
			System.out.println("Decryption completed");
		} catch (CoseException e) {
			System.err.println("Error while encrypting: " + e.getMessage());
		}
		System.out.println("Decryption correctness: " + Arrays.equals(payloadToEncrypt, myPlaintext));
		System.out.println();
		
	}
	
	private static void setupSupportedCipherSuites() {
		
		// Add the supported cipher suites in decreasing order of preference
		
		supportedCipherSuites.add(Constants.EDHOC_CIPHER_SUITE_0);
		supportedCipherSuites.add(Constants.EDHOC_CIPHER_SUITE_1);
		supportedCipherSuites.add(Constants.EDHOC_CIPHER_SUITE_2);
		supportedCipherSuites.add(Constants.EDHOC_CIPHER_SUITE_3);
				
	}
	
	private static void setupSupportedEADs() {
	    
	    // Add the supported EAD items, as per the example line below
	    // supportedEADs.add(Integer.valueOf(1));
	    
	}

	private static void setupOwnAuthenticationCredentials () {
		
		byte[] privateKeyBinary = null;
		byte[] publicKeyBinary = null;
		byte[] publicKeyBinaryY = null;
		byte[] serializedCert = null;
		
		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		keyPairs.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		creds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.ECDH_KEY), new HashMap<Integer, CBORObject>());
		
		// A single type will be used for all these authentication credentials.
		// A single type will be used for identifiers of the authentication credentials.

	    // The subject name used for the identity key of this peer
	    String subjectName = "";
		
	    
		// Add one authentication credential for curve Ed25519 and one for curve X25519
		
		if (supportedCipherSuites.contains(Integer.valueOf(Constants.EDHOC_CIPHER_SUITE_0)) ||
			supportedCipherSuites.contains(Integer.valueOf(Constants.EDHOC_CIPHER_SUITE_1))) {

			
			// Curve Ed25519
			
			OneKey keyPairEd25519 = null;
			byte[] credEd25519 = null;
			CBORObject idCredEd25519 = null;
			CBORObject ccsObjectEd25519 = null;
			
			// If the type of credential identifier is 'kid', use 0x07,
			// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x07
			byte[] kidEd25519 = new byte[] {(byte) 0x07};
			
			// Build the key pair
			
 			privateKeyBinary = StringUtil.hex2ByteArray("df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94");
			publicKeyBinary = StringUtil.hex2ByteArray("dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2");
			keyPairEd25519 = SharedSecretCalculation.buildEd25519OneKey(privateKeyBinary, publicKeyBinary);
			
			// Build CRED
			
			switch (credType) {
		    case Constants.CRED_TYPE_CWT:
		        // TODO
		        break;
		    case Constants.CRED_TYPE_CCS:
		        System.out.print("My   ");
		        CBORObject idCredKidCbor = CBORObject.FromObject(kidEd25519);
		        ccsObjectEd25519 = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(keyPairEd25519, subjectName, idCredKidCbor));
		        
		        // These serializations have to be prepared manually, in order to ensure that
		        // the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
		        credEd25519 = StringUtil.hex2ByteArray("a2026008a101a401010241072006215820dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2");
		        break;
		    case Constants.CRED_TYPE_X509:
		        // The x509 certificate of this peer
		        serializedCert = StringUtil.hex2ByteArray("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb2");
		        
		        // Test with Peter (real DER certificate for the same identity key)
		        // serializedCert = StringUtil.hex2ByteArray("30820225308201cba003020102020711223344556600300a06082a8648ce3d040302306f310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31153013060355040b0c0c6d616e7566616374757265723115301306035504030c0c6d6173612e73746f6b2e6e6c3020170d3231303230393039333131345a180f39393939313233313233353935395a308190310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31163014060355040b0c0d6d616e75666163747572696e67311c301a06035504030c13757569643a706c656467652e312e322e332e34311730150603550405130e706c656467652e312e322e332e343059301306072a8648ce3d020106082a8648ce3d03010703420004d474715902aa13cd63984076ea4aeb38818f99a80413fcdd9e033c3c50318817eb1cd945afce48b64479441d1095fb0cf5c31774c786d07959935839bb147defa32e302c30090603551d1304023000301f0603551d23041830168014707f9105ed9e1e1c3fe0cf869d810b2d43d10042300a06082a8648ce3d040302034800304502200fdaaaf09f44ccdafa54a467de952c1e90d1a9a8f60b96793bc9497af318671202210086fddeb42703574df21c7c36a66a3807034fa3366a72b812567f0ed0249a2b31");
		        
		        // CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		        credEd25519 = CBORObject.FromObject(serializedCert).EncodeToBytes();
		        break;
			}
			
			// Build ID_CRED

			switch (idCredType) {
			case Constants.ID_CRED_TYPE_CWT:
				// TODO
				break;
			case Constants.ID_CRED_TYPE_CCS:
				idCredEd25519 = Util.buildIdCredKccs(ccsObjectEd25519);
				break;
			case Constants.ID_CRED_TYPE_KID:
				idCredEd25519 = Util.buildIdCredKid(kidEd25519);
				break;
			case Constants.ID_CRED_TYPE_X5CHAIN:
				idCredEd25519 = Util.buildIdCredX5chain(serializedCert);
				break;
			case Constants.ID_CRED_TYPE_X5T:
				idCredEd25519 = Util.buildIdCredX5t(serializedCert);
				break;
			case Constants.ID_CRED_TYPE_X5U:
				idCredEd25519 = Util.buildIdCredX5u("http://example.repo.com/hostB-x509-Ed25519");
				break;
			}
			
			// Add the key pair, CRED and ID_CRED to the respective collections
			keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
					 put(Integer.valueOf(Constants.CURVE_Ed25519), keyPairEd25519);
			creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
				  	 put(Integer.valueOf(Constants.CURVE_Ed25519), CBORObject.FromObject(credEd25519));
			idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
			  		 put(Integer.valueOf(Constants.CURVE_Ed25519), idCredEd25519);
			
		    // Add this ID_CRED to the whole collection of ID_CRED_X for this peer 
			ownIdCreds.add(idCredEd25519);
			
			
			// Curve X25519

			OneKey keyPairX25519 = null;
			byte[] credX25519 = null;
			CBORObject idCredX25519 = null;
			CBORObject ccsObjectX25519 = null;
			
			// If the type of credential identifier is 'kid', use 0x08,
			// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x08
			byte[] kidX25519 = new byte[] {(byte) 0x08};
			
			// Build the key pair
			
			privateKeyBinary = StringUtil.hex2ByteArray("bb501aac67b9a95f97e0eded6b82a662934fbbfc7ad1b74c1fcad66a079422d0");
			publicKeyBinary = StringUtil.hex2ByteArray("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");
			keyPairX25519 = SharedSecretCalculation.buildCurve25519OneKey(privateKeyBinary, publicKeyBinary);
			
			// Build CRED
			
			switch (credType) {
		    case Constants.CRED_TYPE_CWT:
		        // TODO
		        break;
		    case Constants.CRED_TYPE_CCS:
		        System.out.print("My   ");
		        CBORObject idCredKidCbor = CBORObject.FromObject(kidX25519);
		        ccsObjectX25519 = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(keyPairX25519, subjectName, idCredKidCbor));
		        
		        // These serializations have to be prepared manually, in order to ensure that
		        // the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
	            credX25519 = StringUtil.hex2ByteArray("a2026008a101a401010241082004215820a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");
		        break;
		    case Constants.CRED_TYPE_X509:
		        // The x509 certificate of this peer
		        serializedCert = StringUtil.hex2ByteArray("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb3");
		        
		        // Test with Peter (real DER certificate for the same identity key)
		        // serializedCert = StringUtil.hex2ByteArray("30820225308201cba003020102020711223344556600300a06082a8648ce3d040302306f310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31153013060355040b0c0c6d616e7566616374757265723115301306035504030c0c6d6173612e73746f6b2e6e6c3020170d3231303230393039333131345a180f39393939313233313233353935395a308190310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31163014060355040b0c0d6d616e75666163747572696e67311c301a06035504030c13757569643a706c656467652e312e322e332e34311730150603550405130e706c656467652e312e322e332e343059301306072a8648ce3d020106082a8648ce3d03010703420004d474715902aa13cd63984076ea4aeb38818f99a80413fcdd9e033c3c50318817eb1cd945afce48b64479441d1095fb0cf5c31774c786d07959935839bb147defa32e302c30090603551d1304023000301f0603551d23041830168014707f9105ed9e1e1c3fe0cf869d810b2d43d10042300a06082a8648ce3d040302034800304502200fdaaaf09f44ccdafa54a467de952c1e90d1a9a8f60b96793bc9497af318671202210086fddeb42703574df21c7c36a66a3807034fa3366a72b812567f0ed0249a2b31");
		        
		        // CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		        credX25519 = CBORObject.FromObject(serializedCert).EncodeToBytes();
		        break;
			}
			
			// Build ID_CRED

			switch (idCredType) {
			case Constants.ID_CRED_TYPE_CWT:
				// TODO
				break;
			case Constants.ID_CRED_TYPE_CCS:
				idCredX25519 = Util.buildIdCredKccs(ccsObjectX25519);
				break;
			case Constants.ID_CRED_TYPE_KID:
				idCredX25519 = Util.buildIdCredKid(kidX25519);
				break;
			case Constants.ID_CRED_TYPE_X5CHAIN:
				idCredX25519 = Util.buildIdCredX5chain(serializedCert);
				break;
			case Constants.ID_CRED_TYPE_X5T:
				idCredX25519 = Util.buildIdCredX5t(serializedCert);
				break;
			case Constants.ID_CRED_TYPE_X5U:
				idCredX25519 = Util.buildIdCredX5u("http://example.repo.com/hostB-x509-X25519");
				break;
			}
			
			// Add the key pair, CRED and ID_CRED to the respective collections
			keyPairs.get(Integer.valueOf(Constants.ECDH_KEY)).
					 put(Integer.valueOf(Constants.CURVE_X25519), keyPairX25519);
			creds.get(Integer.valueOf(Constants.ECDH_KEY)).
            		 put(Integer.valueOf(Constants.CURVE_X25519), CBORObject.FromObject(credX25519));
			idCreds.get(Integer.valueOf(Constants.ECDH_KEY)).
            		 put(Integer.valueOf(Constants.CURVE_X25519), idCredX25519);
						
		    // Add this ID_CRED to the whole collection of ID_CRED_X for this peer 
			ownIdCreds.add(idCredX25519);
			
		}


		// Add two authentication credentials for curve P-256 (one for signing only, one for ECDH only)
		if (supportedCipherSuites.contains(Integer.valueOf(Constants.EDHOC_CIPHER_SUITE_2)) ||
			supportedCipherSuites.contains(Integer.valueOf(Constants.EDHOC_CIPHER_SUITE_3))) {
		
			// Signing authentication credential
			
			OneKey keyPairP256 = null;
			byte[] credP256 = null;
			CBORObject idCredP256 = null;
			CBORObject ccsObjectP256 = null;
			
			// If the type of credential identifier is 'kid', use 0x09,
			// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x09
			byte[] kidP256 = new byte[] {(byte) 0x09};
			
			// Build the key pair
			
			privateKeyBinary = StringUtil.hex2ByteArray("ec93c2f8a58f123daa982688e384f54c10c50a1d2c90c00304f648e58f14354c");
			publicKeyBinary = StringUtil.hex2ByteArray("6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f");
			publicKeyBinaryY = StringUtil.hex2ByteArray("C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800");
			keyPairP256 =  SharedSecretCalculation.buildEcdsa256OneKey(privateKeyBinary, publicKeyBinary, publicKeyBinaryY);
		
			// Build CRED
			switch (credType) {
		    case Constants.CRED_TYPE_CWT:
		        // TODO
		        break;
		    case Constants.CRED_TYPE_CCS:
		        System.out.print("My   ");
		        CBORObject idCredKidCbor = CBORObject.FromObject(kidP256);
		        ccsObjectP256 = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(keyPairP256, subjectName, idCredKidCbor));
		        
		        // These serializations have to be prepared manually, in order to ensure that
		        // the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
	            credP256 = StringUtil.hex2ByteArray("a2026008a101a5010202410920012158206f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f225820c8d33274c71c9b3ee57d842bbf2238b8283cb410eca216fb72a78ea7a870f800");
		        break;
		    case Constants.CRED_TYPE_X509:
		        // The x509 certificate of this peer
		        serializedCert = StringUtil.hex2ByteArray("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb4");
		        
		        // Test with Peter (real DER certificate for the same identity key)
		        // serializedCert = StringUtil.hex2ByteArray("30820225308201cba003020102020711223344556600300a06082a8648ce3d040302306f310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31153013060355040b0c0c6d616e7566616374757265723115301306035504030c0c6d6173612e73746f6b2e6e6c3020170d3231303230393039333131345a180f39393939313233313233353935395a308190310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31163014060355040b0c0d6d616e75666163747572696e67311c301a06035504030c13757569643a706c656467652e312e322e332e34311730150603550405130e706c656467652e312e322e332e343059301306072a8648ce3d020106082a8648ce3d03010703420004d474715902aa13cd63984076ea4aeb38818f99a80413fcdd9e033c3c50318817eb1cd945afce48b64479441d1095fb0cf5c31774c786d07959935839bb147defa32e302c30090603551d1304023000301f0603551d23041830168014707f9105ed9e1e1c3fe0cf869d810b2d43d10042300a06082a8648ce3d040302034800304502200fdaaaf09f44ccdafa54a467de952c1e90d1a9a8f60b96793bc9497af318671202210086fddeb42703574df21c7c36a66a3807034fa3366a72b812567f0ed0249a2b31");
		        
		        // CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		        credP256 = CBORObject.FromObject(serializedCert).EncodeToBytes();
		        break;
			}
			
			// Build ID_CRED

			switch (idCredType) {
			case Constants.ID_CRED_TYPE_CWT:
				// TODO
				break;
			case Constants.ID_CRED_TYPE_CCS:
				idCredP256 = Util.buildIdCredKccs(ccsObjectP256);
				break;
			case Constants.ID_CRED_TYPE_KID:
				idCredP256 = Util.buildIdCredKid(kidP256);
				break;
			case Constants.ID_CRED_TYPE_X5CHAIN:
				idCredP256 = Util.buildIdCredX5chain(serializedCert);
				break;
			case Constants.ID_CRED_TYPE_X5T:
				idCredP256 = Util.buildIdCredX5t(serializedCert);
				break;
			case Constants.ID_CRED_TYPE_X5U:
				idCredP256 = Util.buildIdCredX5u("http://example.repo.com/hostB-x509-P256-signing");
				break;
			}
			
			// Add the key pair, CRED and ID_CRED to the respective collections
			keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
					 put(Integer.valueOf(Constants.CURVE_P256), keyPairP256);
			creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
            		 put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credP256));
			idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).
            		 put(Integer.valueOf(Constants.CURVE_P256), idCredP256);
			
		    // Add this ID_CRED to the whole collection of ID_CRED_X for this peer 
			ownIdCreds.add(idCredP256);
			
			
			// ECDH authentication credential
			
			OneKey keyPairP256dh = null;
			byte[] credP256dh = null;
			CBORObject idCredP256dh = null;
			CBORObject ccsObjectP256dh = null;
			
			// If the type of credential identifier is 'kid', use 0x0a,
			// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x0a
			byte[] kidP256dh = new byte[] {(byte) 0x0a};
			
			// Build the key pair
			
			privateKeyBinary = StringUtil.hex2ByteArray("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac");
			publicKeyBinary = StringUtil.hex2ByteArray("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
			publicKeyBinaryY = StringUtil.hex2ByteArray("4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
			keyPairP256dh =  SharedSecretCalculation.buildEcdsa256OneKey(privateKeyBinary, publicKeyBinary, publicKeyBinaryY);
		
			// Build CRED
			switch (credType) {
		    case Constants.CRED_TYPE_CWT:
		        // TODO
		        break;
		    case Constants.CRED_TYPE_CCS:
		        System.out.print("My   ");
		        CBORObject idCredKidCbor = CBORObject.FromObject(kidP256dh);
		        ccsObjectP256dh = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(keyPairP256dh, subjectName, idCredKidCbor));
		        
		        // These serializations have to be prepared manually, in order to ensure that
		        // the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
	            credP256dh = StringUtil.hex2ByteArray("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");
		        break;
		    case Constants.CRED_TYPE_X509:
		        // The x509 certificate of this peer
		    	serializedCert = StringUtil.hex2ByteArray("4488370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb4");
		        
		        // Test with Peter (real DER certificate for the same identity key)
		        // serializedCert = StringUtil.hex2ByteArray("30820225308201cba003020102020711223344556600300a06082a8648ce3d040302306f310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31153013060355040b0c0c6d616e7566616374757265723115301306035504030c0c6d6173612e73746f6b2e6e6c3020170d3231303230393039333131345a180f39393939313233313233353935395a308190310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31163014060355040b0c0d6d616e75666163747572696e67311c301a06035504030c13757569643a706c656467652e312e322e332e34311730150603550405130e706c656467652e312e322e332e343059301306072a8648ce3d020106082a8648ce3d03010703420004d474715902aa13cd63984076ea4aeb38818f99a80413fcdd9e033c3c50318817eb1cd945afce48b64479441d1095fb0cf5c31774c786d07959935839bb147defa32e302c30090603551d1304023000301f0603551d23041830168014707f9105ed9e1e1c3fe0cf869d810b2d43d10042300a06082a8648ce3d040302034800304502200fdaaaf09f44ccdafa54a467de952c1e90d1a9a8f60b96793bc9497af318671202210086fddeb42703574df21c7c36a66a3807034fa3366a72b812567f0ed0249a2b31");
		        
		        // CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		        credP256dh = CBORObject.FromObject(serializedCert).EncodeToBytes();
		        break;
			}
			
			// Build ID_CRED

			switch (idCredType) {
			case Constants.ID_CRED_TYPE_CWT:
				// TODO
				break;
			case Constants.ID_CRED_TYPE_CCS:
				idCredP256dh = Util.buildIdCredKccs(ccsObjectP256dh);
				break;
			case Constants.ID_CRED_TYPE_KID:
				idCredP256dh = Util.buildIdCredKid(kidP256dh);
				break;
			case Constants.ID_CRED_TYPE_X5CHAIN:
				idCredP256dh = Util.buildIdCredX5chain(serializedCert);
				break;
			case Constants.ID_CRED_TYPE_X5T:
				idCredP256dh = Util.buildIdCredX5t(serializedCert);
				break;
			case Constants.ID_CRED_TYPE_X5U:
				idCredP256dh = Util.buildIdCredX5u("http://example.repo.com/hostB-x509-P256-dh");
				break;
			}
			
			// Add the key pair, CRED and ID_CRED to the respective collections
			keyPairs.get(Integer.valueOf(Constants.ECDH_KEY)).
					 put(Integer.valueOf(Constants.CURVE_P256), keyPairP256dh);
			creds.get(Integer.valueOf(Constants.ECDH_KEY)).
            		 put(Integer.valueOf(Constants.CURVE_P256), CBORObject.FromObject(credP256dh));
			idCreds.get(Integer.valueOf(Constants.ECDH_KEY)).
            		 put(Integer.valueOf(Constants.CURVE_P256), idCredP256dh);
			
		    // Add this ID_CRED to the whole collection of ID_CRED_X for this peer 
			ownIdCreds.add(idCredP256dh);
			
		}

	}

	private static void setupPeerAuthenticationCredentials () {
		
		byte[] peerPublicKeyBinary = null;
		byte[] peerPublicKeyBinaryY = null;
		byte[] peerCred = null;
		byte[] peerSerializedCert = null;

	    // The subject name used for the identity key of the other peer
	    String peerSubjectName = "";

	    
		/* *** *** *** *** */
		//
		// Add other peers' authentication credentials for curve Ed25519
		//
		/* *** *** *** *** */

	    OneKey peer1PublicKeyEd25519 = null;
		CBORObject peer1CcsObjectEd25519 = null;
		CBORObject peer1IdCredEd25519kccs = null;
		CBORObject peer1IdCredEd25519kid = null;
		CBORObject peer1IdCredEd25519x5chain = null;
		CBORObject peer1IdCredEd25519x5t = null;
		CBORObject peer1IdCredEd25519x5u = null;
	    
		// If the type of credential identifier is 'kid', use 0x00,
		// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x00
		byte[] peer1KidEd25519 = new byte[] {(byte) 0x00};
		
		
		// Build the public key
		
		peerPublicKeyBinary = StringUtil.hex2ByteArray("38e5d54563c2b6a4ba26f3015f61bb706e5c2efdb556d2e1690b97fc3c6de149");
		peer1PublicKeyEd25519 =  SharedSecretCalculation.buildEd25519OneKey(null, peerPublicKeyBinary);
		
		
		// Build CRED as a CCS, and the corresponding ID_CRED as 'kccs' and 'kid'
		
		System.out.print("Peer ");
		CBORObject peer1KidCborEd25519 = CBORObject.FromObject(peer1KidEd25519);
		peer1CcsObjectEd25519 = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(peer1PublicKeyEd25519, peerSubjectName, peer1KidCborEd25519));
		
		// These serializations have to be prepared manually, in order to ensure that
		// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
		peerCred = StringUtil.hex2ByteArray("A2026008A101A40101024100200621582038E5D54563C2B6A4BA26F3015F61BB706E5C2EFDB556D2E1690B97FC3C6DE149");
 		
		peer1IdCredEd25519kccs = Util.buildIdCredKccs(peer1CcsObjectEd25519); // ID_CRED as 'kccs'
		peer1IdCredEd25519kid = Util.buildIdCredKid(peer1KidEd25519); // ID_CRED as 'kid'
		
		peerPublicKeys.put(peer1IdCredEd25519kccs, peer1PublicKeyEd25519);
		peerCredentials.put(peer1IdCredEd25519kccs, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredEd25519kid, peer1PublicKeyEd25519);
		peerCredentials.put(peer1IdCredEd25519kid, CBORObject.FromObject(peerCred));
		
		
		// Build CRED as an X.509 certificate, and the corresponding ID_CRED as 'x5chain', 'x5t' and 'x5u'
		peerSerializedCert = StringUtil.hex2ByteArray("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda6");
		
		// Test with Peter (real DER certificate for the same identity key)
		// peerSerializedCert = StringUtil.hex2ByteArray("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
		
		peer1IdCredEd25519x5chain = Util.buildIdCredX5chain(peerSerializedCert); // ID_CRED as 'x5chain'
		peer1IdCredEd25519x5t = Util.buildIdCredX5t(peerSerializedCert); // ID_CRED as 'x5t'
		peer1IdCredEd25519x5u = Util.buildIdCredX5u("http://example.repo.com/hostA-x509-Ed25519"); // ID_CRED as 'x5u'
		
		peerPublicKeys.put(peer1IdCredEd25519x5chain, peer1PublicKeyEd25519);
		peerCredentials.put(peer1IdCredEd25519x5chain, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredEd25519x5t, peer1PublicKeyEd25519);
		peerCredentials.put(peer1IdCredEd25519x5t, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredEd25519x5u, peer1PublicKeyEd25519);
		peerCredentials.put(peer1IdCredEd25519x5u, CBORObject.FromObject(peerCred));
		
		
		/* *** *** *** *** */
		//
		// Add other peers' authentication credentials for curve X25519
		//
		/* *** *** *** *** */
		
	    OneKey peer1PublicKeyX25519 = null;
		CBORObject peer1CcsObjectX25519 = null;
		CBORObject peer1IdCredX25519kccs = null;
		CBORObject peer1IdCredX25519kid = null;
		CBORObject peer1IdCredX25519x5chain = null;
		CBORObject peer1IdCredX25519x5t = null;
		CBORObject peer1IdCredX25519x5u = null;
	    
		// If the type of credential identifier is 'kid', use 0x01,
		// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x01
		byte[] peer1KidX25519 = new byte[] {(byte) 0x01};
		
		// Build the public key
		
		peerPublicKeyBinary = StringUtil.hex2ByteArray("2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71");
		peer1PublicKeyX25519 =  SharedSecretCalculation.buildCurve25519OneKey(null, peerPublicKeyBinary);
		
		
		// Build CRED as a CCS, and the corresponding ID_CRED as 'kccs' and 'kid'
		
		System.out.print("Peer ");
		CBORObject peer1KidCborX25519 = CBORObject.FromObject(peer1KidX25519);
		peer1CcsObjectX25519 = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(peer1PublicKeyX25519, peerSubjectName, peer1KidCborX25519));
		
		// These serializations have to be prepared manually, in order to ensure that
		// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
		peerCred = StringUtil.hex2ByteArray("A2026008A101A4010102410120042158202C440CC121F8D7F24C3B0E41AEDAFE9CAA4F4E7ABB835EC30F1DE88ADB96FF71");
 		
		peer1IdCredX25519kccs = Util.buildIdCredKccs(peer1CcsObjectX25519); // ID_CRED as 'kccs'
		peer1IdCredX25519kid = Util.buildIdCredKid(peer1KidX25519); // ID_CRED as 'kid'
		
		peerPublicKeys.put(peer1IdCredX25519kccs, peer1PublicKeyX25519);
		peerCredentials.put(peer1IdCredX25519kccs, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredX25519kid, peer1PublicKeyX25519);
		peerCredentials.put(peer1IdCredX25519kid, CBORObject.FromObject(peerCred));
		
		
		// Build CRED as an X.509 certificate, and the corresponding ID_CRED as 'x5chain', 'x5t' and 'x5u'
		peerSerializedCert = StringUtil.hex2ByteArray("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda7");
		
		// Test with Peter (real DER certificate for the same identity key)
		// peerSerializedCert = StringUtil.hex2ByteArray("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
		
		peer1IdCredX25519x5chain = Util.buildIdCredX5chain(peerSerializedCert); // ID_CRED as 'x5chain'
		peer1IdCredX25519x5t = Util.buildIdCredX5t(peerSerializedCert); // ID_CRED as 'x5t'
		peer1IdCredX25519x5u = Util.buildIdCredX5u("http://example.repo.com/hostA-x509-X25519"); // ID_CRED as 'x5u'
		
		peerPublicKeys.put(peer1IdCredX25519x5chain, peer1PublicKeyX25519);
		peerCredentials.put(peer1IdCredX25519x5chain, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredX25519x5t, peer1PublicKeyX25519);
		peerCredentials.put(peer1IdCredX25519x5t, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredX25519x5u, peer1PublicKeyX25519);
		peerCredentials.put(peer1IdCredX25519x5u, CBORObject.FromObject(peerCred));
		
	
		/* *** *** *** *** */
		//
		// Add other peers' authentication credentials for curve P-256 (one for signing only, one for ECDH only)
		//
		/* *** *** *** *** */
		
		// Signing authentication credential
		
	    OneKey peer1PublicKeyP256 = null;
		CBORObject peer1CcsObjectP256 = null;
		CBORObject peer1IdCredP256kccs = null;
		CBORObject peer1IdCredP256kid = null;
		CBORObject peer1IdCredP256x5chain = null;
		CBORObject peer1IdCredP256x5t = null;
		CBORObject peer1IdCredP256x5u = null;
	    
		// If the type of credential identifier is 'kid', use 0x02,
		// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x02
		byte[] peer1KidP256 = new byte[] {(byte) 0x02};
		
		
		// Build the public key
		
		peerPublicKeyBinary = StringUtil.hex2ByteArray("cd4177ba62433375ede279b5e18e8b91bc3ed8f1e174474a26fc0edb44ea5373");
		peerPublicKeyBinaryY = StringUtil.hex2ByteArray("A0391DE29C5C5BADDA610D4E301EAAA18422367722289CD18CBE6624E89B9CFD");
		peer1PublicKeyP256 =  SharedSecretCalculation.buildEcdsa256OneKey(null, peerPublicKeyBinary, peerPublicKeyBinaryY);
		
		
		// Build CRED as a CCS, and the corresponding ID_CRED as 'kccs' and 'kid'
		
		System.out.print("Peer ");
		CBORObject peer1KidCborP256 = CBORObject.FromObject(peer1KidP256);
		peer1CcsObjectP256 = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(peer1PublicKeyP256, peerSubjectName, peer1KidCborP256));
		
		// These serializations have to be prepared manually, in order to ensure that
		// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
		peerCred = StringUtil.hex2ByteArray("A2026008A101A501020241022001215820CD4177BA62433375EDE279B5E18E8B91BC3ED8F1E174474A26FC0EDB44EA5373225820A0391DE29C5C5BADDA610D4E301EAAA18422367722289CD18CBE6624E89B9CFD");	
		
		peer1IdCredP256kccs = Util.buildIdCredKccs(peer1CcsObjectP256); // ID_CRED as 'kccs'
		peer1IdCredP256kid = Util.buildIdCredKid(peer1KidP256); // ID_CRED as 'kid'
		
		peerPublicKeys.put(peer1IdCredP256kccs, peer1PublicKeyP256);
		peerCredentials.put(peer1IdCredP256kccs, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredP256kid, peer1PublicKeyP256);
		peerCredentials.put(peer1IdCredP256kid, CBORObject.FromObject(peerCred));
		
		
		// Build CRED as an X.509 certificate, and the corresponding ID_CRED as 'x5chain', 'x5t' and 'x5u'
		peerSerializedCert = StringUtil.hex2ByteArray("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda8");
		
		// Test with Peter (real DER certificate for the same identity key)
		// peerSerializedCert = StringUtil.hex2ByteArray("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
		
		peer1IdCredP256x5chain = Util.buildIdCredX5chain(peerSerializedCert); // ID_CRED as 'x5chain'
		peer1IdCredP256x5t = Util.buildIdCredX5t(peerSerializedCert); // ID_CRED as 'x5t'
		peer1IdCredP256x5u = Util.buildIdCredX5u("http://example.repo.com/hostA-x509-P256-signing"); // ID_CRED as 'x5u'
		
		peerPublicKeys.put(peer1IdCredP256x5chain, peer1PublicKeyP256);
		peerCredentials.put(peer1IdCredP256x5chain, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredP256x5t, peer1PublicKeyP256);
		peerCredentials.put(peer1IdCredP256x5t, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredP256x5u, peer1PublicKeyP256);
		peerCredentials.put(peer1IdCredP256x5u, CBORObject.FromObject(peerCred));

		
		
		// ECDH authentication credential
		
	    OneKey peer1PublicKeyP256DH = null;
		CBORObject peer1CcsObjectP256DH = null;
		CBORObject peer1IdCredP256DHkccs = null;
		CBORObject peer1IdCredP256DHkid = null;
		CBORObject peer1IdCredP256DHx5chain = null;
		CBORObject peer1IdCredP256DHx5t = null;
		CBORObject peer1IdCredP256DHx5u = null;
	    
		// If the type of credential identifier is 'kid', use 0x03,
		// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x03
		byte[] peer1KidP256DH = new byte[] {(byte) 0x03};
		
		// Build the public key
		
		peerPublicKeyBinary = StringUtil.hex2ByteArray("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
		peerPublicKeyBinaryY = StringUtil.hex2ByteArray("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
		
		peer1PublicKeyP256DH =  SharedSecretCalculation.buildEcdsa256OneKey(null, peerPublicKeyBinary, peerPublicKeyBinaryY);
		
		
		// Build CRED as a CCS, and the corresponding ID_CRED as 'kccs' and 'kid'
		
		System.out.print("Peer ");
		CBORObject peer1KidCborP256DH = CBORObject.FromObject(peer1KidP256DH);
		peer1CcsObjectP256DH = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(
														peer1PublicKeyP256DH, peerSubjectName, peer1KidCborP256DH));
		
		// These serializations have to be prepared manually, in order to ensure that
		// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
		peerCred = StringUtil.hex2ByteArray("A2026008A101A501020241032001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
		
		peer1IdCredP256DHkccs = Util.buildIdCredKccs(peer1CcsObjectP256DH); // ID_CRED as 'kccs'
		peer1IdCredP256DHkid = Util.buildIdCredKid(peer1KidP256DH); // ID_CRED as 'kid'
		
		peerPublicKeys.put(peer1IdCredP256DHkccs, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHkccs, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredP256DHkid, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHkid, CBORObject.FromObject(peerCred));
		
		
		// Build CRED as an X.509 certificate, and the corresponding ID_CRED as 'x5chain', 'x5t' and 'x5u'
		peerSerializedCert = StringUtil.hex2ByteArray("7713204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda8");
		
		// Test with Peter (real DER certificate for the same identity key)
		// peerSerializedCert = StringUtil.hex2ByteArray("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
		
		peer1IdCredP256DHx5chain = Util.buildIdCredX5chain(peerSerializedCert); // ID_CRED as 'x5chain'
		peer1IdCredP256DHx5t = Util.buildIdCredX5t(peerSerializedCert); // ID_CRED as 'x5t'
		peer1IdCredP256DHx5u = Util.buildIdCredX5u("http://example.repo.com/hostA-x509-P256-dh"); // ID_CRED as 'x5u'
		
		peerPublicKeys.put(peer1IdCredP256DHx5chain, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHx5chain, CBORObject.FromObject(peerCred));
		
		peerPublicKeys.put(peer1IdCredP256DHx5t, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHx5t, CBORObject.FromObject(peerCred));
		
		peerPublicKeys.put(peer1IdCredP256DHx5u, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHx5u, CBORObject.FromObject(peerCred));
		
	}

}
