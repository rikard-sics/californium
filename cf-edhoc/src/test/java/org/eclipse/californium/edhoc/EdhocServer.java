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
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

public class EdhocServer extends CoapServer {

	private static final int COAP_PORT = Configuration.getStandard().get(CoapConfig.COAP_PORT);

	// private static final int COAP_PORT = 5690;
	
	private final static Provider EdDSA = new EdDSASecurityProvider();
	
	
	// Set to True if this CoAP server is the EDHOC responder (only flow available at the moment)
	// Relevant to choose with public keys to install, when testing with selected ciphersuite 0 or 1
	private final static boolean isResponder = true;
	
	// What will be the selected ciphersuite as indicated in EDHOC message 1
	// Has to be aligned between Initiator and Responder, to choose which public keys to install for testing
	private static int selectedCipherSuite = Constants.EDHOC_CIPHER_SUITE_0;
	
	// The authentication method to include in EDHOC message 1 (Initiator only)
	// Has to be aligned between Initiator and Responder, to choose which public keys to install for testing
	private static int authenticationMethod = Constants.EDHOC_AUTH_METHOD_0;
	
    // The type of the credential of this peer
    // Possible values: CRED_TYPE_CWT ; CRED_TYPE_CCS ; CRED_TYPE_X509
    private static int credType = Constants.CRED_TYPE_X509;
    
    // The type of the credential identifier of this peer
    // Possible values: ID_CRED_TYPE_KID ; ID_CRED_TYPE_CWT ; ID_CRED_TYPE_CCS ;
    //                  ID_CRED_TYPE_X5T ; ID_CRED_TYPE_X5U ; ID_CRED_TYPE_X5CHAIN
    private static int idCredType = Constants.ID_CRED_TYPE_X5T;
    
    // The type of the credential of the other peer
    // Possible values: CRED_TYPE_CWT ; CRED_TYPE_CCS ; CRED_TYPE_X509
    private static int peerCredType = Constants.CRED_TYPE_X509;
    
    // The type of the credential identifier of the other peer
    // Possible values: ID_CRED_TYPE_KID ; ID_CRED_TYPE_CWT ; ID_CRED_TYPE_CCS ;
    //                  ID_CRED_TYPE_X5T ; ID_CRED_TYPE_X5U ; ID_CRED_TYPE_X5CHAIN
    private static int peerIdCredType = Constants.ID_CRED_TYPE_X5T;
    
    // The subject name used for the identity key of this peer
    private static String subjectName = "";
    
    // The CRED used for the identity key of this peer
    private static byte[] cred = null;
    
    // The ID_CRED used for the identity key of this peer
    private static CBORObject idCred = null;
    
	// Key curve of the long-term identity key of this peer
    private static int keyCurve = -1;

	// Key curve of the long-term identity key of the other peer
    private static int peerKeyCurve = -1;
    
    // The long-term asymmetric key pair of this peer
	private static OneKey keyPair = null;
	
	// Each element is the ID_CRED_X used for an
	// authentication credential associated to this peer
	private static Set<CBORObject> ownIdCreds = new HashSet<>();
	
	// Long-term public keys of authorized peers
	// The map label is a CBOR Map used as ID_CRED_X
	private static Map<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
	
	// CRED of the long-term public keys of authorized peers
	// The map label is a CBOR Map used as ID_CRED_X
	// The map value is a CBOR byte string, with value the serialization of CRED
	// (i.e. what the other peer stores as CRED in its Session)
	private static Map<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();

	// Existing EDHOC Sessions, including completed ones
	// The map label is C_X, i.e. the connection identifier offered to the other peer, as a CBOR integer or byte string
	private static Map<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
	
	// Each element is a used Connection Identifier offered to the other peers.
	// Connection Identifiers are stored as CBOR integers (if numeric) or as CBOR byte strings (if binary)
	private static Set<CBORObject> usedConnectionIds = new HashSet<>();
	
	// List of supported ciphersuites, in decreasing order of preference.
	private static List<Integer> supportedCiphersuites = new ArrayList<Integer>();
	
	// The collection of application profiles - The lookup key is the full URI of the EDHOC resource
	private static Map<String, AppProfile> appProfiles = new HashMap<String, AppProfile>();
	
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

		// Use to set up hardcoded keys for this peer and the other peer 
		setupIdentityKeys();
		
		// Add the supported ciphersuites
		setupSupportedCipherSuites();
		
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
		int conversionMethodOscoreToEdhoc = Constants.CONVERSION_ID_UNDEFINED; // Undefined yields using CONVERSION_ID_CORE
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE,
											   supportCombinedRequest, conversionMethodOscoreToEdhoc);
		
		appProfiles.put(uriLocal + "/.well-known/edhoc", appProfile);
		
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
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// prepare the set of information for this EDHOC endpoint
		EdhocEndpointInfo edhocEndpointInfo = new EdhocEndpointInfo(idCred, cred, keyPair, peerPublicKeys,
																	peerCredentials, edhocSessions, usedConnectionIds,
																	supportedCiphersuites, db, uriLocal,
																	OSCORE_REPLAY_WINDOW, MAX_UNFRAGMENTED_SIZE,
																	appProfiles, edp);
		
		// provide an instance of a .well-known/edhoc resource
		CoapResource edhocResource = new EdhocResource("edhoc", edhocEndpointInfo, ownIdCreds);
		
		wellKnownResource.add(edhocResource);

	}
	
	private static void setupSupportedCipherSuites() {
		
		if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_2);
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_3);
		}
 		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32() || keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_0);
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_1);
 		}
				
	}
	
	private static void setupIdentityKeys () {
		
		byte[] privateKeyBinary = null;
		byte[] publicKeyBinary = null;
		byte[] publicKeyBinaryY = null;
		byte[] peerPublicKeyBinary = null;
		byte[] peerPublicKeyBinaryY = null;
		
		
		// In order to install the right public keys to use for testing, determine the public key curve
		// consistent with the expected selected cipher suite and the expected authentication method.
		if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_0 ||
			selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_1) {
			
			switch (authenticationMethod) {
				case Constants.EDHOC_AUTH_METHOD_0:
					keyCurve = peerKeyCurve = Constants.CURVE_Ed25519;
					break;
				case Constants.EDHOC_AUTH_METHOD_1:
					if (isResponder) {
						keyCurve = Constants.CURVE_X25519;
						peerKeyCurve = Constants.CURVE_Ed25519;
					}
					else {						
						keyCurve = Constants.CURVE_Ed25519;
						peerKeyCurve = Constants.CURVE_X25519;
					}
					break;
				case Constants.EDHOC_AUTH_METHOD_2:
					if (isResponder) {
						keyCurve = Constants.CURVE_Ed25519;
						peerKeyCurve = Constants.CURVE_X25519;
					}
					else {
						keyCurve = Constants.CURVE_X25519;
						peerKeyCurve = Constants.CURVE_Ed25519;
					}
					break;
				case Constants.EDHOC_AUTH_METHOD_3:
					keyCurve = peerKeyCurve = Constants.CURVE_X25519;
					break;
			}			
		}
		else if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_2 ||
				 selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_3) {
			
			keyCurve = peerKeyCurve = Constants.CURVE_P256;
			
		}
				
		/* Values as binary serializations */
		if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
			privateKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("ec93c2f8a58f123daa982688e384f54c10c50a1d2c90c00304f648e58f14354c");
			publicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f");
			publicKeyBinaryY = net.i2p.crypto.eddsa.Utils.hexToBytes("C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800");
		}
 		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
 			privateKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("df69274d713296e246306365372b4683ced5381bfcadcd440a24c391d2fedb94");
 			publicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2");
 		}
 		else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
 			privateKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("bb501aac67b9a95f97e0eded6b82a662934fbbfc7ad1b74c1fcad66a079422d0");
 			publicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");
 		}
		
		if (peerKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
			peerPublicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("cd4177ba62433375ede279b5e18e8b91bc3ed8f1e174474a26fc0edb44ea5373");
			peerPublicKeyBinaryY = net.i2p.crypto.eddsa.Utils.hexToBytes("A0391DE29C5C5BADDA610D4E301EAAA18422367722289CD18CBE6624E89B9CFD");
		}
 		else if (peerKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			peerPublicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("38e5d54563c2b6a4ba26f3015f61bb706e5c2efdb556d2e1690b97fc3c6de149");
 		}
 		else if (peerKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
			peerPublicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71");
 		}
		
			
		/* Settings for this peer */
		
		// Build the OneKey object for the identity key pair of this peer
		
		/* Values as binary serializations */
		if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
			keyPair =  SharedSecretCalculation.buildEcdsa256OneKey(privateKeyBinary, publicKeyBinary, publicKeyBinaryY);
		}
 		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			keyPair =  SharedSecretCalculation.buildEd25519OneKey(privateKeyBinary, publicKeyBinary);
		}
		else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
			keyPair =  SharedSecretCalculation.buildCurve25519OneKey(privateKeyBinary, publicKeyBinary);
		}
		
		// Build CRED for this peer
		byte[] serializedCert = null;
		CBORObject ccsObject = null;
		
		// Use 0x07 as kid for this peer, i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x07
		byte[] idCredKid = new byte[] {(byte) 0x07};
		
		switch (credType) {
			case Constants.CRED_TYPE_CWT:
				// TODO
				break;
			case Constants.CRED_TYPE_CCS:
				System.out.print("My   ");
				CBORObject idCredKidCbor = CBORObject.FromObject(idCredKid);
				ccsObject = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(keyPair, subjectName, idCredKidCbor));
				
				// These serializations have to be prepared manually, in order to ensure that
				// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
				if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
					cred = net.i2p.crypto.eddsa.Utils.hexToBytes("a2026008a101a5010202410720012158206f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f225820c8d33274c71c9b3ee57d842bbf2238b8283cb410eca216fb72a78ea7a870f800");
				}
		 		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
					cred = net.i2p.crypto.eddsa.Utils.hexToBytes("a2026008a101a401010241072006215820dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2");
		 		}
		 		else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
					cred = net.i2p.crypto.eddsa.Utils.hexToBytes("a2026008a101a401010241072004215820a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");
		 		}
				break;
			case Constants.CRED_TYPE_X509:
				// The x509 certificate of this peer
	    		serializedCert = net.i2p.crypto.eddsa.Utils.hexToBytes("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb2");
	    		
	    		// Test with Peter (real DER certificate for the same identity key)
	    		// serializedCert = net.i2p.crypto.eddsa.Utils.hexToBytes("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
	    		
	    		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
	    		cred = CBORObject.FromObject(serializedCert).EncodeToBytes();
	    		break;
		}
		
		// Build ID_CRED for this peer
	    switch (idCredType) {
	    	case Constants.ID_CRED_TYPE_KID:
	    		// ID_CRED for the identity key of this peer, using the kid associated to the RPK
				idCred = Util.buildIdCredKid(idCredKid);
				break;
	    	case Constants.ID_CRED_TYPE_CWT:
	    		// ID_CRED for the identity key of this peer, using a CWT to transport the RPK by value
				// TODO
				break;
	    	case Constants.ID_CRED_TYPE_CCS:
	    		// ID_CRED for the identity key of this peer, using a CCS to transport the RPK by value
	    		idCred = Util.buildIdCredKccs(ccsObject);
				break;
			case Constants.ID_CRED_TYPE_X5CHAIN:
	    		// ID_CRED for the identity key of this peer, built from the x509 certificate using x5chain
	    		idCred = Util.buildIdCredX5chain(serializedCert);
	    		break;
			case Constants.ID_CRED_TYPE_X5T:
	    		// ID_CRED for the identity key of this peer, built from the x509 certificate using x5t
	    		idCred = Util.buildIdCredX5t(serializedCert);
	    		break;
			case Constants.ID_CRED_TYPE_X5U:
	    		// ID_CRED for the identity key of this peer, built from the x509 certificate using x5u
	    		idCred = Util.buildIdCredX5u("http://example.repo.com");
	    		break;
	    }
	    // Add ID_CRED to the whole collection of ID_CRED_X for this peer 
	    if (idCred != null) {
	    	ownIdCreds.add(idCred);
	    }
		
	    
		/* Settings for the other peer */
	    
		// Build the OneKey object for the identity public key of the other peer
	    OneKey peerPublicKey = null;
	    
		/* Values as binary serializations */
		if (peerKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
			peerPublicKey =  SharedSecretCalculation.buildEcdsa256OneKey(null, peerPublicKeyBinary, peerPublicKeyBinaryY);
		}
 		else if (peerKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			peerPublicKey =  SharedSecretCalculation.buildEd25519OneKey(null, peerPublicKeyBinary);
		}
		else if (peerKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
			peerPublicKey =  SharedSecretCalculation.buildCurve25519OneKey(null, peerPublicKeyBinary);
		}

		
		// Build CRED for the other peer
		byte[] peerCred = null;
		byte[] peerSerializedCert = null;
		CBORObject peerCcsObject = null;
		
		// Use 0x24 as kid for the other peer, i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x24
		byte[] peerKid = new byte[] {(byte) 0x24};
		
		switch (peerCredType) {
		case Constants.CRED_TYPE_CWT:
			// TODO
			break;
		case Constants.CRED_TYPE_CCS:				
			System.out.print("Peer ");
			CBORObject peerKidCbor = CBORObject.FromObject(peerKid);
			peerCcsObject = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(peerPublicKey, subjectName, peerKidCbor));
			
			// These serializations have to be prepared manually, in order to ensure that
			// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
			if (peerKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
				peerCred = net.i2p.crypto.eddsa.Utils.hexToBytes("a2026008a101a501020241242001215820cd4177ba62433375ede279b5e18e8b91bc3ed8f1e174474a26fc0edb44ea5373225820a0391de29c5c5badda610d4e301eaaa18422367722289cd18cbe6624e89b9cfd");
			}
	 		else if (peerKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	 			peerCred = net.i2p.crypto.eddsa.Utils.hexToBytes("a2026008a101a40101024124200621582038e5d54563c2b6a4ba26f3015f61bb706e5c2efdb556d2e1690b97fc3c6de149");
	 		}
	 		else if (peerKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
	 			peerCred = net.i2p.crypto.eddsa.Utils.hexToBytes("a2026008a101a4010102412420042158202c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71");
	 		}
			break;
		case Constants.CRED_TYPE_X509:
			// The x509 certificate of the other peer
    		peerSerializedCert = net.i2p.crypto.eddsa.Utils.hexToBytes("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda6");
    		
    		// Test with Peter (real DER certificate for the same identity key)
    		// peerSerializedCert = net.i2p.crypto.eddsa.Utils.hexToBytes("30820225308201cba003020102020711223344556600300a06082a8648ce3d040302306f310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31153013060355040b0c0c6d616e7566616374757265723115301306035504030c0c6d6173612e73746f6b2e6e6c3020170d3231303230393039333131345a180f39393939313233313233353935395a308190310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31163014060355040b0c0d6d616e75666163747572696e67311c301a06035504030c13757569643a706c656467652e312e322e332e34311730150603550405130e706c656467652e312e322e332e343059301306072a8648ce3d020106082a8648ce3d03010703420004d474715902aa13cd63984076ea4aeb38818f99a80413fcdd9e033c3c50318817eb1cd945afce48b64479441d1095fb0cf5c31774c786d07959935839bb147defa32e302c30090603551d1304023000301f0603551d23041830168014707f9105ed9e1e1c3fe0cf869d810b2d43d10042300a06082a8648ce3d040302034800304502200fdaaaf09f44ccdafa54a467de952c1e90d1a9a8f60b96793bc9497af318671202210086fddeb42703574df21c7c36a66a3807034fa3366a72b812567f0ed0249a2b31");
    		
    		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
    		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
    		break;
		}
		
		// Build ID_CRED for the other peer
		CBORObject peerIdCred = null;
		
	    switch (peerIdCredType) {
	    	case Constants.ID_CRED_TYPE_KID:
	    		// ID_CRED for the identity key of the other peer, using the kid associated to the RPK
	    		peerIdCred = Util.buildIdCredKid(peerKid);
				break;
	    	case Constants.ID_CRED_TYPE_CWT:
	    		// ID_CRED for the identity key of the other peer, using a CWT to transport the RPK by value
				// TODO
				break;
	    	case Constants.ID_CRED_TYPE_CCS:
	    		// ID_CRED for the identity key of the other peer, using a CCS to transport the RPK by value
	    		peerIdCred = Util.buildIdCredKccs(peerCcsObject);
				break;
			case Constants.ID_CRED_TYPE_X5CHAIN:
	    		// ID_CRED for the identity key of the other peer, built from the x509 certificate using x5chain
				peerIdCred = Util.buildIdCredX5chain(peerSerializedCert);
	    		break;
			case Constants.ID_CRED_TYPE_X5T:
	    		// ID_CRED for the identity key of the other peer, built from the x509 certificate using x5t
				peerIdCred = Util.buildIdCredX5t(peerSerializedCert);
	    		break;
			case Constants.ID_CRED_TYPE_X5U:
	    		// ID_CRED for the identity key of this peer, built from the x509 certificate using x5u
				peerIdCred = Util.buildIdCredX5u("http://example.repo.com");
	    		break;
	    }
		peerPublicKeys.put(peerIdCred, peerPublicKey);
		peerCredentials.put(peerIdCred, CBORObject.FromObject(peerCred));

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
			System.out.println("Hash input: " + Utils.bytesToHex(inputHash));
			byte[] resultHash = Util.computeHash(inputHash, "SHA-256");
			System.out.println("Hash output: " + Utils.bytesToHex(resultHash));
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
			mySignature = Util.computeSignature(idCredX, externalData, payloadToSign, keyPair);
	        System.out.println("Signing completed");
		} catch (CoseException e) {
			System.err.println("Error while computing the signature: " +  e.getMessage());
		}
		
		boolean verified = false;
		try {
			verified = Util.verifySignature(mySignature, idCredX, externalData, payloadToSign, keyPair);
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
		
		
		System.out.println("Plaintext: " + Utils.bytesToHex(payloadToEncrypt));
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
		
}
