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
 * This class is based on org.eclipse.californium.examples.GETClient
 * 
 * Contributors: 
 *    Rikard Höglund (RISE)
 *    Marco Tiloca (RISE)
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

public class EdhocClient {
	
	private static final boolean debugPrint = true;
	
	private static final File CONFIG_FILE = new File("Californium.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Fileclient";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 2 * 1024 * 1024; // 2
																			// MB
	private static final int DEFAULT_BLOCK_SIZE = 512;
	
	private final static Provider EdDSA = new EdDSASecurityProvider();
	
	private final static int keyFormat = 1; // 0 is for Base64; 1 is for binary encoding
	
	// Uncomment to use an ECDSA key pair with curve P-256 as long-term identity key
    // private final static int keyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to use an EdDSA key pair with curve Ed25519 for signatures
    private final static int keyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Uncomment to use a Montgomery key pair with curve X25519
    // private final static int keyCurve = KeyKeys.OKP_X25519.AsInt32();
    
    // The ID_CRED used for the identity key of this peer
    private static CBORObject idCred = null;
    
    // The type of the credential of this peer and the other peer
    // Possible values: CRED_TYPE_RPK ; CRED_TYPE_X5T ; CRED_TYPE_X5U ; CRED_TYPE_X5CHAIN
    private static int credType = Constants.CRED_TYPE_X5T;
    
    // The CRED used for the identity key of this peer
    private static byte[] cred = null;
    
    // The subject name used for the identity key of this peer
    private static String subjectName = "";
    
    // The long-term asymmetric key pair of this peer
	private static OneKey keyPair = null;
	
	// Long-term public keys of authorized peers
	// The map label is a CBOR Map used as ID_CRED_X
	private static Map<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
	
	// CRED of the long-term public keys of authorized peers
	// The map label is a CBOR Map used as ID_CRED_X
	// The map value is a CBOR byte string, with value the serialization of CRED
	// (i.e. the serialization of what the other peer stores as CRED in its Session)
	private static Map<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
		
	// Existing EDHOC Sessions, including completed ones
	// The map label is C_X, i.e. the connection identifier offered to the other peer, as a CBOR byte string
	private static Map<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
	
	// Each set of the list refers to a different size of Connection Identifier, i.e. C_ID_X to offer to the other peer.
	// The element with index 0 includes as elements Recipient IDs with size 1 byte.
	private static List<Set<Integer>> usedConnectionIds = new ArrayList<Set<Integer>>();
	
	// List of supported ciphersuites
	private static List<Integer> supportedCiphersuites = new ArrayList<Integer>();
	
	// The authentication method to be indicated in EDHOC message 1 (relevant for the Initiator only)
	private static int authenticationMethod = Constants.EDHOC_AUTH_METHOD_0;
	
	// The correlation method to be indicated in EDHOC message 1 (relevant for the Initiator only)
	private static int correlationMethod = Constants.EDHOC_CORR_METHOD_1;
		
	// The database of OSCORE Security Contexts
	private final static HashMapCtxDB db = new HashMapCtxDB();
	
	// The size of the Replay Window to use in an OSCORE Recipient Context
	private static final int OSCORE_REPLAY_WINDOW = 32;
	
	// Set to true if an OSCORE-protected exchange is performed after EDHOC completion
	private static final boolean POST_EDHOC_EXCHANGE = false;
	
	// Set to true if EDHOC message_3 will be combined with the first OSCORE request
	private static final boolean OSCORE_EDHOC_COMBINED = false;
	
	// The collection of applicability statements - The lookup key is the full URI of the EDHOC resource
	private static Map<String, AppStatement> appStatements = new HashMap<String, AppStatement>();
	
	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
		}
	};
	
	private static String helloWorldURI = "coap://localhost/helloWorld";
	
	private static String edhocURI = "coap://localhost/.well-known/edhoc";
	// private static String edhocURI = "coap://195.251.58.203:5683/.well-known/edhoc"; // Lidia
	// private static String edhocURI = "coap://edhocerver.proxy.rd.coap.amsuess.com/.well-known/edhoc"; // Christian
	
	/*
	 * Application entry point.
	 * 
	 */
	public static void main(String args[]) {
		String defaultUri = "coap://localhost/helloWorld";
				
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		NetworkConfig.setStandard(config);

		// Insert EdDSA security provider
		Security.insertProviderAt(EdDSA, 1);

		// Enable EDHOC stack with EDHOC and OSCORE layers
		EdhocCoapStackFactory.useAsDefault(db, edhocSessions, peerPublicKeys, peerCredentials,
				                           usedConnectionIds, OSCORE_REPLAY_WINDOW);

		// Use to dynamically generate a key pair
		// keyPair = Util.generateKeyPair(keyCurve);
		Util.generateKeyPair(keyCurve);
		
		// Use to set up hardcoded keys for this peer and the other peer 
		setupIdentityKeys();
				
		// Add the supported ciphersuites
		setupSupportedCipherSuites();
		
		// Set the applicability statement
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(authMethods, false, false);
		appStatements.put(edhocURI, appStatement);
		
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Connection Identifiers; one set for each possible size in bytes.
        	// The set with index 0 refers to Connection Identifiers with size 1 byte
    		usedConnectionIds.add(new HashSet<Integer>());
    	}
    	
		URI uri = null; // URI parameter of the request

		// input URI from command line arguments
		try {
			if (args.length == 0) {
				uri = new URI(defaultUri);
			} else {
				uri = new URI(args[0]);
			}
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}
		// helloWorldExchange(args, uri);
		
		
		// Run EDHOC
		try {
			uri = new URI(edhocURI);
		}
		catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}
		// EDHOC execution with signature key
		edhocExchangeAsInitiator(args, uri);

	}
	
	private static void setupIdentityKeys () {
		
		String keyPairBase64 = null;
		String peerPublicKeyBase64 = null;
		byte[] privateKeyBinary = null;
		byte[] publicKeyBinary = null;
		byte[] publicKeyBinaryY = null;
		byte[] peerPublicKeyBinary = null;
		byte[] peerPublicKeyBinaryY = null;
		
		switch (keyFormat) {
		
			/* For stand-alone testing, as base64 encoding of OneKey objects */
			case 0:
				if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
					keyPairBase64 = "pgMmAQIgASFYIGdZmgAlZDXB6FGfVVxHrB2LL8JMZag4JgK4ZcZ/+GBUIlgguZsSChh5hecy3n4Op+lZZJ2xXdbsz8DY7qRmLdIVavkjWCDfyRlRix5e7y5M9aMohvqWGgWCbCW2UYo7V5JppHHsRA==";
					peerPublicKeyBase64 = "pQMmAQIgASFYIPWSTdB9SCF/+CGXpy7gty8qipdR30t6HgdFGQo8ViiAIlggXvJCtXVXBJwmjMa4YdRbcdgjpXqM57S2CZENPrUGQnM=";
				}
		 		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
		 			keyPairBase64 = "pQMnAQEgBiFYIEPgltbaO4rEBSYv3Lhs09jLtrOdihHUxLdc9pRoR/W9I1ggTriT3VdzE7bLv2mJ3gqW/YIyJ7vDuCac62OZMNO8SP4=";
		 			peerPublicKeyBase64 = "pAMnAQEgBiFYIDzQyFH694a7CcXQasH9RcqnmwQAy2FIX97dGGGy+bpS";
		 		}
		 		else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
		 			keyPairBase64 = "pQMnAQEgBiFYIGt2OynWjaQY4cE9OhPQrwcrZYNg8lRJ+MwXIYMjeCtrI1gg5TeGQyIjv2d2mulBYLnL7Mxp0cuaHMBlSuuFtmaU808=";
		 			peerPublicKeyBase64 = "pAMnAQEgBiFYIKOjK/y+4psOGi9zdnJBqTLThdpEj6Qygg4Voc10NYGS";
		 		}
				break;
			
			/* Value from the test vectors, as binary serializations */
			case 1:
				if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
					privateKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("04f347f2bead699adb247344f347f2bdac93c7f2bead6a9d2a9b24754a1e2b62");
					publicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("cd4177ba62433375ede279b5e18e8b91bc3ed8f1e174474a26fc0edb44ea5373");
					publicKeyBinaryY = net.i2p.crypto.eddsa.Utils.hexToBytes("A0391DE29C5C5BADDA610D4E301EAAA18422367722289CD18CBE6624E89B9CFD");
					peerPublicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f");
					peerPublicKeyBinaryY = net.i2p.crypto.eddsa.Utils.hexToBytes("C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800");
				}
		 		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
		 			privateKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("2ffce7a0b2b825d397d0cb54f746e3da3f27596ee06b5371481dc0e012bc34d7");
					publicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("38e5d54563c2b6a4ba26f3015f61bb706e5c2efdb556d2e1690b97fc3c6de149");					
		 			peerPublicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2");
		 		}
		 		else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
		 			privateKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("2bbea655c23371c329cfbd3b1f02c6c062033837b8b59099a4436f666081b08e");
					publicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71");
		 			peerPublicKeyBinary = net.i2p.crypto.eddsa.Utils.hexToBytes("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");
		 		}
				break;
		
		}
		
		
		try {

			/* Settings for this peer */
			
			// Build the OneKey object for the identity key pair of this peer
			
			switch (keyFormat) {
			/* For stand-alone testing, as base64 encoding of OneKey objects */
			case 0:
				keyPair =  new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(keyPairBase64)));
				break;
				
			/* Value from the test vectors, as binary serializations */
			case 1:
				if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
					keyPair =  SharedSecretCalculation.buildEcdsa256OneKey(privateKeyBinary, publicKeyBinary, publicKeyBinaryY);
				}
		 		else 
				if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
					keyPair =  SharedSecretCalculation.buildEd25519OneKey(privateKeyBinary, publicKeyBinary);
				}
				else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
					keyPair =  SharedSecretCalculation.buildCurve25519OneKey(privateKeyBinary, publicKeyBinary);
				}
				break;
			}
			
			byte[] serializedCert = null;
			
		    switch (credType) {
		    	case Constants.CRED_TYPE_RPK:
					// Build the related ID_CRED
		    		// Use 0x24 as kid for the other peer, i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x24
				    byte[] idCredKid = new byte[] {(byte) 0x24};
					idCred = Util.buildIdCredKid(idCredKid);
					// Build the related CRED
					cred = Util.buildCredRawPublicKey(keyPair, subjectName);
					break;
		    	case Constants.CRED_TYPE_X5CHAIN:
		    	case Constants.CRED_TYPE_X5T:
		    	case Constants.CRED_TYPE_X5U:
		    		// The x509 certificate of this peer
		    		serializedCert = net.i2p.crypto.eddsa.Utils.hexToBytes("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda6");
		    		
		    		// Test with Peter (real DER certificate for the same identity key)
		    		// serializedCert = net.i2p.crypto.eddsa.Utils.hexToBytes("30820225308201cba003020102020711223344556600300a06082a8648ce3d040302306f310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31153013060355040b0c0c6d616e7566616374757265723115301306035504030c0c6d6173612e73746f6b2e6e6c3020170d3231303230393039333131345a180f39393939313233313233353935395a308190310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31163014060355040b0c0d6d616e75666163747572696e67311c301a06035504030c13757569643a706c656467652e312e322e332e34311730150603550405130e706c656467652e312e322e332e343059301306072a8648ce3d020106082a8648ce3d03010703420004d474715902aa13cd63984076ea4aeb38818f99a80413fcdd9e033c3c50318817eb1cd945afce48b64479441d1095fb0cf5c31774c786d07959935839bb147defa32e302c30090603551d1304023000301f0603551d23041830168014707f9105ed9e1e1c3fe0cf869d810b2d43d10042300a06082a8648ce3d040302034800304502200fdaaaf09f44ccdafa54a467de952c1e90d1a9a8f60b96793bc9497af318671202210086fddeb42703574df21c7c36a66a3807034fa3366a72b812567f0ed0249a2b31");
		    		
		    		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		    		cred = CBORObject.FromObject(serializedCert).EncodeToBytes();
		    		switch (credType) {
		    			case Constants.CRED_TYPE_X5CHAIN:
				    		// ID_CRED for the identity key of this peer, built from the x509 certificate using x5chain
				    		idCred = Util.buildIdCredX5chain(serializedCert);
				    		break;
		    			case Constants.CRED_TYPE_X5T:
				    		// ID_CRED for the identity key of this peer, built from the x509 certificate using x5t
				    		idCred = Util.buildIdCredX5t(serializedCert);
				    		break;
		    			case Constants.CRED_TYPE_X5U:
				    		// ID_CRED for the identity key of this peer, built from the x509 certificate using x5u
				    		idCred = Util.buildIdCredX5u("http://example.repo.com");
				    		break;
		    		}
		    }

			
			/* Settings for the other peer */
		    
			// Build the OneKey object for the identity public key of the other peer
		    OneKey peerPublicKey = null;
		    
			switch (keyFormat) {
			/* For stand-alone testing, as base64 encoding of OneKey objects */
			case 0:
				peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(peerPublicKeyBase64)));
				break;
				
			/* Value from the test vectors, as binary serializations */
			case 1:
				if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
					peerPublicKey =  SharedSecretCalculation.buildEcdsa256OneKey(null, peerPublicKeyBinary, peerPublicKeyBinaryY);
				}
		 		else 
				if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
					peerPublicKey =  SharedSecretCalculation.buildEd25519OneKey(null, peerPublicKeyBinary);
				}
				else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
					peerPublicKey =  SharedSecretCalculation.buildCurve25519OneKey(null, peerPublicKeyBinary);
				}
				break;
		}
			
			CBORObject peerIdCred = null;
			byte[] peerCred = null;
			byte[] peerSerializedCert = null;
			
		    switch (credType) {
			    case Constants.CRED_TYPE_RPK:
					// Build the related ID_CRED
		    		// Use 0x07 as kid for the other peer, i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x07
					byte[] peerKid = new byte[] {(byte) 0x07};
					peerIdCred = Util.buildIdCredKid(peerKid);
					// Build the related CRED
					peerCred = Util.buildCredRawPublicKey(peerPublicKey, "");
					break;
			    case Constants.CRED_TYPE_X5CHAIN:
		    	case Constants.CRED_TYPE_X5T:
		    	case Constants.CRED_TYPE_X5U:
		    		// The x509 certificate of the other peer
		    		peerSerializedCert = net.i2p.crypto.eddsa.Utils.hexToBytes("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb2");
		    		
		    		// Test with Peter (real DER certificate for the same identity key)
		    		// peerSerializedCert = net.i2p.crypto.eddsa.Utils.hexToBytes("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
		    		
		    		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		    		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
		    		switch (credType) {
		    			case Constants.CRED_TYPE_X5CHAIN:
				    		// ID_CRED for the identity key of the other peer, built from the x509 certificate using x5chain
		    				peerIdCred = Util.buildIdCredX5chain(peerSerializedCert);
				    		break;
		    			case Constants.CRED_TYPE_X5T:
				    		// ID_CRED for the identity key of the other peer, built from the x509 certificate using x5t
				    		peerIdCred = Util.buildIdCredX5t(peerSerializedCert);
				    		break;
		    			case Constants.CRED_TYPE_X5U:
				    		// ID_CRED for the identity key of the other peer, built from the x509 certificate using x5u
		    				peerIdCred = Util.buildIdCredX5u("http://example.repo.com");
		    				break;
		    		}
		    		break;
		    }
			peerPublicKeys.put(peerIdCred, peerPublicKey);
			peerCredentials.put(peerIdCred, CBORObject.FromObject(peerCred));
			
		} catch (CoseException e) {
			System.err.println("Error while generating the key pair");
			return;
		}
		
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
		
	private static void helloWorldExchange(final String args[], final URI targetUri) {
		
		CoapClient client = new CoapClient(targetUri);

		CoapResponse response = null;
		try {
			response = client.get();
		} catch (ConnectorException | IOException e) {
			System.err.println("Got an error: " + e);
		}

		if (response != null) {

			System.out.println(response.getCode());
			System.out.println(response.getOptions());
			if (args.length > 1) {
				try (FileOutputStream out = new FileOutputStream(args[1])) {
					out.write(response.getPayload());
				} catch (IOException e) {
					System.err.println("Error while writing the response payload to file: " +  e.getMessage());
				}
			} else {
				System.out.println(response.getResponseText());

				System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
				// access advanced API with access to more details through
				// .advanced()
				System.out.println(Utils.prettyPrint(response));
			}
		} else {
			System.out.println("No response received.");
		}
		client.shutdown();
		
	}
	
	private static void edhocExchangeAsInitiator(final String args[], final URI targetUri) {
		
		CoapClient client = new CoapClient(targetUri);
		
		/*
		// Simple sending of a GET request
		 
		CoapResponse response = null;
		
		try {
			response = client.get();
		} catch (ConnectorException | IOException e) {
			System.err.println("Got an error: " + e);
		}

		if (response != null) {

			System.out.println(response.getCode());
			System.out.println(response.getOptions());
			if (args.length > 1) {
				try (FileOutputStream out = new FileOutputStream(args[1])) {
					out.write(response.getPayload());
				} catch (IOException e) {
					System.err.println("Error while writing the response payload to file: " +  e.getMessage());
				}
			} else {
				System.out.println(response.getResponseText());

				System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
				// access advanced API with access to more details through
				// .advanced()
				System.out.println(Utils.prettyPrint(response));
			}
		} else {
			System.out.println("No response received.");
		}
		*/
		
		// Simple test with a dummy payload
		/*
		byte[] requestPayload = { (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03 };
		
		Request edhocMessage1 = new Request(Code.POST, Type.CON);
		edhocMessage1.setPayload(requestPayload);
		edhocMessage1.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
		
        // Submit the request
        System.out.println("\nSent EDHOC Message1\n");
        CoapResponse edhocMessage2;
        try {
			edhocMessage2 = client.advanced(edhocMessage1);
		} catch (ConnectorException e) {
			System.err.println("ConnectorException when sending EDHOC Message1");
			return;
		} catch (IOException e) {
			System.err.println("IOException when sending EDHOC Message1");
			return;
		}
		
        byte[] responsePayload = edhocMessage2.getPayload();
        System.out.println("\nResponse: " + new String(responsePayload) + "\n");
        */		
        
		
		/* Prepare and send EDHOC Message 1 */
		
		// Possibly specify application data for AD_1, or null if none have to be provided
		byte[] ad1 = null;
        
		String uriAsString = targetUri.toString();
		AppStatement appStatement = appStatements.get(uriAsString);
		
		EdhocSession session = MessageProcessor.createSessionAsInitiator
                (authenticationMethod, correlationMethod, keyPair, idCred, cred, subjectName,
                 supportedCiphersuites, usedConnectionIds, appStatement);
		
		// At this point, the initiator may overwrite the information in the EDHOC session about the supported ciphersuites
		// and the selected ciphersuite, based on a previously received EDHOC Error Message
		
        byte[] nextPayload = MessageProcessor.writeMessage1(session, ad1);
        
		if (nextPayload == null || session.getCurrentStep() != Constants.EDHOC_BEFORE_M1) {
			System.err.println("Inconsistent state before sending EDHOC Message 1");
			session.deleteTemporaryMaterial();
			session = null;
			client.shutdown();
			return;
		}
		
		// Add the new session to the list of existing EDHOC sessions
		session.setMessage1(nextPayload);
		session.setCurrentStep(Constants.EDHOC_AFTER_M1);
		byte[] connectionId = session.getConnectionId();
		edhocSessions.put(CBORObject.FromObject(connectionId), session);
		
		Request edhocMessageReq = new Request(Code.POST, Type.CON);
		edhocMessageReq.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
		edhocMessageReq.setPayload(nextPayload);
		
        System.out.println("Sent EDHOC Message 1\n");
        Util.nicePrint("EDHOC message 1", nextPayload);
        
        CoapResponse edhocMessageResp;
        try {
        	edhocMessageResp = client.advanced(edhocMessageReq);
		} catch (ConnectorException e) {
			System.err.println("ConnectorException when sending EDHOC Message 1");
			Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
			client.shutdown();
			return;
		} catch (IOException e) {
			System.err.println("IOException when sending EDHOC Message 1");
			Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
			client.shutdown();
			return;
		}
		
        boolean discontinue = false;
        int responseType = -1;
        byte[] responsePayload = edhocMessageResp.getPayload();
        
        if (responsePayload == null)
        	discontinue = true;
        else {
        	responseType = MessageProcessor.messageType(responsePayload, appStatement);
        	if (responseType != Constants.EDHOC_MESSAGE_2 && responseType != Constants.EDHOC_ERROR_MESSAGE)
        		discontinue = true;
        }
        if (discontinue == true) {
        	System.err.println("Received invalid reply to EDHOC Message 1");
			Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
        	client.shutdown();
        	return;
        }
		
        String myString = (responseType == Constants.EDHOC_MESSAGE_2) ? "EDHOC Message 2" : "EDHOC Error Message";
		System.out.println("Determined EDHOC message type: " + myString + "\n");
        Util.nicePrint("EDHOC message " + responseType, responsePayload);
        
        
		/* Process the received response */
        
        // Since the Correlation Method 1 is used, this response relates to the previous request through the CoAP Token
        // Hence, the Initiator knows what session to refer to, from which the correct C_I can be retrieved
    	CBORObject connectionIdentifier = CBORObject.FromObject(session.getConnectionId());
    	CBORObject cI = Util.encodeToBstrIdentifier(connectionIdentifier);
        
    	nextPayload = new byte[] {};
    	
        // The received message is an EDHOC Error Message
        if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
        	
        	List<Integer> peerSupportedCiphersuites = new ArrayList<Integer>();
        	
        	CBORObject[] objectList = MessageProcessor.readErrorMessage(responsePayload, cI, edhocSessions);
        	
        	if (objectList != null) {
        	
		    	// This execution flow has the client as Initiator. Consistently, the Correlation Method is 1.
		    	// Hence, there is no C_I included, and the first element of the EDHOC Error Message is DIAG_MSG.
		    	String errMsg = objectList[0].toString();
		    	
		    	if (objectList[1].getType() == CBORType.Integer) {
		    		int suite = objectList[1].AsInt32();
		    		peerSupportedCiphersuites.add(Integer.valueOf(suite));
		    	}
		    	else if (objectList[1].getType() == CBORType.Array) {
		    		for (int i = 0; i < objectList.length; i++) {
		        		int suite = objectList[1].get(i).AsInt32();
		        		peerSupportedCiphersuites.add(Integer.valueOf(suite));
		    		}
		    	}
		    	session.setPeerSupportedCipherSuites(peerSupportedCiphersuites);
		    	
		    	System.out.println("DIAG_MSG: " + errMsg + "\n");
		    	
		    	// The following simply deletes the EDHOC session. However, it would be fine to prepare a new
		    	// EDHOC Message 1 right away, keeping the same Connection Identifier C_I and this same session.
		    	// In fact, the session is marked as "used", hence new ephemeral keys would be generated when
		    	// preparing a new EDHOC Message 1.        	
		    	
		    	Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
		    	
        	}
        	
			client.shutdown();
    		return;
    		
        }
        
        // The received message is an EDHOC Message 2
        if (responseType == Constants.EDHOC_MESSAGE_2) {
        	
        	List<CBORObject> processingResult = new ArrayList<CBORObject>();
			
			// Possibly specify application data for AD_3, or null if none have to be provided
			byte[] ad3 = null;
			
			/* Start handling EDHOC Message 2 */
			
			processingResult = MessageProcessor.readMessage2(responsePayload, cI, edhocSessions, peerPublicKeys,
					                                         peerCredentials, usedConnectionIds);
			
			if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
				System.err.println("Internal error when processing EDHOC Message 2");
				Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
				client.shutdown();
				return;
			}
			
			// A non-zero length response payload would be an EDHOC Error Message
			nextPayload = processingResult.get(0).GetByteString();

			// Prepare EDHOC Message 3
			if (nextPayload.length == 0) {
				
				// Deliver AD_2 to the application, if present
				if (processingResult.size() == 2) {
					processAD2(processingResult.get(1).GetByteString());
				}
				
				session.setCurrentStep(Constants.EDHOC_AFTER_M2);
				
				nextPayload = MessageProcessor.writeMessage3(session, ad3);
		        
				if (nextPayload == null || session.getCurrentStep() != Constants.EDHOC_AFTER_M3) {
					System.err.println("Inconsistent state before sending EDHOC Message 3");
					Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
					client.shutdown();
					return;
				}
				
			}

			int requestType = MessageProcessor.messageType(nextPayload, appStatement);			
			if (requestType != Constants.EDHOC_MESSAGE_3 && responseType != Constants.EDHOC_ERROR_MESSAGE) {
				nextPayload = null;
			}
			
			if (nextPayload != null) {
				
				myString = (requestType == Constants.EDHOC_MESSAGE_3) ? "EDHOC Message 3" : "EDHOC Error Message";
				System.out.println("Request type: " + myString + "\n");
				
				if (requestType == Constants.EDHOC_MESSAGE_3) {
			        
			        System.out.println("Sent EDHOC Message 3\n");
			        if (debugPrint) {
			        	Util.nicePrint("EDHOC Message 3", nextPayload);
			        }
					
			        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
			        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
			        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
			        if (debugPrint) {
			        	Util.nicePrint("OSCORE Master Secret", masterSecret);
			        	Util.nicePrint("OSCORE Master Salt", masterSalt);
			        }
			        
			        /* Setup the OSCORE Security Context */
			        
			        // The Sender ID of this peer is the EDHOC connection identifier of the other peer
			        byte[] senderId = session.getPeerConnectionId();
			        
			        int selectedCiphersuite = session.getSelectedCiphersuite();
			        AlgorithmID alg = EdhocSession.getAppAEAD(selectedCiphersuite);
			        AlgorithmID hkdf = EdhocSession.getAppHkdf(selectedCiphersuite);
			        
			        OSCoreCtx ctx = null;
			        try {
						ctx = new OSCoreCtx(masterSecret, true, alg, senderId, 
													  connectionId, hkdf, OSCORE_REPLAY_WINDOW, masterSalt, null);
					} catch (OSException e) {
						System.err.println("Error when deriving the OSCORE Security Context "
					                        + e.getMessage());
						Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
						client.shutdown();
						return;
					}
			        
			        try {
						db.addContext(edhocURI, ctx);
					} catch (OSException e) {
						System.err.println("Error when adding the OSCORE Security Context to the context database "
					                        + e.getMessage());
						Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
						client.shutdown();
						return;
					}
			        
				}
				else if (requestType == Constants.EDHOC_ERROR_MESSAGE) {			     	
				    Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			        System.out.println("Sent EDHOC Error Message\n");
			        if (debugPrint) {
			        	Util.nicePrint("EDHOC Error Message", nextPayload);
			        }
			        
				}
				
		        CoapResponse edhocMessageResp2 = null;
		        
		        try {
					Request edhocMessageReq2 = new Request(Code.POST, Type.CON);
					edhocMessageReq2.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
					edhocMessageReq2.setPayload(nextPayload);
					
		        	// If EDHOC message_3 has to be combined with the first
		        	// OSCORE-protected request include the EDHOC option in the request
		        	if (OSCORE_EDHOC_COMBINED == true && requestType == Constants.EDHOC_MESSAGE_3) {
		        		
		        		
						client = new CoapClient(helloWorldURI);
						CoapResponse protectedResponse = null;
						edhocMessageReq2 = Request.newGet();
						edhocMessageReq2.setType(Type.CON);
						edhocMessageReq2.getOptions().setOscore(Bytes.EMPTY);
						
						
		        		edhocMessageReq2.getOptions().setEdhoc(true);
						session.setMessage3(nextPayload);

						
						try {
							protectedResponse = client.advanced(edhocMessageReq2);
							session.setCurrentStep(Constants.EDHOC_SENT_M3);
						} catch (ConnectorException e) {
							System.err.println("ConnectorException when sending a protected request\n");
						} catch (IOException e) {
							System.err.println("IOException when sending a protected request\n");
						}
					
						byte[] myPayload = protectedResponse.getPayload();
						if (myPayload != null) {
							System.out.println(Utils.prettyPrint(protectedResponse));
						}
						
						session.cleanMessage3();
						
		        	}
		        	else {
		        		edhocMessageResp2 = client.advanced(edhocMessageReq2);
		        		session.setCurrentStep(Constants.EDHOC_SENT_M3);
		        	}
		        	
				} catch (ConnectorException e) {
					System.err.println("ConnectorException when sending " + myString + "\n");
					Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
					client.shutdown();
					return;
				} catch (IOException e) {
					System.err.println("IOException when sending "  + myString + "\n");
					Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
					client.shutdown();
					return;
				}
				
				// Wait for a possible response. For how long?
		        
		        // This is a generic response, to be passed to the application
		        if (edhocMessageResp2 != null && edhocMessageResp2.getOptions().getContentFormat() != Constants.APPLICATION_EDHOC) {
		        	
		        	processResponseAfterEdhoc(edhocMessageResp2);
		        	
		        }
		        else if (edhocMessageResp2 != null) { // Only an EDHOC Error Message is a legitimate EDHOC message at this point
		        	
		        	responseType = -1;
		            responsePayload = edhocMessageResp2.getPayload();
		            
		            if (responsePayload == null)
		            	discontinue = true;
		            else {
		            	responseType = MessageProcessor.messageType(responsePayload, appStatement);
		            	if (responseType != Constants.EDHOC_ERROR_MESSAGE)
		            		discontinue = true;
		            }
		            if (discontinue == true) {
		            	System.err.println("Received invalid reply to EDHOC Message 3");
		    			Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
		            	client.shutdown();
		            	return;
		            }
		    		
		    		System.out.println("Determined EDHOC message type: EDHOC Error Message\n");
		            Util.nicePrint("EDHOC message " + responseType, responsePayload);
		            
		        	CBORObject[] objectList = MessageProcessor.readErrorMessage(responsePayload, cI, edhocSessions);
		        	
		        	if (objectList != null) {
		        		
				    	// This execution flow has the client as Initiator. Consistently, the Correlation Method is 1.
				    	// Hence, there is no C_I included, and the first element of the EDHOC Error Message is DIAG_MSG.
			        	String errMsg = objectList[0].toString();
			        	
			        	System.out.println("DIAG_MSG: " + errMsg + "\n");
			        			        	
			        	Util.purgeSession(session, CBORObject.FromObject(connectionId), edhocSessions, usedConnectionIds);
		        	
		        	}
		        	
					client.shutdown();
		    		return;
		        	
		        }

				// Send a request protected with the just established Security Context
		        if (POST_EDHOC_EXCHANGE) {
					client = new CoapClient(helloWorldURI);
					Request protectedRequest = Request.newGet();
					CoapResponse protectedResponse = null;
					protectedRequest.setType(Type.CON);
					protectedRequest.getOptions().setOscore(Bytes.EMPTY);
					try {
						protectedResponse = client.advanced(protectedRequest);
					} catch (ConnectorException e) {
						System.err.println("ConnectorException when sending a protected request\n");
					} catch (IOException e) {
						System.err.println("IOException when sending a protected request\n");
					}
					byte[] myPayload = protectedResponse.getPayload();
					if (myPayload != null) {
						System.out.println(Utils.prettyPrint(protectedResponse));
					}
		        }
				
			}

        }
        
		client.shutdown();
		
	}
	
	/*
	 * Process application data conveyed in AD_1 in EDHOC Message 1
	 */
	private static void processAD1(byte[] ad1) {
		// Do nothing
		System.out.println("Entered processAD1()");
	}
	
	/*
	 * Process application data conveyed in AD_2 in EDHOC Message 2
	 */
	private static void processAD2(byte[] ad2) {
		// Do nothing
		System.out.println("Entered processAD2()");
	}
	
	/*
	 * Process application data conveyed in AD_3 in EDHOC Message 3
	 */
	private static void processAD3(byte[] ad3) {
		// Do nothing
		System.out.println("Entered processAD3()");
	}
	
	/*
	 * Process a generic response received as reply to EDHOC Message 3
	 */
	private static void processResponseAfterEdhoc(CoapResponse msg) {
		// Do nothing
		System.out.println("ResponseAfterEdhoc()");
	}
	
}
