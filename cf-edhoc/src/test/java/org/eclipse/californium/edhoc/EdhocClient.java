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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
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
	
	// Uncomment to use an ECDSA key pair with curve P-256 as long-term identity key
    // private final static int keyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to use an EdDSA key pair with curve Ed25519 for signatures
    private final static int keyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Uncomment to use a Montgomery key pair with curve X25519
    // private final static int keyCurve = KeyKeys.OKP_X25519.AsInt32();
    
    // The ID_CRED used for the identity key of this peer
    private static CBORObject idCred = null;
    
    // The CRED used for the identity key of this peer
    private static byte[] cred = null;
    
    // The subject name used for the identity key of this peer
    private static String subjectName = "myClient";
    
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
	// The map label is C_X, i.e. the connection identifier offered to the other peer in the session, as plain bytes
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
		
	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
		}
	};

	/*
	 * Application entry point.
	 * 
	 */
	public static void main(String args[]) {
		String defaultUri = "coap://localhost/helloWorld";
		String edhocURI = "coap://localhost/.well-known/edhoc";

		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		NetworkConfig.setStandard(config);

		// Use to dynamically generate a key pair
		// keyPair = Util.generateKeyPair(keyCurve);
		Util.generateKeyPair(keyCurve);
		
		// Use to set up hardcoded keys for this peer and the other peer 
		setupIdentityKeys();
				
		// Add the supported ciphersuites
		setupSupportedCipherSuites();
		
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
 			
 			
 			/*
 			keyPairBase64 = "pAEBIAQhWCBKnDup/RNKUlI34RpV7oL66uUv4YLJHQ7C9siQGCjQCCNYID6bhr0M9aXL8O3ZDN+CneyWdYrrU7J2jKCcQAm9C9Jn";
 			peerPublicKeyBase64 = "owEBIAQhWCDmEXBYPmWt3xrRPNr9UMnyDgErwLV+j4uDy3G05//INA==";
 			*/
 			
 		}
		
		try {
			Provider EdDSA = new EdDSASecurityProvider();
			Security.insertProviderAt(EdDSA, 0);
			
			// Build the OneKey object for the identity key pair of this peer
			keyPair =  new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(keyPairBase64)));
			// Build the related ID_CRED
			byte[] idCredKid = new byte[] {(byte) 0x00}; // Use 0x00 as kid for this peer
			idCred = Util.buildIdCredKid(idCredKid);
			// Build the related CRED
			cred = Util.buildCredRawPublicKey(keyPair, "");
			
			// Build the OneKey object for the identity public key of the other peer
			OneKey peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(peerPublicKeyBase64)));
			// Build the related ID_CRED
			byte[] peerKid = new byte[] {(byte) 0x01}; // Use 0x01 as kid for the other peer
			CBORObject idCredPeer = Util.buildIdCredKid(peerKid);
			peerPublicKeys.put(idCredPeer, peerPublicKey);
			// Build the related CRED
			byte[] peerCred = Util.buildCredRawPublicKey(peerPublicKey, "");
			peerCredentials.put(idCredPeer, CBORObject.FromObject(peerCred));
			
		} catch (CoseException e) {
			System.err.println("Error while generating the key pair");
			return;
		}
		
	}
	
	private static void setupSupportedCipherSuites() {
		
		if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_2);
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_3);
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_0);
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_1);
		}
 		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32() || keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_0);
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_1);
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_2);
 			supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_3);
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
        
		EdhocSession mySession = MessageProcessor.createSessionAsInitiator
                (authenticationMethod, correlationMethod, keyPair, idCred, cred, subjectName, supportedCiphersuites, usedConnectionIds);
		
        byte[] nextPayload = MessageProcessor.writeMessage1(mySession, ad1);
        
		if (nextPayload == null || mySession.getCurrentStep() != Constants.EDHOC_BEFORE_M1) {
			System.err.println("Inconsistent state before sending EDHOC Message 1");
			return;
		}
		
		// Add the new session to the list of existing EDHOC sessions
		mySession.setMessage1(nextPayload);
		mySession.setCurrentStep(Constants.EDHOC_AFTER_M1);
		byte[] connectionId = mySession.getConnectionId();
		CBORObject bstrIdentifier = Util.encodeToBstrIdentifier(CBORObject.FromObject(connectionId));
		edhocSessions.put(CBORObject.FromObject(bstrIdentifier), mySession);
		
		Request edhocMessageReq = new Request(Code.POST, Type.CON);
		edhocMessageReq.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
		edhocMessageReq.setPayload(nextPayload);
		
        System.out.println("Sent EDHOC Message 1\n");
        Util.nicePrint("EDHOC message 1", nextPayload);
        
        CoapResponse edhocMessageResp;
        try {
        	edhocMessageResp = client.advanced(edhocMessageReq);
		} catch (ConnectorException e) {
			System.err.println("ConnectorException when sending EDHOC Message1");
			return;
		} catch (IOException e) {
			System.err.println("IOException when sending EDHOC Message1");
			return;
		}
		
        boolean discontinue = false;
        int responseType = -1;
        byte[] responsePayload = edhocMessageResp.getPayload();
        
        if (responsePayload == null)
        	discontinue = true;
        else {
        	responseType = MessageProcessor.messageType(responsePayload);
        	if (responseType != Constants.EDHOC_MESSAGE_2 && responseType != Constants.EDHOC_ERROR_MESSAGE)
        		discontinue = true;
        }
        if (discontinue == true) {
        	client.shutdown();
        	return;
        }
		
        String myString = (responseType == Constants.EDHOC_MESSAGE_2) ? "EDHOC Message 2" : "EDHOC Error Message";
		System.out.println("Determined EDHOC message type: " + myString + "\n");
        Util.nicePrint("EDHOC message " + responseType, responsePayload);
        
        
		/* Process the received response */
        
        // Since the Correlation Method 1 is used, this response relates to the previous request through the CoAP Token
        // Hence, the Initiator knows what session to refer to, from which the correct C_I can be retrieved
    	CBORObject connectionIdentifier = CBORObject.FromObject(mySession.getConnectionId());
    	CBORObject cI = Util.encodeToBstrIdentifier(connectionIdentifier);
        
    	nextPayload = new byte[] {};
    	
        // The received message is an EDHOC Error Message
        if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
        	
        	List<Integer> peerSupportedCiphersuites = new ArrayList<Integer>();
        	
        	CBORObject[] objectList = MessageProcessor.readErrorMessage(responsePayload, cI, edhocSessions);
        	
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
        	mySession.setPeerSupportedCipherSuites(peerSupportedCiphersuites);
        	
        	System.out.println("ERR_MSG: " + errMsg + "\n");
        	
        	// TODO - Send a new EDHOC Message 1, now knowing the ciphersuites supported by the Responder
        	
    		client.shutdown();
    		
        }
        
        // The received message is an EDHOC Message 2
        if (responseType == Constants.EDHOC_MESSAGE_2) {
        	
        	List<CBORObject> processingResult = new ArrayList<CBORObject>();
			
			// Possibly specify application data for AD_3, or null if none have to be provided
			byte[] ad3 = null;
			
			/* Start handling EDHOC Message 2 */
			
			processingResult = MessageProcessor.readMessage2(responsePayload, cI, edhocSessions, peerPublicKeys, peerCredentials);
			
			if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
				System.err.println("Internal error when processing EDHOC Message 2");
				return;
			}
			
			// Deliver AD_2 to the application
			if (processingResult.size() == 2) {
				processAD2(processingResult.get(1).GetByteString());
			}
			
			// A non-zero length response payload would be an EDHOC Error Message
			nextPayload = processingResult.get(0).GetByteString();

			// Prepare EDHOC Message 3
			if (nextPayload.length == 0) {
				
				mySession.setCurrentStep(Constants.EDHOC_AFTER_M2);
				
				nextPayload = MessageProcessor.writeMessage3(mySession, ad3);
		        
				if (nextPayload == null || mySession.getCurrentStep() != Constants.EDHOC_AFTER_M3) {
					System.err.println("Inconsistent state before sending EDHOC Message 3");
					return;
				}
				
			}

			int requestType = MessageProcessor.messageType(nextPayload);			
			if (requestType != Constants.EDHOC_MESSAGE_3 && responseType != Constants.EDHOC_ERROR_MESSAGE) {
				nextPayload = null;
			}
			
			if (nextPayload != null) {
				
				Request edhocMessageReq2 = new Request(Code.POST, Type.CON);
				edhocMessageReq2.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
				edhocMessageReq2.setPayload(nextPayload);
				
				myString = (requestType == Constants.EDHOC_MESSAGE_3) ? "EDHOC Message 3" : "EDHOC Error Message";
				System.out.println("Request type: " + myString + "\n");
				
				if (requestType == Constants.EDHOC_MESSAGE_3) {
			        
			        /* Invoke the EDHOC-Exporter to produce OSCORE input material */
			        byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(mySession);
			        byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(mySession);
			        if (debugPrint) {
			        	Util.nicePrint("OSCORE Master Secret", masterSecret);
			        	Util.nicePrint("OSCORE Master Salt", masterSalt);
			        }
			        
			        System.out.println("Sent EDHOC Message 3\n");
			        if (debugPrint) {
			        	Util.nicePrint("EDHOC Message 3", nextPayload);
			        }
				}
				else if (requestType == Constants.EDHOC_ERROR_MESSAGE) {
			        System.out.println("Sent EDHOC Error Message\n");
			        if (debugPrint) {
			        	Util.nicePrint("EDHOC Error Message", nextPayload);
			        }
				}
				
		        CoapResponse edhocMessageResp2;
		        
		        try {
		        	edhocMessageResp2 = client.advanced(edhocMessageReq2);
				} catch (ConnectorException e) {
					System.err.println("ConnectorException when sending " + myString + "\n");
					return;
				} catch (IOException e) {
					System.err.println("IOException when sending "  + myString + "\n");
					return;
				}
				
				// Wait for a possible Error Message as a response. For how long?
				
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
	
}
