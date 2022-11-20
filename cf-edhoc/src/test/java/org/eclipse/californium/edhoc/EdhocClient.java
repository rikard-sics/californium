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
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;

public class EdhocClient {
	
	private static final boolean debugPrint = true;
	
	private static final File CONFIG_FILE = new File("Californium.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Fileclient";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 2 * 1024 * 1024; // 2 MB

	private static final int DEFAULT_BLOCK_SIZE = 512;
	
	private final static Provider EdDSA = new EdDSASecurityProvider();
		
	
	// Set to True if this CoAP client is the EDHOC initiator (only flow available at the moment)
	// Relevant to choose with public keys to install, when testing with selected cipher suite 0 or 1
	private final static boolean isInitiator = true;
	
	// Set to true if an OSCORE-protected exchange is performed after EDHOC completion
	private static final boolean POST_EDHOC_EXCHANGE = false;

	// Set to true if EDHOC message_3 will be combined with the first OSCORE request
	// Note: the application profile pertaining the EDHOC resource must first indicate support for the combined request 
	private static final boolean OSCORE_EDHOC_COMBINED = false;
	
	// The authentication method to include in EDHOC message_1 (relevant only when Initiator)
	private static int authenticationMethod = Constants.EDHOC_AUTH_METHOD_0;
	
    // The type of the authentication credential of this peer (same type for all its credentials)
    // Possible values: CRED_TYPE_CWT ; CRED_TYPE_CCS ; CRED_TYPE_X509
    private static int credType = Constants.CRED_TYPE_X509;
    
    // The type of the credential identifier of this peer (same type for all its credentials)
    // This will be the type of ID_CRED_R used in EDHOC message_2 or as ID_CRED_I in EDHOC message_3.
    // Possible values: ID_CRED_TYPE_KID ; ID_CRED_TYPE_CWT ; ID_CRED_TYPE_CCS ;
    //                  ID_CRED_TYPE_X5T ; ID_CRED_TYPE_X5U ; ID_CRED_TYPE_X5CHAIN
    private static int idCredType = Constants.ID_CRED_TYPE_X5T;

    // The trust model used to validate authentication credentials of other peers
    private static int trustModel = Constants.TRUST_MODEL_STRICT;
    
    // Authentication credentials of this peer
    //
    // At the top level, authentication credentials are sorted by key usage of the authentication keys.
    // The outer map has label SIGNATURE_KEY or ECDH_KEY for distinguishing the two key usages. 
    //
    // The asymmetric key pairs of this peer (one per supported curve)
	private static HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
    
    // The identifiers of the authentication credentials of this peer
	private static HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
    
    // The authentication credentials of this peer (one per supported curve)
	private static HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
    
	// Each element is the ID_CRED_X used for an authentication credential associated to this peer
	private static Set<CBORObject> ownIdCreds = new HashSet<>();
	
	
    // Authentication credentials of the other peers
	// 
	// The map label is a CBOR Map used as ID_CRED_X
	private static HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
	
	// Authentication credentials of other peers
	// 
	// The map label is a CBOR Map used as ID_CRED_X
	// The map value is a CBOR Byte String, with value the serialization of CRED_X
	private static HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
		
	// Existing EDHOC Sessions, including completed ones
	// The map label is C_X, i.e. the connection identifier offered to the other peer, as a CBOR integer or byte string
	private static HashMap<CBORObject, EdhocSession> edhocSessions = new HashMap<CBORObject, EdhocSession>();
	
	// Each element is a used Connection Identifier offered to the other peers.
	// Connection Identifiers are stored as CBOR integers (if numeric) or as CBOR byte strings (if binary)
	private static Set<CBORObject> usedConnectionIds = new HashSet<>();
	
	// List of supported cipher suites, in decreasing order of preference.
	private static List<Integer> supportedCipherSuites = new ArrayList<Integer>();
	
	// Set of supported EAD items, identified by their EAD label
	private static Set<Integer> supportedEADs = new HashSet<>();
	
	// The collection of application profiles - The lookup key is the full URI of the EDHOC resource
	private static HashMap<String, AppProfile> appProfiles = new HashMap<String, AppProfile>();
	
	// The database of OSCORE Security Contexts
	private final static HashMapCtxDB db = new HashMapCtxDB();
	
	// The size of the Replay Window to use in an OSCORE Recipient Context
	private static final int OSCORE_REPLAY_WINDOW = 32;
	
	// The size to consider for MAX_UNFRAGMENTED SIZE
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;
	
	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MULTICAST_BASE_MID, 65000);
			
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
		}

	};
	
	private static String helloWorldURI = "coap://localhost/helloWorld";
	
	private static String edhocURI = "coap://localhost/.well-known/edhoc";
	
	// private static String edhocURI = "coap://31.133.138.127/.well-known/edhoc";
	// private static String edhocURI = "coap://31.133.130.112/.well-known/edhoc";
	// private static String edhocURI = "coap://51.75.194.248/.well-known/edhoc"; // Timothy
	// private static String edhocURI = "coap://54.93.59.163/.well-known/edhoc"; // Stefan
	// private static String edhocURI = "coap://195.251.58.203:5683/.well-known/edhoc"; // Lidia
	// private static String edhocURI = "coap://hephaistos.proxy.rd.coap.amsuess.com:1234/.well-known/edhoc"; // Christian
	
	
	/*
	 * Application entry point.
	 * 
	 */
	public static void main(String args[]) {
		String defaultUri = "coap://localhost/helloWorld";
				
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		Configuration.setStandard(config);

		// Insert EdDSA security provider
		Security.insertProviderAt(EdDSA, 1);

		// Enable EDHOC stack with EDHOC and OSCORE layers
		EdhocCoapStackFactory.useAsDefault(db, edhocSessions, peerPublicKeys, peerCredentials,
				                           usedConnectionIds, OSCORE_REPLAY_WINDOW, MAX_UNFRAGMENTED_SIZE);

		// Use to dynamically generate a key pair
		// keyPair = Util.generateKeyPair(keyCurve);
		
		// Add the supported cipher suites
		setupSupportedCipherSuites();

		// Add the supported EAD items
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
		
		appProfiles.put(edhocURI, appProfile);
		
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
		
		// Specify the processor of External Authorization Data
		KissEDP edp = new KissEDP();
		
		// Prepare the set of information for this EDHOC endpoint
		EdhocEndpointInfo edhocEndpointInfo = new EdhocEndpointInfo(idCreds, creds, keyPairs, peerPublicKeys,
																	peerCredentials, edhocSessions, usedConnectionIds,
																	supportedCipherSuites, supportedEADs, trustModel, db,
																	edhocURI, OSCORE_REPLAY_WINDOW, MAX_UNFRAGMENTED_SIZE,
																	appProfiles, edp);
		
		// Possibly specify external authorization data for EAD_1, or null if none has to be provided
		// The EAD is structured in pairs of CBOR items (int, any), i.e. the EAD Label first and then the EAD Value 
		CBORObject[] ead1 = null;
		
		edhocExchangeAsInitiator(args, uri, ownIdCreds, edhocEndpointInfo, ead1);

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
	
	private static void edhocExchangeAsInitiator(final String args[], final URI targetUri, Set<CBORObject> ownIdCreds,
												 EdhocEndpointInfo edhocEndpointInfo, CBORObject[] ead1) {
		
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

		String uriAsString = targetUri.toString();
		AppProfile appProfile = edhocEndpointInfo.getAppProfiles().get(uriAsString);
		
		EdhocSession session = MessageProcessor.createSessionAsInitiator(authenticationMethod,
																		 edhocEndpointInfo.getKeyPairs(),
																		 edhocEndpointInfo.getIdCreds(),
																		 edhocEndpointInfo.getCreds(),
                 														 edhocEndpointInfo.getSupportedCipherSuites(),
                 														 edhocEndpointInfo.getSupportedEADs(),
                 														 edhocEndpointInfo.getUsedConnectionIds(),
                 														 appProfile, edhocEndpointInfo.getTrustModel(),
                 														 edhocEndpointInfo.getEdp(), db);
		
		// At this point, the initiator may overwrite the information in the EDHOC session about the supported cipher suites
		// and the selected cipher suite, based on a previously received EDHOC Error Message
		
        byte[] nextPayload = MessageProcessor.writeMessage1(session, ead1);
        
		if (nextPayload == null || session.getCurrentStep() != Constants.EDHOC_BEFORE_M1) {
			System.err.println("Inconsistent state before sending EDHOC Message 1");
			session.deleteTemporaryMaterial();
			session = null;
			client.shutdown();
			return;
		}
		
		// Add the new session to the list of existing EDHOC sessions
		session.setCurrentStep(Constants.EDHOC_AFTER_M1);
		
		// Compute and store the hash of EDHOC Message 1
		// The first byte 0xf5 sent in the CoAP request must be skipped
		byte[] hashInput = new byte[nextPayload.length - 1];
		System.arraycopy(nextPayload, 1, hashInput, 0, hashInput.length);
		session.setHashMessage1(hashInput);
		
		byte[] connectionIdentifier = session.getConnectionId();
		CBORObject connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
		edhocSessions.put(connectionIdentifierCbor, session);
		
		Request edhocMessageReq = new Request(Code.POST, Type.CON);
		edhocMessageReq.getOptions().setContentFormat(Constants.APPLICATION_CID_EDHOC_CBOR_SEQ);
		edhocMessageReq.setPayload(nextPayload);
		
        System.out.println("Sent EDHOC Message 1\n");
        
        CoapResponse edhocMessageResp;
        try {
        	session.setCurrentStep(Constants.EDHOC_SENT_M1);
        	edhocMessageResp = client.advanced(edhocMessageReq);
		} catch (ConnectorException e) {
			System.err.println("ConnectorException when sending EDHOC Message 1");
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			client.shutdown();
			return;
		} catch (IOException e) {
			System.err.println("IOException when sending EDHOC Message 1");
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			client.shutdown();
			return;
		}
        
        boolean discontinue = false;
        int responseType = -1;
        byte[] responsePayload = null; 
        		
        if (edhocMessageResp != null)
        	responsePayload = edhocMessageResp.getPayload();
        
        if (responsePayload == null)
        	discontinue = true;
        else {
        	responseType = MessageProcessor.messageType(responsePayload, false, edhocSessions, connectionIdentifier);
        	if (responseType != Constants.EDHOC_MESSAGE_2 && responseType != Constants.EDHOC_ERROR_MESSAGE)
        		discontinue = true;
        }
        if (discontinue == true) {
        	System.err.println("Received invalid reply to EDHOC Message 1");
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
        	client.shutdown();
        	return;
        }
		
        String myString = (responseType == Constants.EDHOC_MESSAGE_2) ? "EDHOC Message 2" : "EDHOC Error Message";
		System.out.println("Determined EDHOC message type: " + myString + "\n");
        Util.nicePrint("EDHOC message " + responseType, responsePayload);
        
        
		/* Process the received response */
        
        // This response relates to the previous request through the CoAP Token.
        // Hence, the Initiator knows what session to refer to, from which the correct C_I can be retrieved
 
    	nextPayload = new byte[] {};
    	
        // The received message is an EDHOC Error Message
        if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
        	
        	List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
        	
        	CBORObject[] objectList = MessageProcessor.readErrorMessage(responsePayload, connectionIdentifier, edhocSessions);
        	
        	if (objectList != null) {
        	
		    	// This execution flow has the client as Initiator.
		    	// Hence, there is no C_I included, and the first element of the EDHOC Error Message is ERR_CODE.
        		
        		// Retrieve ERR_CODE
        		int errorCode = objectList[0].AsInt32();
        		System.out.println("ERR_CODE: " + errorCode + "\n");

        		// Retrieve ERR_INFO
        		if (errorCode == Constants.ERR_CODE_SUCCESS) {
        		    System.out.println("Success\n");
        		}
        		else if (errorCode == Constants.ERR_CODE_UNSPECIFIED_ERROR) {
        		    String errMsg = objectList[1].toString();
        		    System.out.println("ERR_INFO: " + errMsg + "\n");
        		}
        		else if (errorCode == Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
        		    CBORObject suitesR = objectList[1];
        		    if (suitesR.getType() == CBORType.Integer) {
        		    	int suite = suitesR.AsInt32();
    		    		peerSupportedCipherSuites.add(Integer.valueOf(suite));
    		    		session.setPeerSupportedCipherSuites(peerSupportedCipherSuites);
        		        System.out.println("SUITES_R: " + suitesR.AsInt32() + "\n");
        		    }
        		    else if (suitesR.getType() == CBORType.Array) {
        		        System.out.print("SUITES_R: [ " );
        		        for (int i = 0; i < suitesR.size(); i++) {
        		        	int suite = suitesR.get(i).AsInt32();
    		        		peerSupportedCipherSuites.add(Integer.valueOf(suite));
        		            System.out.print(suitesR.get(i).AsInt32() + " " );
        		        }
        		        System.out.println("]\n");
        		        session.setPeerSupportedCipherSuites(peerSupportedCipherSuites);
        		    }
        		}
		    	
		    	// The following simply deletes the EDHOC session. However, it would be fine to prepare a new
		    	// EDHOC Message 1 right away, keeping the same Connection Identifier C_I and this same session.
		    	// In fact, the session is marked as "used", hence new ephemeral keys would be generated when
		    	// preparing a new EDHOC Message 1.        	
		    	
		    	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
		    	
        	}
        	
			client.shutdown();
    		return;
    		
        }
        
        // The received message is an EDHOC Message 2
        if (responseType == Constants.EDHOC_MESSAGE_2) {
        	
        	List<CBORObject> processingResult = new ArrayList<CBORObject>();
			
        	// Possibly specify external authorization data for EAD_3, or null if none has to be provided
        	// The EAD is structured in pairs of CBOR items (int, any), i.e. the EAD Label first and then the EAD Value
			CBORObject[] ead3 = null;
			
			/* Start handling EDHOC Message 2 */
			
			processingResult = MessageProcessor.readMessage2(responsePayload, false, connectionIdentifier, edhocSessions,
															 peerPublicKeys, peerCredentials, usedConnectionIds, ownIdCreds);
			
			if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
				System.err.println("Internal error when processing EDHOC Message 2");
				Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
				client.shutdown();
				return;
			}
			
			// A non-zero length response payload would be an EDHOC Error Message
			nextPayload = processingResult.get(0).GetByteString();

			// Prepare EDHOC Message 3
			if (nextPayload.length == 0) {
				
				// Deliver EAD_2 to the application, if present
				if (processingResult.size() == 2 && processingResult.get(1).getType() == CBORType.Array) {
				    // This inspected element of 'processing_result' should really be a CBOR Array at this point
				    int length = processingResult.get(1).size();
				    CBORObject[] ead2 = new CBORObject[length];
				    for (int i = 0; i < length; i++) {
				        ead2[i] = processingResult.get(1).get(i);
				    }
				    edhocEndpointInfo.getEdp().processEAD2(ead2);
				}
				
				session.setCurrentStep(Constants.EDHOC_AFTER_M2);
				
				nextPayload = MessageProcessor.writeMessage3(session, ead3);
		        
				if (nextPayload == null || session.getCurrentStep() != Constants.EDHOC_AFTER_M3) {
					System.err.println("Inconsistent state before sending EDHOC Message 3");
					Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
					client.shutdown();
					return;
				}
				
			}

			int requestType = MessageProcessor.messageType(nextPayload, true, edhocSessions, connectionIdentifier);
			
			if (requestType != Constants.EDHOC_MESSAGE_3 && requestType != Constants.EDHOC_ERROR_MESSAGE) {
				nextPayload = null;
			}
			
			if (nextPayload != null) {
				myString = (requestType == Constants.EDHOC_MESSAGE_3) ? "EDHOC Message 3" : "EDHOC Error Message";
				
				if (requestType == Constants.EDHOC_MESSAGE_3) {
			        
			        System.out.println("Sent EDHOC Message 3\n");
					
			        if (session.getApplicationProfile().getUsedForOSCORE() == true) {
			        
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
				        
				        int selectedCipherSuite = session.getSelectedCipherSuite();
				        AlgorithmID alg = EdhocSession.getAppAEAD(selectedCipherSuite);
				        AlgorithmID hkdf = EdhocSession.getAppHkdf(selectedCipherSuite);
				        
				        OSCoreCtx ctx = null;
				        byte[] recipientId = connectionIdentifier;
				        if (Arrays.equals(senderId, recipientId)) {
							System.err.println("Error: the Sender ID coincides with the Recipient ID " +
												Utils.toHexString(senderId));
							Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
							client.shutdown();
							return;
				        }
				        try {
							
							ctx = new OSCoreCtx(masterSecret, true, alg, senderId, recipientId, hkdf,
									            OSCORE_REPLAY_WINDOW, masterSalt, null, MAX_UNFRAGMENTED_SIZE);
							
						} catch (OSException e) {
							System.err.println("Error when deriving the OSCORE Security Context "
						                        + e.getMessage());
							Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
							client.shutdown();
							return;
						}
				        
				        try {
							db.addContext(edhocURI, ctx);
						} catch (OSException e) {
							System.err.println("Error when adding the OSCORE Security Context to the context database "
						                        + e.getMessage());
							Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
							client.shutdown();
							return;
						}
			        
			        }
			        
				}
				else if (requestType == Constants.EDHOC_ERROR_MESSAGE) {
					
					// If the Error Message was generated while reading EDHOC Message 2,
					// deliver EAD_2 to the application, if any was present in EDHOC Message 2
					if (processingResult.size() == 3 && processingResult.get(2).getType() == CBORType.Array) {
					    // This inspected element of 'processing_result' should really be a CBOR Array at this point
					    int length = processingResult.get(2).size();
					    CBORObject[] ead2 = new CBORObject[length];
					    for (int i = 0; i < length; i++) {
					        ead2[i] = processingResult.get(2).get(i);
					    }
					    edhocEndpointInfo.getEdp().processEAD2(ead2);
					}
					
				    Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			        System.out.println("Sent EDHOC Error Message\n");
			        if (debugPrint) {
			        	Util.nicePrint("EDHOC Error Message", nextPayload);
			        }
			        
				}
				
		        CoapResponse edhocMessageResp2 = null;
		        
		        try {
					Request edhocMessageReq2 = new Request(Code.POST, Type.CON);
					edhocMessageReq2.setPayload(nextPayload);
					
		        	// If EDHOC message_3 has to be combined with the first
		        	// OSCORE-protected request include the EDHOC option in the request
		        	if (OSCORE_EDHOC_COMBINED == true && requestType == Constants.EDHOC_MESSAGE_3 &&
		        		session.getApplicationProfile().getUsedForOSCORE() == true &&
		        		session.getApplicationProfile().getSupportCombinedRequest() == true) {
		        		
		        		// The combined request cannot be used if the Responder has to send message_4
		        		if (session.getApplicationProfile().getUseMessage4() == true) {
							System.err.println("Cannot send the combined EDHOC+OSCORE request if message_4 is expected\n");
			    			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			            	client.shutdown();
			            	return;
		        		}
		        		
						client = new CoapClient(helloWorldURI);
						CoapResponse protectedResponse = null;
						edhocMessageReq2 = Request.newGet();
						edhocMessageReq2.setType(Type.CON);
						edhocMessageReq2.getOptions().setOscore(Bytes.EMPTY);
						
		        		edhocMessageReq2.getOptions().setEdhoc(true);
						session.setMessage3(nextPayload);
						
						try {
							session.setCurrentStep(Constants.EDHOC_SENT_M3);
							protectedResponse = client.advanced(edhocMessageReq2);
						} catch (ConnectorException e) {
							System.err.println("ConnectorException when sending a protected request\n");
			    			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			            	client.shutdown();
			            	return;
						} catch (IOException e) {
							System.err.println("IOException when sending a protected request\n");
			    			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			            	client.shutdown();
			            	return;
						}
					
						byte[] myPayload = null;
						if (protectedResponse != null)
							myPayload = protectedResponse.getPayload();
						if (myPayload != null) {
							System.out.println(Utils.prettyPrint(protectedResponse));
							
							int contentFormat = protectedResponse.getOptions().getContentFormat();
							int restCode = protectedResponse.getCode().value;
							
							// Check if it is an EDHOC Error Message returned by the server
							// when processing the combined EDHOC + OSCORE request
			            	if (contentFormat == Constants.APPLICATION_EDHOC_CBOR_SEQ &&
			            	      ((restCode == ResponseCode.BAD_REQUEST.value) ||
			            	       (restCode == ResponseCode.INTERNAL_SERVER_ERROR.value)) ) {
			            	
				            	responseType = MessageProcessor.messageType(myPayload, false,
		                                                                    edhocSessions, connectionIdentifier);
			            		
				            	if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
				            		
				            		System.err.println("Received an EDHOC Error Message");
						        	CBORObject[] objectList = MessageProcessor.readErrorMessage(myPayload,
						        																connectionIdentifier,
						        																edhocSessions);
						        	processErrorMessageAsResponse(objectList, connectionIdentifier);
				            		
				            	}
			            	
							}
			            	
						}
						
						session.cleanMessage3();
						
		        	}
		        	else {
		        		
		        		if (requestType == Constants.EDHOC_ERROR_MESSAGE) {
			        		// The request to send is an EDHOC Error Message
		        			edhocMessageReq2.setConfirmable(true);
		        			edhocMessageReq2.setURI(targetUri);
		        			edhocMessageReq2.send();
		        			client.shutdown();
							return;
		        		}
		        		
		        		session.setCurrentStep(Constants.EDHOC_SENT_M3);
		        		edhocMessageReq2.getOptions().setContentFormat(Constants.APPLICATION_CID_EDHOC_CBOR_SEQ);
		        		edhocMessageResp2 = client.advanced(edhocMessageReq2);
		        		
		        	}
		        	
				} catch (ConnectorException e) {
					System.err.println("ConnectorException when sending " + myString + "\n");
					Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
					client.shutdown();
					return;
				} catch (IOException e) {
					System.err.println("IOException when sending "  + myString + "\n");
					Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
					client.shutdown();
					return;
				}
				
				// Wait for a possible response. For how long?
		        
		        // Only an EDHOC message_4 or an EDHOC Error Message is a legitimate EDHOC message at this point
		        if (edhocMessageResp2 != null) {

		        	responseType = -1;
		        	responsePayload = null;
		        	boolean expectMessage4 = session.getApplicationProfile().getUseMessage4();
		        	
		        	if (edhocMessageResp2 != null)
		        		responsePayload = edhocMessageResp2.getPayload();
		            
		            if (responsePayload == null)
		            	discontinue = true;
		            else {
		            	responseType = MessageProcessor.messageType(responsePayload, false, edhocSessions, connectionIdentifier);
		            	
		            	// It is always consistent to receive an Error Message
		            	if (responseType != Constants.EDHOC_ERROR_MESSAGE) {
		            		
		            		if (responseType == Constants.EDHOC_MESSAGE_4) {
		            			if (expectMessage4 == false)
		            				discontinue = true;
		            			// Else it is fine, i.e., it is message_4 and it is expected
		            		}
		            		else {
		            			// Any other message than message_4 and Error Message
		            			if (expectMessage4 == true) {
					            	System.err.println("Received invalid reply to EDHOC Message 3 while expecting Message 4");
					            	System.err.println("responseType: " + responseType);
			            			discontinue = true;
		            			}
		            			else {
		            				// This is a generic response received as reply to EDHOC Message 3
		        		        	processResponseAfterEdhoc(edhocMessageResp2);
		            			}
		            		}
		            		
		            	}
		            	// It is an EDHOC Error Message
		            	else {
		            		System.err.println("Received an EDHOC Error Message");
				        	CBORObject[] objectList = MessageProcessor.readErrorMessage(responsePayload,
				        																connectionIdentifier,
				        																edhocSessions);
				        	processErrorMessageAsResponse(objectList, connectionIdentifier);
				        	discontinue = true;
		            	}

		            }
		            if (discontinue == true) {
		    			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
		            	client.shutdown();
		            	return;
		            }
		    		
					myString = (responseType == Constants.EDHOC_MESSAGE_4) ? "EDHOC Message 4" : "EDHOC Error Message";
		            
					String typeName = "";
					switch (responseType) {
						case Constants.EDHOC_ERROR_MESSAGE:
							typeName = new String("EDHOC Error Message");
							break;
						case Constants.EDHOC_MESSAGE_1:
						case Constants.EDHOC_MESSAGE_2:
						case Constants.EDHOC_MESSAGE_3:
						case Constants.EDHOC_MESSAGE_4:
							typeName = new String("EDHOC Message " + responseType);
							break;		
					}
					if (responseType != -1) {
			    		System.out.println("Determined EDHOC message type: " + typeName + "\n");
			            Util.nicePrint(typeName, responsePayload);
					}
		            
		            
		            if (responseType == Constants.EDHOC_MESSAGE_4) {
		            	processingResult = MessageProcessor.readMessage4(responsePayload, false, connectionIdentifier,
		            			                                         edhocSessions, usedConnectionIds);
		            	
						if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
							System.err.println("Internal error when processing EDHOC Message 4");
							Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			            	client.shutdown();
			            	return;
						}
						
						// A non-zero length response payload would be an EDHOC Error Message
						byte[] nextMessage = processingResult.get(0).GetByteString();
						
						// The EDHOC message_4 was successfully processed
						if (nextMessage.length == 0) {
							
							// Deliver EAD_4 to the application, if present
							if (processingResult.size() == 2 && processingResult.get(1).getType() == CBORType.Array) {
							    // This inspected element of 'processing_result' should really be a CBOR Array at this point
							    int length = processingResult.get(1).size();
							    CBORObject[] ead4 = new CBORObject[length];
							    for (int i = 0; i < length; i++) {
							        ead4[i] = processingResult.get(1).get(i);
							    }
							    edhocEndpointInfo.getEdp().processEAD4(ead4);
							}
							
							// If message_4 was a Confirmable response, send an empty ACK
							
					        if (edhocMessageResp2.advanced().isConfirmable()) {
					        	edhocMessageResp2.advanced().acknowledge();
					        }
							
						}
						// An EDHOC error message has to be returned in response to EDHOC message_4
						else {
							
							// Deliver EAD_4 to the application, if any was present in EDHOC Message 4
							if (processingResult.size() == 3 && processingResult.get(2).getType() == CBORType.Array) {
							    // This inspected element of 'processing_result' should really be a CBOR Array at this point
							    int length = processingResult.get(2).size();
							    CBORObject[] ead4 = new CBORObject[length];
							    for (int i = 0; i < length; i++) {
							        ead4[i] = processingResult.get(2).get(i);
							    }
							    edhocEndpointInfo.getEdp().processEAD4(ead4);
							}
							
							Request edhocMessageReq3 = new Request(Code.POST, Type.CON);
							edhocMessageReq3.setPayload(nextMessage);
							
					        try {
					        	edhocMessageResp = client.advanced(edhocMessageReq3);
							} catch (ConnectorException e) {
								System.err.println("ConnectorException when sending EDHOC Error Message");
								Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
								client.shutdown();
								return;
							} catch (IOException e) {
								System.err.println("IOException when sending EDHOC Error Message");
								Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
								client.shutdown();
								return;
							}
						}
		            	
		            }
		            else if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
		            	System.err.println("Received an EDHOC Error Message");
			        	CBORObject[] objectList = MessageProcessor.readErrorMessage(responsePayload,
			        																connectionIdentifier,
			        																edhocSessions);
			        	
			        	processErrorMessageAsResponse(objectList, connectionIdentifier);
			        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			        	
						client.shutdown();
			    		return;
		    		
		            }
		    		
		        }

				// Send a request protected with the just established Security Context
		        boolean usedForOSCORE = session.getApplicationProfile().getUsedForOSCORE();
		        if (POST_EDHOC_EXCHANGE && usedForOSCORE == true) {
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
					byte[] myPayload = null;
					if (protectedResponse != null)
						myPayload = protectedResponse.getPayload();
					if (myPayload != null) {
						System.out.println(Utils.prettyPrint(protectedResponse));
					}
		        }
				
			}

        }
        
		client.shutdown();
		
	}
	
	/*
	 * Process a generic response received as reply to EDHOC Message 3
	 */
	private static void processResponseAfterEdhoc(CoapResponse msg) {
		// Do nothing
		System.out.println("ResponseAfterEdhoc()");
	}
	
	/*
	 * Process an EDHOC Error Message as a CoAP response
	 */
	private static void processErrorMessageAsResponse(CBORObject[] objectList, byte[] connectionIdentifier) {
		
    	if (objectList != null) {
    		
    		int index = 0;
    		
        	// Retrieve ERR_CODE
        	int errorCode = objectList[index].AsInt32();
        	index++;
        	System.out.println("ERR_CODE: " + errorCode + "\n");
        	
        	// Retrieve ERR_INFO
    		if (errorCode == Constants.ERR_CODE_SUCCESS) {
    			System.out.println("Success\n");
    		}
    		else if (errorCode == Constants.ERR_CODE_UNSPECIFIED_ERROR) {
	        	String errMsg = objectList[index].toString();
	        	System.out.println("DIAG_MSG: " + errMsg + "\n");
    		}
    		else if (errorCode == Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
    			CBORObject suitesR = objectList[index];
				if (suitesR.getType() == CBORType.Integer) {
		        	System.out.println("SUITES_R: " + suitesR.AsInt32() + "\n");
				}
				else if (suitesR.getType() == CBORType.Array) {
					System.out.print("SUITES_R: [ " );
					for (int i = 0; i < suitesR.size(); i++) {
						System.out.print(suitesR.get(i).AsInt32() + " " );
					}
					System.out.println("]\n");
				}
    		}
    		
    		if (connectionIdentifier == null) {
    			System.err.println("Unavailable connection identifier to delete EDHOC session");
    			return;
    		}
    	
    		CBORObject connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
    		EdhocSession session = edhocSessions.get(connectionIdentifierCbor);
    		if (session == null) {
    			System.err.println("EDHOC session to delete not found");
    			return;
    		}
    	
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
    	}
		
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
			
			// If the type of credential identifier is 'kid', use 0x00,
			// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x00
			byte[] kidEd25519 = new byte[] {(byte) 0x00};
			
			// Build the key pair
			
 			privateKeyBinary = StringUtil.hex2ByteArray("2ffce7a0b2b825d397d0cb54f746e3da3f27596ee06b5371481dc0e012bc34d7");
			publicKeyBinary = StringUtil.hex2ByteArray("38e5d54563c2b6a4ba26f3015f61bb706e5c2efdb556d2e1690b97fc3c6de149");
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
		        credEd25519 = StringUtil.hex2ByteArray("A2026008A101A40101024100200621582038E5D54563C2B6A4BA26F3015F61BB706E5C2EFDB556D2E1690B97FC3C6DE149");
		        break;
		    case Constants.CRED_TYPE_X509:
		        // The x509 certificate of this peer
		    	serializedCert = StringUtil.hex2ByteArray("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda6");
		        
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
				idCredEd25519 = Util.buildIdCredX5u("http://example.repo.com/hostA-x509-Ed25519");
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
			
			// If the type of credential identifier is 'kid', use 0x01,
			// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x01
			byte[] kidX25519 = new byte[] {(byte) 0x01};
			
			// Build the key pair
			
			privateKeyBinary = StringUtil.hex2ByteArray("2bbea655c23371c329cfbd3b1f02c6c062033837b8b59099a4436f666081b08e");
			publicKeyBinary = StringUtil.hex2ByteArray("2c440cc121f8d7f24c3b0e41aedafe9caa4f4e7abb835ec30f1de88adb96ff71");
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
	            credX25519 = StringUtil.hex2ByteArray("A2026008A101A4010102410120042158202C440CC121F8D7F24C3B0E41AEDAFE9CAA4F4E7ABB835EC30F1DE88ADB96FF71");
		        break;
		    case Constants.CRED_TYPE_X509:
		        // The x509 certificate of this peer
		    	serializedCert = StringUtil.hex2ByteArray("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda7");
		        
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
				idCredX25519 = Util.buildIdCredX5u("http://example.repo.com/hostA-x509-X25519");
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
			
			// If the type of credential identifier is 'kid', use 0x02,
			// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x02
			byte[] kidP256 = new byte[] {(byte) 0x02};
			
			// Build the key pair
			
			privateKeyBinary = StringUtil.hex2ByteArray("04f347f2bead699adb247344f347f2bdac93c7f2bead6a9d2a9b24754a1e2b62");
			publicKeyBinary = StringUtil.hex2ByteArray("cd4177ba62433375ede279b5e18e8b91bc3ed8f1e174474a26fc0edb44ea5373");
			publicKeyBinaryY = StringUtil.hex2ByteArray("A0391DE29C5C5BADDA610D4E301EAAA18422367722289CD18CBE6624E89B9CFD");
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
	            credP256 = StringUtil.hex2ByteArray("A2026008A101A501020241022001215820CD4177BA62433375EDE279B5E18E8B91BC3ED8F1E174474A26FC0EDB44EA5373225820A0391DE29C5C5BADDA610D4E301EAAA18422367722289CD18CBE6624E89B9CFD");
		        break;
		    case Constants.CRED_TYPE_X509:
		        // The x509 certificate of this peer
		    	serializedCert = StringUtil.hex2ByteArray("5413204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda8");
		        
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
				idCredP256 = Util.buildIdCredX5u("http://example.repo.com/hostA-x509-P256-signing");
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
			
			// If the type of credential identifier is 'kid', use 0x03,
			// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x03
			byte[] kidP256dh = new byte[] {(byte) 0x03};
			
			// Build the key pair
			
			privateKeyBinary = StringUtil.hex2ByteArray("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b");
			publicKeyBinary = StringUtil.hex2ByteArray("ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6");
			publicKeyBinaryY = StringUtil.hex2ByteArray("6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8");
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
	            credP256dh = StringUtil.hex2ByteArray("A2026008A101A501020241032001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8");
		        break;
		    case Constants.CRED_TYPE_X509:
		        // The x509 certificate of this peer
		    	serializedCert = StringUtil.hex2ByteArray("7713204c3ebc3428a6cf57e24c9def59651770449bce7ec6561e52433aa55e71f1fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda8");
		        
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
				idCredP256dh = Util.buildIdCredX5u("http://example.repo.com/hostA-x509-P256-dh");
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
	    
		// If the type of credential identifier is 'kid', use 0x07,
		// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x07
		byte[] peer1KidEd25519 = new byte[] {(byte) 0x07};
		
		
		// Build the public key
		
		peerPublicKeyBinary = StringUtil.hex2ByteArray("dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2");
		peer1PublicKeyEd25519 =  SharedSecretCalculation.buildEd25519OneKey(null, peerPublicKeyBinary);
		
		
		// Build CRED as a CCS, and the corresponding ID_CRED as 'kccs' and 'kid'
		
		System.out.print("Peer ");
		CBORObject peer1KidCborEd25519 = CBORObject.FromObject(peer1KidEd25519);
		peer1CcsObjectEd25519 = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(peer1PublicKeyEd25519, peerSubjectName, peer1KidCborEd25519));
		
		// These serializations have to be prepared manually, in order to ensure that
		// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
		peerCred = StringUtil.hex2ByteArray("a2026008a101a401010241072006215820dbd9dc8cd03fb7c3913511462bb23816477c6bd8d66ef5a1a070ac854ed73fd2");
 		
		peer1IdCredEd25519kccs = Util.buildIdCredKccs(peer1CcsObjectEd25519); // ID_CRED as 'kccs'
		peer1IdCredEd25519kid = Util.buildIdCredKid(peer1KidEd25519); // ID_CRED as 'kid'
		
		peerPublicKeys.put(peer1IdCredEd25519kccs, peer1PublicKeyEd25519);
		peerCredentials.put(peer1IdCredEd25519kccs, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredEd25519kid, peer1PublicKeyEd25519);
		peerCredentials.put(peer1IdCredEd25519kid, CBORObject.FromObject(peerCred));
		
		
		// Build CRED as an X.509 certificate, and the corresponding ID_CRED as 'x5chain', 'x5t' and 'x5u'
		peerSerializedCert = StringUtil.hex2ByteArray("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb2");
		
		// Test with Peter (real DER certificate for the same identity key)
		// peerSerializedCert = StringUtil.hex2ByteArray("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
		
		peer1IdCredEd25519x5chain = Util.buildIdCredX5chain(peerSerializedCert); // ID_CRED as 'x5chain'
		peer1IdCredEd25519x5t = Util.buildIdCredX5t(peerSerializedCert); // ID_CRED as 'x5t'
		peer1IdCredEd25519x5u = Util.buildIdCredX5u("http://example.repo.com/hostB-x509-Ed25519"); // ID_CRED as 'x5u'
		
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
	    
		// If the type of credential identifier is 'kid', use 0x08,
		// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x08
		byte[] peer1KidX25519 = new byte[] {(byte) 0x08};
		
		// Build the public key
		
		peerPublicKeyBinary = StringUtil.hex2ByteArray("a3ff263595beb377d1a0ce1d04dad2d40966ac6bcb622051b84659184d5d9a32");
		peer1PublicKeyX25519 =  SharedSecretCalculation.buildCurve25519OneKey(null, peerPublicKeyBinary);
		
		
		// Build CRED as a CCS, and the corresponding ID_CRED as 'kccs' and 'kid'
		
		System.out.print("Peer ");
		CBORObject peer1KidCborX25519 = CBORObject.FromObject(peer1KidX25519);
		peer1CcsObjectX25519 = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(peer1PublicKeyX25519, peerSubjectName, peer1KidCborX25519));
		
		// These serializations have to be prepared manually, in order to ensure that
		// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
		peerCred = StringUtil.hex2ByteArray("A2026008A101A401010241082004215820A3FF263595BEB377D1A0CE1D04DAD2D40966AC6BCB622051B84659184D5D9A32");
 		
		peer1IdCredX25519kccs = Util.buildIdCredKccs(peer1CcsObjectX25519); // ID_CRED as 'kccs'
		peer1IdCredX25519kid = Util.buildIdCredKid(peer1KidX25519); // ID_CRED as 'kid'
		
		peerPublicKeys.put(peer1IdCredX25519kccs, peer1PublicKeyX25519);
		peerCredentials.put(peer1IdCredX25519kccs, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredX25519kid, peer1PublicKeyX25519);
		peerCredentials.put(peer1IdCredX25519kid, CBORObject.FromObject(peerCred));
		
		
		// Build CRED as an X.509 certificate, and the corresponding ID_CRED as 'x5chain', 'x5t' and 'x5u'
		peerSerializedCert = StringUtil.hex2ByteArray("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb3");
		
		// Test with Peter (real DER certificate for the same identity key)
		// peerSerializedCert = StringUtil.hex2ByteArray("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
		
		peer1IdCredX25519x5chain = Util.buildIdCredX5chain(peerSerializedCert); // ID_CRED as 'x5chain'
		peer1IdCredX25519x5t = Util.buildIdCredX5t(peerSerializedCert); // ID_CRED as 'x5t'
		peer1IdCredX25519x5u = Util.buildIdCredX5u("http://example.repo.com/hostB-x509-X25519"); // ID_CRED as 'x5u'
		
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
	    
		// If the type of credential identifier is 'kid', use 0x09,
		// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x09
		byte[] peer1KidP256 = new byte[] {(byte) 0x09};
		
		// Build the public key
		
		peerPublicKeyBinary = StringUtil.hex2ByteArray("6f9702a66602d78f5e81bac1e0af01f8b52810c502e87ebb7c926c07426fd02f");
		peerPublicKeyBinaryY = StringUtil.hex2ByteArray("C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800");
		peer1PublicKeyP256 =  SharedSecretCalculation.buildEcdsa256OneKey(null, peerPublicKeyBinary, peerPublicKeyBinaryY);
		
		
		// Build CRED as a CCS, and the corresponding ID_CRED as 'kccs' and 'kid'
		
		System.out.print("Peer ");
		CBORObject peer1KidCborP256 = CBORObject.FromObject(peer1KidP256);
		peer1CcsObjectP256 = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(peer1PublicKeyP256, peerSubjectName, peer1KidCborP256));
		
		// These serializations have to be prepared manually, in order to ensure that
		// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
		peerCred = StringUtil.hex2ByteArray("A2026008A101A5010202410920012158206F9702A66602D78F5E81BAC1E0AF01F8B52810C502E87EBB7C926C07426FD02F225820C8D33274C71C9B3EE57D842BBF2238B8283CB410ECA216FB72A78EA7A870F800");
 		
		peer1IdCredP256kccs = Util.buildIdCredKccs(peer1CcsObjectP256); // ID_CRED as 'kccs'
		peer1IdCredP256kid = Util.buildIdCredKid(peer1KidP256); // ID_CRED as 'kid'
		
		peerPublicKeys.put(peer1IdCredP256kccs, peer1PublicKeyP256);
		peerCredentials.put(peer1IdCredP256kccs, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredP256kid, peer1PublicKeyP256);
		peerCredentials.put(peer1IdCredP256kid, CBORObject.FromObject(peerCred));
		
		
		// Build CRED as an X.509 certificate, and the corresponding ID_CRED as 'x5chain', 'x5t' and 'x5u'
		peerSerializedCert = StringUtil.hex2ByteArray("c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb4");
			
		// Test with Peter (real DER certificate for the same identity key)
		// peerSerializedCert = StringUtil.hex2ByteArray("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
		
		peer1IdCredP256x5chain = Util.buildIdCredX5chain(peerSerializedCert); // ID_CRED as 'x5chain'
		peer1IdCredP256x5t = Util.buildIdCredX5t(peerSerializedCert); // ID_CRED as 'x5t'
		peer1IdCredP256x5u = Util.buildIdCredX5u("http://example.repo.com/hostB-x509-P256-signing"); // ID_CRED as 'x5u'
		
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
	    
		// If the type of credential identifier is 'kid', use 0x0a,
		// i.e. the serialized ID_CRED_X is 0xa1, 0x04, 0x41, 0x0a
		byte[] peer1KidP256DH = new byte[] {(byte) 0x0a};
		
		
		// Build the public key
		
		peerPublicKeyBinary = StringUtil.hex2ByteArray("bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0");
		peerPublicKeyBinaryY = StringUtil.hex2ByteArray("4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072");
		peer1PublicKeyP256DH =  SharedSecretCalculation.buildEcdsa256OneKey(null, peerPublicKeyBinary, peerPublicKeyBinaryY);
		
		
		// Build CRED as a CCS, and the corresponding ID_CRED as 'kccs' and 'kid'
		
		System.out.print("Peer ");
		CBORObject peer1KidCborP256DH = CBORObject.FromObject(peer1KidP256DH);
		peer1CcsObjectP256DH = CBORObject.DecodeFromBytes(Util.buildCredRawPublicKeyCcs(
														peer1PublicKeyP256DH, peerSubjectName, peer1KidCborP256DH));
		
		// These serializations have to be prepared manually, in order to ensure that
		// the CBOR map used as CRED has its parameters encoded in bytewise lexicographic order
		peerCred = StringUtil.hex2ByteArray("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072");		
		
		peer1IdCredP256DHkccs = Util.buildIdCredKccs(peer1CcsObjectP256DH); // ID_CRED as 'kccs'
		peer1IdCredP256DHkid = Util.buildIdCredKid(peer1KidP256DH); // ID_CRED as 'kid'
		
		peerPublicKeys.put(peer1IdCredP256DHkccs, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHkccs, CBORObject.FromObject(peerCred));
		peerPublicKeys.put(peer1IdCredP256DHkid, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHkid, CBORObject.FromObject(peerCred));
		
		
		// Build CRED as an X.509 certificate, and the corresponding ID_CRED as 'x5chain', 'x5t' and 'x5u'
		peerSerializedCert = StringUtil.hex2ByteArray("4488370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b70a47624dc9cdc6824b2a4c52e95ec9d6b0534b71c2b49e4bf9031500cee6869979c297bb5a8b381e98db714108415e5c50db78974c271579b01633a3ef6271be5c225eb4");
		
		// Test with Peter (real DER certificate for the same identity key)
		// peerSerializedCert = StringUtil.hex2ByteArray("308202763082021ca00302010202144aebaeff99a7ec4c9b398e007e3074d6d24fd779300a06082a8648ce3d0403023073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c301e170d3231303230393039333131345a170d3232303230393039333131345a3073310b3009060355040613024e4c310b300906035504080c024e423110300e06035504070c0748656c6d6f6e6431133011060355040a0c0a76616e64657273746f6b31143012060355040b0c0b636f6e73756c74616e6379311a301806035504030c117265676973747261722e73746f6b2e6e6c3059301306072a8648ce3d020106082a8648ce3d030107034200040d75040e117b0fed769f235a4c831ff3b6699b8e310af28094fe3baea003b5e9772a4def5d8d4ee362e9ae9ef615215d115341f531338e3fa4030b6257b25d66a3818d30818a301d0603551d0e0416041444f3cf92db3cda030a3faf611872b90c601c0f74301f0603551d2304183016801444f3cf92db3cda030a3faf611872b90c601c0f74300f0603551d130101ff040530030101ff30270603551d250420301e06082b0601050507031c06082b0601050507030106082b06010505070302300e0603551d0f0101ff0404030201f6300a06082a8648ce3d0403020348003045022100ee29fb91849d8f0c617de9f817e016b535cac732235eed8a6711e68a3a634d0802205d1750bc02f0f1dde19a7c48d82fb5442c560d13f3d1a7e99546a6c39a28f38b");
		
		// CRED, as serialization of a CBOR byte string wrapping the serialized certificate
		peerCred = CBORObject.FromObject(peerSerializedCert).EncodeToBytes();
		
		peer1IdCredP256DHx5chain = Util.buildIdCredX5chain(peerSerializedCert); // ID_CRED as 'x5chain'
		peer1IdCredP256DHx5t = Util.buildIdCredX5t(peerSerializedCert); // ID_CRED as 'x5t'
		peer1IdCredP256DHx5u = Util.buildIdCredX5u("http://example.repo.com/hostB-x509-P256-dh"); // ID_CRED as 'x5u'
		
		peerPublicKeys.put(peer1IdCredP256DHx5chain, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHx5chain, CBORObject.FromObject(peerCred));
		
		peerPublicKeys.put(peer1IdCredP256DHx5t, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHx5t, CBORObject.FromObject(peerCred));
		
		peerPublicKeys.put(peer1IdCredP256DHx5u, peer1PublicKeyP256DH);
		peerCredentials.put(peer1IdCredP256DHx5u, CBORObject.FromObject(peerCred));
		
	}
	
}
