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
 *    Rikard Höglund (RISE)
 *    Marco Tiloca (RISE)
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
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

public class EdhocServer extends CoapServer {

	private static final boolean debugPrint = true;
	
	private static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);

	private final static Provider EdDSA = new EdDSASecurityProvider();
	
	// Uncomment to use an ECDSA key pair with curve P-256 as long-term identity key
    // private final static int keyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to use an EdDSA key pair with curve Ed25519 for signatures
    private final static int keyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Uncomment to use a Montgomery key pair with curve X25519
	// private final static int keyCurve = KeyKeys.OKP_X25519.AsInt32();
    
    // The ID_CRED used for the identity key of this peer
    private static CBORObject idCred = null;
    
    // The subject name used for the identity key of this peer
    private static String subjectName = "myServer";
    
    // The long-term asymmetric key pair of this peer
	private static OneKey keyPair = null;
	
	// Long-term public keys of authorized peers
	// The map label is a CBOR Map used as ID_CRED_X
	private static Map<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
	
	// Existing EDHOC Sessions, including completed ones
	// The map label is C_X, i.e. the connection identifier offered to the other peer in the session, as a bstr_identifier
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
	
	/*
	 * Application entry point.
	 */
	public static void main(String[] args) {

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
		
		// Use to set up hardcoded keys for this peer and the other peer 
		setupIdentityKeys(keyCurve);
		
		// Add the supported ciphersuites
		supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_0);
		supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_1);
		supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_2);
		supportedCiphersuites.add(Constants.EDHOC_CIPHER_SUITE_3);
		
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Connection Identifiers; one set for each possible size in bytes.
        	// The set with index 0 refers to Connection Identifiers with size 1 byte
    		usedConnectionIds.add(new HashSet<Integer>());
    	}
		
    	// Uncomment to run tests of different cryptographic operations
		// runTests();		
	}

	/**
	 * Add individual endpoints listening on default CoAP port on all IPv4
	 * addresses of all network interfaces.
	 */
	private void addEndpoints(boolean udp) {
		NetworkConfig config = NetworkConfig.getStandard();
		for (InetAddress addr : NetworkInterfacesUtil.getNetworkInterfaces()) {
			InetSocketAddress bindToAddress = new InetSocketAddress(addr, COAP_PORT);
			if (udp) {
				CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
				builder.setInetSocketAddress(bindToAddress);
				builder.setNetworkConfig(config);
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
		
		// provide an instance of a .well-known/edhoc resource
		CoapResource edhocResource = new EdhocResource();
		wellKnownResource.add(edhocResource);

	}
	
	/*
	 * Process application data conveyed in AD_1 in EDHOC Message 1
	 */
	private void processAD1(byte[] ad1) {
		// Do nothing
		System.out.println("Entered processAD1()");
	}
	
	/*
	 * Process application data conveyed in AD_2 in EDHOC Message 2
	 */
	private void processAD2(byte[] ad2) {
		// Do nothing
		System.out.println("Entered processAD2()");
	}
	
	/*
	 * Process application data conveyed in AD_3 in EDHOC Message 3
	 */
	private void processAD3(byte[] ad3) {
		// Do nothing
		System.out.println("Entered processAD3()");
	}
	
	private static void setupIdentityKeys (int keyCurve) {
		
		String keyPairBase64 = null;
		String peerPublicKeyBase64 = null;
		
		if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
			keyPairBase64 = "pgMmAQIgASFYIPWSTdB9SCF/+CGXpy7gty8qipdR30t6HgdFGQo8ViiAIlggXvJCtXVXBJwmjMa4YdRbcdgjpXqM57S2CZENPrUGQnMjWCDXCb+hy1ybUu18KTAJMvjsmXch4W3Hd7Rw7mTF3ocbLQ==";
			peerPublicKeyBase64 = "pQMmAQIgASFYIGdZmgAlZDXB6FGfVVxHrB2LL8JMZag4JgK4ZcZ/+GBUIlgguZsSChh5hecy3n4Op+lZZJ2xXdbsz8DY7qRmLdIVavk=";
		}
 		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
 			keyPairBase64 = "pQMnAQEgBiFYIDzQyFH694a7CcXQasH9RcqnmwQAy2FIX97dGGGy+bpSI1gg5aAfgdGCH2/2KFsQH5lXtDc8JUn1a+OkF0zOG6lIWXQ=";
 			peerPublicKeyBase64 = "pAMnAQEgBiFYIEPgltbaO4rEBSYv3Lhs09jLtrOdihHUxLdc9pRoR/W9";
 		}
 		else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
 			keyPairBase64 = "pQMnAQEgBiFYIKOjK/y+4psOGi9zdnJBqTLThdpEj6Qygg4Voc10NYGSI1ggn/quL33vMaN9Rp4LKWCXVnaIRSgeeCJlU0Mv/y6zHlQ=";
 			peerPublicKeyBase64 = "pAMnAQEgBiFYIGt2OynWjaQY4cE9OhPQrwcrZYNg8lRJ+MwXIYMjeCtr";
 		}
		
		try {
			Provider EdDSA = new EdDSASecurityProvider();
			Security.insertProviderAt(EdDSA, 0);
			
			// The following considers raw public keys when building ID_CRED_X and CRED_X
			
			// Build the OneKey object for the identity key pair of this peer
			keyPair =  new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(keyPairBase64)));
			// Build the related ID_CRED
			byte[] idCredKid = new byte[] {(byte) 0x01}; // Use 0x01 as kid for this peer
			idCred = Util.buildIdCredKid(idCredKid);
			// Build the related CRED
			
			// Build the OneKey object for the identity public key of the other peer
			OneKey peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(peerPublicKeyBase64)));
			// Build the related ID_CRED
			byte[] peerKid = new byte[] {(byte) 0x00}; // Use 0x00 as kid for the other peer
			CBORObject idCredPeer = Util.buildIdCredKid(peerKid);
			peerPublicKeys.put(idCredPeer, peerPublicKey);
			// Build the related CRED
			
		} catch (CoseException e) {
			System.err.println("Error while generating the key pair");
			return;
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
			System.out.println("Hash outpu: " + Utils.bytesToHex(resultHash));
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
		
		byte[] mySignature = null;
		try {
			mySignature = Util.computeSignature(idCredX, externalData, payloadToSign, keyPair);
	        System.out.println("Signing completed");
		} catch (CoseException e) {
			System.err.println("Error while computing the signature");
			e.printStackTrace();
		}
		
		boolean verified = false;
		try {
			verified = Util.verifySignature(mySignature, idCredX, externalData, payloadToSign, keyPair);
		} catch (CoseException e) {
			System.err.println("Error while verifying the signature");
			e.printStackTrace();
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
			myCiphertext = Util.encrypt(idCredX, externalData, payloadToEncrypt, encryptionAlg, iv, symmetricKey);
			System.out.println("Encryption completed");
		} catch (CoseException e) {
			System.err.println("Error while encrypting");
			e.printStackTrace();
		}
		byte[] myPlaintext = null;
		try {
			myPlaintext = Util.decrypt(idCredX, externalData, myCiphertext, encryptionAlg, iv, symmetricKey);
			System.out.println("Decryption completed");
		} catch (CoseException e) {
			System.err.println("Error while encrypting");
			e.printStackTrace();
		}
		System.out.println("Decryption correctness: " + Arrays.equals(payloadToEncrypt, myPlaintext));
		System.out.println();
		
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
	
	/*
	 * Definition of the EDHOC Resource
	 */
	class EdhocResource extends CoapResource {

		public EdhocResource() {

			// set resource identifier
			super("edhoc");

			// set display name
			getAttributes().setTitle("EDHOC Resource");
		}

		@Override
		public void handleGET(CoapExchange exchange) {

			// respond to the request
			exchange.respond("Send me a POST request to run EDHOC!");
		}
		
		
		@Override
		public void handlePOST(CoapExchange exchange) {
			
			System.out.println("\nReceived EDHOC Message\n");
			
			byte[] message1 = exchange.getRequestPayload();
			int messagetType = MessageProcessor.messageType(message1);
			
			List<CBORObject> processingResult = new ArrayList<CBORObject>();
			byte[] nextMessage = new byte[] {};
			
			// Possibly specify application data for AD_2, or null if none have to be provided
			byte[] ad2 = null;
			
			// Invalid EDHOC message type
			if (messagetType == -1) {
				String responseString = new String("Invalid EDHOC message type");
				nextMessage = responseString.getBytes(Constants.charset);
				Response genericErrorResponse = new Response(ResponseCode.BAD_REQUEST);
				genericErrorResponse.setPayload(nextMessage);
				
			}
			
			System.out.println("Determined EDHOC message type: " + messagetType + "\n");
			Util.nicePrint("EDHOC message " + messagetType, message1);

			/* Start handling EDHOC Message 1 */
			if (messagetType == Constants.EDHOC_MESSAGE_1) {
				processingResult = MessageProcessor.readMessage1(message1, keyPair, usedConnectionIds,
						                                         supportedCiphersuites, edhocSessions);

				// A non-zero length response payload would be an EDHOC Error Message
				nextMessage = processingResult.get(0).GetByteString();

				// Prepare EDHOC Message 2
				if (nextMessage.length == 0) {
					
					EdhocSession mySession = MessageProcessor.createSessionAsResponder
							                 (message1, keyPair, idCred, subjectName, supportedCiphersuites, usedConnectionIds);
					
					// Compute the EDHOC Message 2
					nextMessage = MessageProcessor.writeMessage2(mySession, ad2);

					byte[] connectionId = mySession.getConnectionId();
					
					// Deallocate the assigned Connection Identifier for this peer
					if (nextMessage == null || mySession.getCurrentStep() != Constants.EDHOC_BEFORE_M2) {
						Util.releaseConnectionId(connectionId, usedConnectionIds);
						System.err.println("Inconsistent state before sending EDHOC Message 2");
						return;
					}
					
					// Add the new session to the list of existing EDHOC sessions
					mySession.setCurrentStep(Constants.EDHOC_AFTER_M2);
					edhocSessions.put(CBORObject.FromObject(connectionId), mySession);
					
				}
				int responseType = MessageProcessor.messageType(nextMessage);
				
				if (responseType != Constants.EDHOC_MESSAGE_2 && responseType != Constants.EDHOC_ERROR_MESSAGE) {
					nextMessage = null;
				}
				
				if (nextMessage != null) {
					Response myResponse = new Response(ResponseCode.CREATED);
					myResponse.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
					myResponse.setPayload(nextMessage);
					
					String myString = (responseType == Constants.EDHOC_MESSAGE_2) ? "EDHOC Message 2" : "EDHOC Error Message";
					System.out.println("Response type: " + myString + "\n");
					
					if (responseType == Constants.EDHOC_MESSAGE_2) {
				        System.out.println("Sent EDHOC Message 2\n");
				        if (debugPrint) {
				        	Util.nicePrint("EDHOC Message 2", nextMessage);
				        }
					}
					if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
				        System.out.println("Sent EDHOC Error Message\n");
				        if (debugPrint) {
				        	Util.nicePrint("EDHOC Error Message", nextMessage);
				        }
					}
					
					exchange.respond(myResponse);
				}
				
				// Deliver AD_1 to the application
				if (processingResult.size() == 2) {
					processAD1(processingResult.get(1).GetByteString());
				}
				
			}
			/* End handling EDHOC Message 1 */

		}
		
	}
}
