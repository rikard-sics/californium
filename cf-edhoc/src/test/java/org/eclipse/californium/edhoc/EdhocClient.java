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

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

public class EdhocClient {

	private static final File CONFIG_FILE = new File("Californium.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Fileclient";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 2 * 1024 * 1024; // 2
																			// MB
	private static final int DEFAULT_BLOCK_SIZE = 512;
	
	private final static Provider EdDSA = new EdDSASecurityProvider();
	
	// Uncomment to use an ECDSA key pair with curve P-256 as long-term identity key
    private final static int keyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to use an EdDSA key pair with curve Ed25519 for signatures
    // private final static int keyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Uncomment to use a Montgomery key pair with curve X25519
    // private final static int keyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // The ID_CRED used for the identity key of this peer
    private static byte[] idCred = null;
    
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
	
	// EDHOC Message1 and EDHOC Message2 can be correlated thanks to the CoAP Token
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
		
		// Use to set up hardcoded keys for this peer and the other peer 
		setupIdentityKeys(keyCurve);
		
		if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
			
		}
		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
			
		}
		else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
			
		}
		
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
		edhocExchangeSignature(args, uri);

	}
	
	private static void setupIdentityKeys (int keyCurve) {
		
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
 		}
		
		try {
			// Build the OneKey object for the identity key pair of this peer
			keyPair =  new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(keyPairBase64)));
			idCred = new byte[] {(byte) 0x00}; // Use 0x00 as ID_CRED for this peer
			
			// Build the OneKey object for the identity public key of the other peer
			OneKey peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(peerPublicKeyBase64)));
			CBORObject idCredX = CBORObject.NewMap();
			byte[] kid = new byte[] {(byte) 0x01}; // Use 0x01 as ID_CRED for the other peer
			idCredX.Add(KeyKeys.KeyId, CBORObject.FromObject(kid));
			peerPublicKeys.put(idCredX, peerPublicKey);
			
		} catch (CoseException e) {
			System.err.println("Error while generating the key pair");
			return;
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
					e.printStackTrace();
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
	
	private static void edhocExchangeSignature(final String args[], final URI targetUri) {
		
		CoapClient client = new CoapClient(targetUri);

		CoapResponse response = null;
		
		/*
		// Simple sending of a GET request
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
					e.printStackTrace();
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
		
		// Send EDHOC Message 1
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
		
		// Receive and process EDHOC Message 2
		// TBD
		
		// Send EDHOC Message 3
		// TBD
				
		client.shutdown();
		
	}

}
