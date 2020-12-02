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

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.exception.ConnectorException;

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
	
	// Uncomment to set ECDSA with curve P-256 for signatures
    private final static int signKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set EDDSA with curve Ed25519 for signatures
    // private final static int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // The long-term asymmetric key pair of this peer
	private static OneKey keyPair = null;
	
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

		// Generate the new long-term asymmetric key pair 
		try {
	 		if (signKeyCurve == KeyKeys.EC2_P256.AsInt32())
	 			keyPair = OneKey.generateKey(AlgorithmID.ECDSA_256);
	    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	        	Security.insertProviderAt(EdDSA, 0);
	    		keyPair = OneKey.generateKey(AlgorithmID.EDDSA);
	    	}
			
		} catch (CoseException e) {
			System.err.println("Error while generating the key pair");
			return;
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
		edhocExchange(args, uri);

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
	
	private static void edhocExchange(final String args[], final URI targetUri) {
		
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
