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
import java.util.Arrays;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

public class EdhocServer extends CoapServer {

	private static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);

	private final static Provider EdDSA = new EdDSASecurityProvider();
	
	// Uncomment to set ECDSA with curve P-256 for signatures
    private final static int signKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set EDDSA with curve Ed25519 for signatures
    // private final static int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // The long-term asymmetric key pair of this peer
	private static OneKey keyPair = null;
	
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
		
		runTests();		
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
	
	public static void runTests() {
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
		idCredX.Add(KeyKeys.KeyId, kid);
		
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
		boolean decryptionMatch = false;
		System.out.println("Decryption correctness: " + Arrays.equals(payloadToEncrypt, myPlaintext));
		System.out.println();
		
	}
	
	private static OneKey makeSingleKey(OneKey keyPair, boolean isPrivate) {
		
	    CBORObject key = CBORObject.NewMap();
        OneKey coseKey = null;
	    
        key.Add(KeyKeys.KeyType.AsCBOR(), keyPair.get(KeyKeys.KeyType));
        
	    if (isPrivate) {
	    	if(keyPair.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2) {
		        key.Add(KeyKeys.EC2_Curve.AsCBOR(), keyPair.get(KeyKeys.EC2_Curve));
		        key.Add(KeyKeys.EC2_D.AsCBOR(), keyPair.get(KeyKeys.EC2_D));

	    	}
	    	else if(keyPair.get(KeyKeys.KeyType) == KeyKeys.KeyType_OKP) {
		        key.Add(KeyKeys.OKP_Curve.AsCBOR(), keyPair.get(KeyKeys.OKP_Curve));
		        key.Add(KeyKeys.OKP_D.AsCBOR(), keyPair.get(KeyKeys.OKP_D));
	    	}
	        
	    }
	    else {
	    	if(keyPair.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2) {
		        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
		        key.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
		        key.Add(KeyKeys.EC2_X.AsCBOR(), keyPair.get(KeyKeys.EC2_X));
		        key.Add(KeyKeys.EC2_Y.AsCBOR(), keyPair.get(KeyKeys.EC2_Y));
	    	}
	    	else if(keyPair.get(KeyKeys.KeyType) == KeyKeys.KeyType_OKP) {
		        key.Add(KeyKeys.OKP_Curve.AsCBOR(), keyPair.get(KeyKeys.OKP_Curve));
		        key.Add(KeyKeys.OKP_X.AsCBOR(), keyPair.get(KeyKeys.OKP_X));
	    	}
	    }

        try {
        	coseKey = new OneKey(key);
		} catch (CoseException e) {
			System.err.println("Error while generating the private key");
		}
	    return coseKey;
		
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
			
			System.out.println("\nReceived EDHOC Message1\n");
			
			byte[] requestPayload = exchange.getRequestPayload();
			
			// Check if this is an EDHOC Message1 or an EDHOC Message3 bound to an ongoing instance
			// TBD
			
			// Process EDHOC Message1
			// TBD
			
			// Prepare EDHOC Message2
			// TBD
			String responseString = new String("Your payload was " + Utils.bytesToHex(requestPayload));
			byte[] responsePayload = responseString.getBytes(Constants.charset);
			
			// Send EDHOC Message2
			Response edhocMessage2 = new Response(ResponseCode.CREATED);
			edhocMessage2.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
			edhocMessage2.setPayload(responsePayload);
			exchange.respond(edhocMessage2);
			
			// Save status to recognize a later EDHOC Message3
			// TBD
			
			// Process EDHOC Message3
			// TBD
			
		}
		
	}
}
