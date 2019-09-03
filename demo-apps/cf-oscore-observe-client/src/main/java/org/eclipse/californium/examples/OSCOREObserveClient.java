/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Achim Kraus (Bosch Software Innovations GmbH) - add saving payload
 *    Rikard Höglund (RISE SICS)                    - modify to OSCORE observe client
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.cose.AlgorithmID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OSCOREObserveClient {

	private static final File CONFIG_FILE = new File("Californium.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Fileclient";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 2 * 1024 * 1024; // 2 MB
	private static final int DEFAULT_BLOCK_SIZE = 512;

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
		}
	};
	
	//OSCORE context information for client
	private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] context_id = { 0x11, 0x22, 0x33, 0x44 };
	private final static byte[] rid = { (byte) 0xAA };
	private final static byte[] sid = { (byte) 0xCC };
	
	private static final Logger LOGGER = LoggerFactory.getLogger(OSCOREObserveClient.class.getCanonicalName());
	
	/*
	 * Application entry point.
	 * 
	 */	
	public static void main(String args[]) {
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		NetworkConfig.setStandard(config);
		
		URI uri = null; // URI parameter of the request
		
		if (args.length > 0) {
			
			// input URI from command line arguments
			try {
				uri = new URI(args[0]);
			} catch (URISyntaxException e) {
				LOGGER.error("Invalid URI: " + e.getMessage());
				System.exit(-1);
			}
			
			//Add OSCORE context for the client
			try {
				OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, context_id);
				dbClient.addContext(uri.toString(), ctx);
			}
			catch (OSException e) {
				LOGGER.error("Failed to set server OSCORE Context information!");
			}
			OSCoreCoapStackFactory.useAsDefault(dbClient);
			
			//Create and send OSCORE request
			CoapClient client = new CoapClient();
			Request request = Request.newGet();
			request.setURI(uri);
			request.getOptions().setOscore(Bytes.EMPTY);
			
			CoapResponse response = null;
			try {
				response = client.advanced(request);
			} catch (ConnectorException | IOException e) {
				LOGGER.error("Got an error: " + e);
			}

			if (response!=null) {
				
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
		} else {
			// display help
			System.out.println("Californium (Cf) OSCORE observe Client");
			System.out.println("(c) 2014, Institute for Pervasive Computing, ETH Zurich");
			System.out.println();
			System.out.println("Usage : " + OSCOREObserveClient.class.getSimpleName() + " URI");
			System.out.println("  URI : The CoAP URI of the remote resource to observe");
		}
	}

}
