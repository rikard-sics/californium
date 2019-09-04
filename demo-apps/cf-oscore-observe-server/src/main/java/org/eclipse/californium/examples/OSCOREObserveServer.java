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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add endpoints for all IP addresses
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP parameter
 *    Rikard Höglund (RISE SICS)                    - modify to OSCORE observe server
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Timer;
import java.util.TimerTask;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OSCOREObserveServer extends CoapServer {

	private static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);
	
	//OSCORE context information for server
	private final static HashMapCtxDB dbServer = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] context_id = { 0x11, 0x22, 0x33, 0x44 };
	private final static byte[] rid = { (byte) 0xCC };
	private final static byte[] sid = { (byte) 0xAA };

	private static final Logger LOGGER = LoggerFactory.getLogger(OSCOREObserveServer.class.getCanonicalName());
	
	//Use OSCORE or not
	private static final boolean USE_OSCORE = false;
	
	/*
	 * Application entry point.
	 */
	public static void main(String[] args) {
		
		//Remove the observe option if the payload is the following
		CoapExchange.setPayloadToSkipObserve("10");

		//Add OSCORE context for the server
		if(USE_OSCORE) {
			try {
				OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, context_id);
				dbServer.addContext(ctx);
			}
			catch (OSException e) {
				LOGGER.error("Failed to set server OSCORE Context information!");
			}
			OSCoreCoapStackFactory.useAsDefault(dbServer);
		}
		LOGGER.info("Using OSCORE: " + USE_OSCORE);
		
		try {
			// create server
			boolean udp = true;

			OSCOREObserveServer server = new OSCOREObserveServer();
			// add endpoints on all IP addresses
			server.addEndpoints(udp);
			server.start();

		} catch (SocketException e) {
			LOGGER.error("Failed to initialize server: " + e.getMessage());
		}
	}

	/**
	 * Add individual endpoints listening on default CoAP port on all IPv4
	 * addresses of all network interfaces.
	 */
	private void addEndpoints(boolean udp) {
		NetworkConfig config = NetworkConfig.getStandard();
		for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
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
	 * Constructor for a new Hello-World server. Here, the resources of the
	 * server are initialized.
	 */
	public OSCOREObserveServer() throws SocketException {

		// provide an instance of a Hello-World resource
		HelloWorldResource helloWorld = new HelloWorldResource();
		LOGGER.info("Added new resource " + helloWorld.getURI());
		add(helloWorld);
		
		ObserveResource observe = new ObserveResource("observe", true);
		LOGGER.info("Added new resource " + observe.getURI());
		add(observe);
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
			LOGGER.info("Received request for " + this.getURI() + " resource.");

			// respond to the request
			exchange.respond("Hello World!");
		}
	}
	
	/**
	 * The resource for testing Observe support 
	 * 
	 * Responds with incrementing number every second.
	 *
	 */
	class ObserveResource extends CoapResource {
		
		public int value = 0;
		private Timer timer;
		private boolean firstRequestReceived = false;
		
		public ObserveResource(String name, boolean visible) {
			super(name, visible);
			
			this.setObservable(true); 
			this.setObserveType(Type.NON);
			this.getAttributes().setObservable();
			
			timer = new Timer();
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			if(firstRequestReceived == false) {
				boolean usingObserve = exchange.getRequestOptions().getObserve() != null;
				boolean usingOSCORE = exchange.getRequestOptions().getOscore() != null;
				LOGGER.info("Received request for " + this.getURI() + " resource. Responding with value: " + value
						+ ". Using Observe: " + usingObserve + ". Using OSCORE: " + usingOSCORE);
				
				firstRequestReceived = true;
				timer.schedule(new UpdateTask(), 2500, 2500);
			}
			
			exchange.respond(String.valueOf(value));
		}
		
		//Update the resource value when timer triggers (if 1st request has been received)
		class UpdateTask extends TimerTask {
			@Override
			public void run() {	
				value++;
				LOGGER.info("Sending notification with value: " + value);
				changed(); // notify all observers
			}
		}
	}
}
