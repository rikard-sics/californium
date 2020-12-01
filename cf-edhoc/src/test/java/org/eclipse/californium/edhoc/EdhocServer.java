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

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;

import net.i2p.crypto.eddsa.Utils;

public class EdhocServer extends CoapServer {

	private static final int COAP_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_PORT);

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
	 * Constructor for a new Hello-World server. Here, the resources of the
	 * server are initialized.
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
