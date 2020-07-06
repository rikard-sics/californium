/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 * 
 * Contributors: 
 *    Rikard Höglund (RISE SICS) - testing Observe messages
 ******************************************************************************/
package org.eclipse.californium.oscore.group.interop;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;

public class UnicastObserveServer {

	private static CoapServer server;
	private static int serverPort = 5683;
	private static String serverAddress = "127.0.0.1";

	public static void main(String[] args) throws InterruptedException {
		createServer();
	}

	/**
	 * Creates server with resources to test Observe functionality
	 * 
	 * @throws InterruptedException if resource update task fails
	 */
	public static void createServer() throws InterruptedException {

		Random rand = new Random();
		final int serverID = rand.nextInt(100);

		// Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();

		InetAddress serverInetAddress = null;
		try {
			serverInetAddress = InetAddress.getByName(serverAddress);
		} catch (UnknownHostException e) {
			System.err.println("Failed to find server address!");
		}

		builder.setInetSocketAddress(new InetSocketAddress(serverInetAddress, 0));
		CoapEndpoint endpoint = builder.build();
		server = new CoapServer(serverPort);
		server.addEndpoint(endpoint);

		/** --- Resources for Observe tests follow --- **/

		// Base resource for Observe test resources
		CoapResource base = new CoapResource("base", true);

		// Second level base resource for Observe test resources
		CoapResource hello = new CoapResource("hello", true);

		/**
		 * The resource for testing Observe support
		 *
		 */
		class ObserveResource extends CoapResource {

			int counter = 0;
			private boolean firstRequestReceived = false;

			public ObserveResource(String name, boolean visible) {
				super(name, visible);

				this.setObservable(true);
				this.setObserveType(Type.NON);
				this.getAttributes().setObservable();

				Timer timer = new Timer();
				timer.schedule(new UpdateTask(), 0, 1500);
			}

			@Override
			public void handleGET(CoapExchange exchange) {
				firstRequestReceived = true;

				exchange.respond("Server Name: " + serverID + ". Value: " + counter);
			}

			// Update the resource value when timer triggers (if 1st request is
			// received)
			class UpdateTask extends TimerTask {

				@Override
				public void run() {
					if (firstRequestReceived) {
						counter++;
						changed(); // notify all observers
					}
				}
			}
		}

		// observe2 resource for Observe tests
		ObserveResource observe2 = new ObserveResource("observe2", true);

		// Creating resource hierarchy
		base.add(hello);
		base.add(observe2);

		server.add(base);

		/** --- End of resources for Observe tests **/

		// Start server
		server.start();
	}

	// @After
	// public void after() {
	// if (null != server) {
	// server.destroy();
	// }
	// System.out.println("End " + getClass().getSimpleName());
	// }
}
