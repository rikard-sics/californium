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


import java.io.File;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Random;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;

public class MulticastObserveClient {

	private static int cancelAfterMessages = 20;

	public static void main(String[] args) throws InterruptedException, ConnectorException, IOException {
		testObserve();
	}

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumMulticast.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Multicast Client";
	/**
	 * Special network configuration defaults handler.
	 */
	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MULTICAST_BASE_MID, 65000);
		}

	};

	/**
	 * Time to wait for replies to the multicast request
	 */
	@SuppressWarnings("unused")
	private static final int HANDLER_TIMEOUT = 2000;

	/**
	 * Multicast address to send to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	/**
	 * Port to send to.
	 */
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT;

	/**
	 * Tests Observe functionality. Registers to a resource and listens for 10
	 * notifications. After this the observation is cancelled.
	 * 
	 * @throws InterruptedException if sleep fails
	 */
	public static void testObserve() throws InterruptedException, ConnectorException, IOException {

		String resourceUri = "/base/observe2";

		/**
		 * URI to perform request against. Need to check for IPv6 to surround it
		 * with []
		 */
		String requestURI;
		if (multicastIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort + resourceUri;
		} else {
			requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort + resourceUri;
		}

		// Configure client
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		CoapEndpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		CoapClient client = new CoapClient();
		client.setEndpoint(endpoint);
		client.setURI(requestURI);

		// Handler for Observe responses
		class ObserveHandler implements CoapHandler {

			int count = 1;
			int abort = 0;

			// Triggered when a Observe response is received
			@Override
			public void onLoad(CoapResponse response) {
				abort++;

				String content = response.getResponseText();
				System.out.println("NOTIFICATION (#" + count + "): " + content);

				count++;
			}

			@Override
			public void onError() {
				System.err.println("Observing failed");
			}
		}

		ObserveHandler handler = new ObserveHandler();

		// Create request and initiate Observe relationship
		byte[] token = new byte[8];
		new Random().nextBytes(token);

		Request r = Request.newGet();
		r.setURI(requestURI);
		r.setType(Type.NON);
		r.setToken(token);
		r.setObserve();

		// Normal way to start observations (for unicast):
		// @SuppressWarnings("unused")
		// CoapObserveRelation relation = client.observe(r, handler);

		// Start observation with an ObserveHandler:
		client.advanced(handler, r);

		// Also works to start it with a MultiCoapHandler:
		// client.advanced(handlerMulti, r);
		// while (handlerMulti.waitOn(HANDLER_TIMEOUT))
		// ;
		
		// Wait until a certain number of messages have been received
		while (handler.count <= cancelAfterMessages) {
			Thread.sleep(550);

			// Failsafe to abort test if needed
			if (handler.abort > cancelAfterMessages + 10) {
				System.exit(0);
				break;
			}
		}

		// Now cancel the Observe and wait for the final response
		// r = createClientRequest(Code.GET, resourceUri);
		// r.setToken(token);
		// r.getOptions().setObserve(1); // Deregister Observe
		// r.send();
		//
		// Response resp = r.waitForResponse(1000);
		//
		// String content = resp.getPayloadString();
		// System.out.println("Response (last): " + content);

		client.shutdown();
	}

	private static final MultiCoapHandler handlerMulti = new MultiCoapHandler();

	private static class MultiCoapHandler implements CoapHandler {

		private boolean on;

		public synchronized boolean waitOn(long timeout) {
			on = false;
			try {
				wait(timeout);
			} catch (InterruptedException e) {
			}
			return on;
		}

		private synchronized void on() {
			on = true;
			notifyAll();
		}

		/**
		 * Handle and parse incoming responses.
		 */
		@Override
		public void onLoad(CoapResponse response) {
			on();

			// System.out.println("Receiving to: "); //TODO
			System.out.println("Receiving from: " + response.advanced().getSourceContext().getPeerAddress());

			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	};

}
