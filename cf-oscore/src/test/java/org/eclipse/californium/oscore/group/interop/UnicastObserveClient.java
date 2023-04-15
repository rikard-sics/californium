/*******************************************************************************
 * Copyright (c) 2023 RISE SICS and others.
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

import java.util.Random;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;

/**
 * Client for CoAP observations using unicast requests
 *
 */
public class UnicastObserveClient {

	private static int serverPort = 5683;
	private static String serverAddress = "127.0.0.1";
	private static int cancelAfterMessages = 20;

	public static void main(String[] args) throws InterruptedException {
		testObserve();
	}

	/**
	 * Tests Observe functionality. Registers to a resource and listens for 10
	 * notifications. After this the observation is cancelled.
	 * 
	 * @throws InterruptedException if sleep fails
	 */
	public static void testObserve() throws InterruptedException {

		String resourceUri = "/base/observe2";
		CoapClient client = new CoapClient();

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

		Request r = createClientRequest(Code.GET, resourceUri);
		r.setToken(token);
		r.setObserve();
		@SuppressWarnings("unused")
		CoapObserveRelation relation = client.observe(r, handler);

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
		r = createClientRequest(Code.GET, resourceUri);
		r.setToken(token);
		r.getOptions().setObserve(1); // Deregister Observe
		r.send();

		Response resp = r.waitForResponse(1000);

		String content = resp.getPayloadString();
		System.out.println("Response (last): " + content);
		client.shutdown();
	}

	/**
	 * Create a request to be set from a client to the server
	 * 
	 * @param c Code of request
	 * @param resourceUri Relative URI of resource
	 * @return The request
	 */
	private static Request createClientRequest(Code c, String resourceUri) {
		String serverUri = "coap://" + serverAddress + ":" + serverPort;

		Request r = new Request(c);

		r.setConfirmable(true);
		r.setURI(serverUri + resourceUri);

		return r;
	}

}
