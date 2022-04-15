/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 * Contributors:
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.Timer;
import java.util.TimerTask;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * 
 * Observe testing server
 * 
 * Has an observable resource under /observe2
 *
 */
public class ObserveTestServer {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.2
	static byte[] id_context = StringUtil.hex2ByteArray("37cbf3210017a2d3");
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[] { 0x02 };
	private final static byte[] rid = new byte[] { 0x01 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;
	private static Timer timer;

	public static void main(String[] args) throws OSException {
		OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, id_context,
				MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriLocal, ctx);
		OSCoreCoapStackFactory.useAsDefault(db);

		final CoapServer server = new CoapServer(5683);

		OSCoreResource hello = new OSCoreResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello Resource");
				exchange.respond(r);
			}
		};

		OSCoreResource hello1 = new OSCoreResource("1", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello/1 resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello World!");
				exchange.respond(r);
				server.destroy();
			}
		};

		/**
		 * The resource for testing Observe support
		 * 
		 * Responds with "one" for the first request and "two" for later
		 * updates.
		 *
		 */
		class ObserveResource extends CoapResource {

			public int value = 1;
			private boolean firstRequestReceived = false;

			public ObserveResource(String name, boolean visible) {
				super(name, visible);

				this.setObservable(true);
				this.setObserveType(Type.NON);
				this.getAttributes().setObservable();

				timer.schedule(new UpdateTask(), 0, 1000);
			}

			@Override
			public void handleGET(CoapExchange exchange) {
				firstRequestReceived = true;

				exchange.respond(Integer.toString(value));
			}

			// Update the resource value when timer triggers (if 1st request is
			// received)
			class UpdateTask extends TimerTask {

				@Override
				public void run() {
					if (firstRequestReceived) {
						value += 1;
						changed(); // notify all observers
					}
				}
			}
		}
		timer = new Timer();
		// observe2 resource for OSCORE Observe tests
		ObserveResource oscore_observe2 = new ObserveResource("observe2", true);

		server.add(oscore_observe2);
		server.add(hello.add(hello1));
		server.start();
	}
}
