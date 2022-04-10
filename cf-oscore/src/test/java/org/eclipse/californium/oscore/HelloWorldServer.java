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

import java.io.IOException;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.util.Base64;

/**
 * 
 * HelloWorldServer to display basic OSCORE mechanics
 *
 */
public class HelloWorldServer {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[] { 0x01 };
	private final static byte[] rid = new byte[0];
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	private static int counter = 0;
	
	public static void main(String[] args) throws OSException, IOException {

		String theString = "QUJDREVGR0hJSks";
		byte[] theBytes = theString.getBytes("US-ASCII");
		byte[] oscore = Base64.decode(theBytes, 0, theBytes.length, Base64.URL_SAFE | Base64.NO_PADDING);
		System.out.println("OSCORE: " + Utils.toHexString(oscore));
		System.out.println("OSCORE: " + new String(oscore));

		OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, null, MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriLocal, ctx);
		OSCoreCoapStackFactory.useAsDefault(db);

		final CoapServer server = new CoapServer(5685);

		CoapResource hello = new CoapResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello Resource");
				exchange.respond(r);
			}
		};

		CoapResource target = new CoapResource("coap-target", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing coap-target resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("coap-target Resource " + counter);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				exchange.respond(r);
				counter++;
			}
		};

		CoapResource hello1 = new CoapResource("1", true) {


			@Override
			public void handleGET(CoapExchange exchange) {
				boolean usingOscore = exchange.getRequestOptions().hasOscore();

				System.out.println("GET: Accessing hello/1 resource" + " with OSCORE: " + usingOscore);
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello World!");
				exchange.respond(r);
			}

			@Override
			public void handlePOST(CoapExchange exchange) {
				boolean usingOscore = exchange.getRequestOptions().hasOscore();

				System.out.println("POST: Accessing hello/1 resource" + " with OSCORE: " + usingOscore);
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello World!");
				exchange.respond(r);
			}
		};

		server.add(target);
		server.add(hello.add(hello1));
		server.start();
	}
}
