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

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * 
 * HelloWorldServer to display basic OSCORE mechanics
 *
 */
public class HelloWorldServerContext {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] context_id_1 = { (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA };
	private final static byte[] context_id_2 = { (byte) 0xBB, (byte) 0xBB, (byte) 0xBB, (byte) 0xBB };
	private final static byte[] sid_1 = new byte[] { 0x01 };
	private final static byte[] rid_1 = new byte[0];
	private final static byte[] sid_2 = new byte[] { (byte) 0x99 };
	private final static byte[] rid_2 = new byte[] { (byte) 0x88 };

	public static void main(String[] args) throws OSException {
		OSCoreCtx ctx1 = new OSCoreCtx(master_secret, false, alg, sid_1, rid_1, kdf, 32, master_salt, context_id_1);
		OSCoreCtx ctx2 = new OSCoreCtx(master_secret, false, alg, sid_2, rid_2, kdf, 32, master_salt, context_id_2);
		db.addContext(uriLocal, ctx1);
		db.addContext(uriLocal, ctx2);
		OSCoreCoapStackFactory.useAsDefault(db);

		final CoapServer server = new CoapServer(5683);

		CoapResource hello = new CoapResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello Resource");
				exchange.respond(r);
			}
		};

		CoapResource hello1 = new CoapResource("1", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				boolean usingOscore = requestUsesOSCORE(exchange.advanced().getRequest());
				String contextID = requestUsesContext(exchange.advanced().getRequest());
				System.out.println("Accessing hello/1 resource (using OSCORE: " + usingOscore + ". With context: "
						+ contextID + ")");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello World!");
				exchange.respond(r);
			}
		};

		server.add(hello.add(hello1));
		server.start();
	}

	private static boolean requestUsesOSCORE(Request request) {
		EndpointContext endpointContext = request.getSourceContext();
		if (endpointContext instanceof MapBasedEndpointContext) {
			MapBasedEndpointContext mapCtx = (MapBasedEndpointContext) endpointContext;
			String recipientID = mapCtx.get(OSCoreEndpointContextInfo.OSCORE_RECIPIENT_ID);
			if (recipientID != null) {
				return true;
			}
		}
		return false;
	}

	private static String requestUsesContext(Request request) {
		EndpointContext endpointContext = request.getSourceContext();
		if (endpointContext instanceof MapBasedEndpointContext) {
			MapBasedEndpointContext mapCtx = (MapBasedEndpointContext) endpointContext;
			String contextID = mapCtx.get(OSCoreEndpointContextInfo.OSCORE_CONTEXT_ID);
			return contextID;
		}

		return null;
	}
}
