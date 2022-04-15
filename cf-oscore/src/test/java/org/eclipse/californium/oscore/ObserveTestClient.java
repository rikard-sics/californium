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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.test.CountingCoapHandler;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * 
 * Observe test client
 *
 */
public class ObserveTestClient {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static String hello1 = "/observe2";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	static byte[] id_context = StringUtil.hex2ByteArray("37cbf3210017a2d3");
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[] { 0x01 };
	private final static byte[] rid = new byte[] { 0x02 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	public static void main(String[] args) throws OSException, ConnectorException, IOException, InterruptedException {
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, id_context,
				MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriLocal, ctx);

		OSCoreCoapStackFactory.useAsDefault(db);
		// CoapClient c = new CoapClient(uriLocal + hello1);

		// Handler for Observe responses
		class ObserveHandler extends CountingCoapHandler {

			// Triggered when a Observe response is received
			@Override
			protected void assertLoad(CoapResponse response) {

				String content = response.getResponseText();
				System.out.println("NOTIFICATION: " + content);

			}
		}

		ObserveHandler handler = new ObserveHandler();
		CoapClient client = new CoapClient();

		// Create request and initiate Observe relationship
		byte[] token = Bytes.createBytes(new Random(), 8);

		Request r = createClientRequest(Code.GET, uriLocal + hello1);
		r.setToken(token);
		r.setObserve();
		CoapObserveRelation relation = client.observe(r, handler);

		// Wait until 2 messages have been received
		handler.waitOnLoadCalls(1000, 100 * 2000, TimeUnit.MILLISECONDS);

		return;

		// Request r = new Request(Code.GET);
		// CoapResponse resp = c.advanced(r);
		// printResponse(resp);
		//
		// r = new Request(Code.GET);
		// r.getOptions().setOscore(new byte[0]);
		// resp = c.advanced(r);
		// printResponse(resp);
		// c.shutdown();
	}

	private static void printResponse(CoapResponse resp) {
		if (resp != null) {
			System.out.println("RESPONSE CODE: " + resp.getCode().name() + " " + resp.getCode());
			if (resp.getPayload() != null) {
				System.out.print("RESPONSE PAYLOAD: ");
				for (byte b : resp.getPayload()) {
					System.out.print(Integer.toHexString(b & 0xff) + " ");
				}
				System.out.println();
			}
			System.out.println("RESPONSE TEXT: " + resp.getResponseText());
		} else {
			System.out.println("RESPONSE IS NULL");
		}
	}

	private static Request createClientRequest(Code c, String resourceUri) {

		Request r = new Request(c);

		r.setConfirmable(true);
		r.setURI(resourceUri);

		if (true) {
			r.getOptions().setOscore(Bytes.EMPTY); // Use OSCORE
		}

		return r;
	}
}
