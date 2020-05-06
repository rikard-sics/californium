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

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;

import java.io.IOException;

/**
 * 
 * HelloWorldClient to display the basic OSCORE mechanics
 *
 */
public class HelloWorldClientContext {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static String hello1 = "/hello/1";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] context_id_1 = { (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA };
	private final static byte[] context_id_2 = { (byte) 0xBB, (byte) 0xBB, (byte) 0xBB, (byte) 0xBB };
	private final static byte[] sid_1 = new byte[0];
	private final static byte[] rid_1 = new byte[] { 0x01 };
	private final static byte[] sid_2 = new byte[] { (byte) 0x88 };
	private final static byte[] rid_2 = new byte[] { (byte) 0x99 };

	public static void main(String[] args) throws OSException, ConnectorException, IOException {
		OSCoreCtx ctx1 = new OSCoreCtx(master_secret, true, alg, sid_1, rid_1, kdf, 32, master_salt, context_id_1);
		OSCoreCtx ctx2 = new OSCoreCtx(master_secret, true, alg, sid_2, rid_2, kdf, 32, master_salt, context_id_2);
		String context = "AAAAAAAA";
		db.addContext(uriLocal, ctx1);

		OSCoreCoapStackFactory.useAsDefault(db);
		CoapClient c = new CoapClient(uriLocal + hello1);

		int count = 0;
		
		Request r = new Request(Code.GET);

		for (; count < 10; count++) {
			r = new Request(Code.GET);
			boolean usingOscore = true;
			r.getOptions().setOscore(Bytes.EMPTY);

			if (count == 5) {
				context = "BBBBBBBB";
				db.purge();
				db.addContext(uriLocal, ctx2);
			}

			CoapResponse resp = c.advanced(r);
			System.out.println(
					"Request #" + count + ": " + resp.getResponseText() + " (" + resp.advanced().getRTT() + " ms) "
							+ "(using OSCORE: " + usingOscore + ". With context: " + context + ")");
		}

		c.shutdown();
	}
}
