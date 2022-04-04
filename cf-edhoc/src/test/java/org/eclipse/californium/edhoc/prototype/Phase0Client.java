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
package org.eclipse.californium.edhoc.prototype;

import java.io.IOException;
import java.util.Scanner;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import net.i2p.crypto.eddsa.Utils;

/**
 * 
 * HelloWorldClient to display the basic OSCORE mechanics
 *
 */
public class Phase0Client {

	// Set accordingly
	private static String serverAddress = "localhost";

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://" + serverAddress;
	private final static String hello1 = "/light";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	public static void main(String[] args) throws OSException, ConnectorException, IOException, InterruptedException {
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null, MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriLocal, ctx);

		OSCoreCoapStackFactory.useAsDefault(db);
		CoapClient c = new CoapClient(uriLocal + hello1);

		System.out.println("Phase 0 Client ready to send CoAP request" + "\n");
		Support.printPause("Press enter to send CoAP message");

		Request r = new Request(Code.POST);
		r.setPayload("1");
		CoapResponse resp = c.advanced(r);
		printResponse(resp);

		Scanner scanner = new Scanner(System.in);
		String command = "";
		String payload = null;
		while (!command.equals("q")) {

			System.out.println("Enter command: ");
			command = scanner.next();

			if (command.equals("1")) {
				payload = "1";
			} else if (command.equals("0")) {
				payload = "0";
			} else if (command.equals("q")) {
				System.exit(0);
			} else {
				System.out.println("Unknown command!");
			}

			r = new Request(Code.POST);
			r.setPayload(payload);
			resp = c.advanced(r);
			org.eclipse.californium.core.Utils.prettyPrint(resp);
			// System.out.println("RTT: " +
			// resp.advanced().getTransmissionRttNanos() + " nanoseconds");

			Thread.sleep(1000);
		}
		scanner.close();

		c.shutdown();
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
}
