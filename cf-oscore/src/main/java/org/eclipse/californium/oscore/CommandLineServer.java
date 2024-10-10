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

import java.net.InetSocketAddress;
import java.util.HashMap;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * 
 * HelloWorldServer to display basic OSCORE mechanics
 *
 */
public class CommandLineServer {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	private final static int localPort = CoAP.DEFAULT_COAP_PORT;

	// test vector OSCORE draft Appendix C.1.2
	private static byte[] masterSecret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
			0x0E, 0x0F, 0x10 };
	private static byte[] masterSalt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23, (byte) 0x78,
			(byte) 0x63, (byte) 0x40 };
	private static byte[] sid = new byte[] { 0x01 };
	private static byte[] rid = new byte[] { 0x02 };
	private static byte[] idContext = null;
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	static String defaultDebugMode = "false";
	static boolean debugMode;

	static String defaultUseOscore = "true";
	static boolean useOscore;

	static String defaultUseAppendixB2 = "false";
	static boolean useAppendixB2;

	static String defaultUseKudos = "false";
	static boolean useKudos;

	static String defaultNonceLength = "8";
	static int nonceLength;

	static String listenAddr;

	public static void main(String[] args) throws OSException {
		// Parse command line arguments
		HashMap<String, String> cmdArgs = new HashMap<>();

		if (args.length % 2 != 0) {
			printHelp();
		}

		for (int i = 0; i < args.length; i += 2) {

			if (args[i + 1].toLowerCase().equals("null")) {
				;
			} else {
				cmdArgs.put(args[i], args[i + 1]);
			}
		}

		if (cmdArgs.containsValue("--help")) {
			printHelp();
		}

		try {
			masterSecret = StringUtil.hex2ByteArray(cmdArgs.get("--msecret"));
			masterSalt = StringUtil.hex2ByteArray(cmdArgs.get("--msalt"));
			sid = StringUtil.hex2ByteArray(cmdArgs.get("--sid"));
			rid = StringUtil.hex2ByteArray(cmdArgs.get("--rid"));
			idContext = StringUtil.hex2ByteArray(cmdArgs.get("--idcontext"));
			debugMode = Boolean.parseBoolean(cmdArgs.getOrDefault("--debug", defaultDebugMode));
			useOscore = Boolean.parseBoolean(cmdArgs.getOrDefault("--oscore", defaultUseOscore));
			useAppendixB2 = Boolean.parseBoolean(cmdArgs.getOrDefault("--appendixb2", defaultUseAppendixB2));
			useKudos = Boolean.parseBoolean(cmdArgs.getOrDefault("--kudos", defaultUseKudos));
			nonceLength = Integer.parseInt(cmdArgs.getOrDefault("--nonce-len", defaultNonceLength));
			listenAddr = cmdArgs.get("--listen-addr");
		} catch (Exception e) {
			printHelp();
		}

		// Change from nulls to emptys
		if (sid == null) {
			sid = Bytes.EMPTY;
		}
		if (rid == null) {
			rid = Bytes.EMPTY;
		}

		// Print settings
		System.out.println("===");
		System.out.println("Settings:");
		System.out.println("Master Secret: " + Utils.toHexString(masterSecret));
		System.out.println("Master Salt: " + Utils.toHexString(masterSalt));
		System.out.println("Sender ID: " + Utils.toHexString(sid));
		System.out.println("Recipient ID: " + Utils.toHexString(rid));
		System.out.println("ID Context: " + Utils.toHexString(idContext));
		System.out.println("Debug Mode: " + debugMode);
		System.out.println("Use OSCORE: " + useOscore);
		System.out.println("Use Appendix B.2: " + useAppendixB2);
		System.out.println("Use KUDOS: " + useKudos);
		System.out.println("Nonce Length: " + nonceLength);
		if (listenAddr == null) {
			System.out.println("Local Address: " + "Default");
		} else {
			System.out.println("Local Address: " + listenAddr);
		}
		System.out.println("===");

		if (debugMode) {
			OSCoreCtx.EXTRA_LOGGING = true;
		}

		// Create OSCORE Security Context
		OSCoreCtx ctx = new OSCoreCtx(masterSecret, false, alg, sid, rid, kdf, 32, masterSalt, idContext,
				MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriLocal, ctx);
		OSCoreCoapStackFactory.useAsDefault(db);

		if (useAppendixB2) {
			ctx.setContextRederivationEnabled(true);
		}

		if (useKudos) {
			ctx.setKudosContextRederivationEnabled(true);
		}

		// Set nonce lengths
		ContextRederivation.setSegmentLength(nonceLength);
		KudosRederivation.NONCE_LENGTH = nonceLength;
		if (debugMode) {
			System.out.println("RID: " + Utils.toHexString(rid));
			System.out.println("SID: " + Utils.toHexString(sid));
			System.out.println("Common IV: " + Utils.toHexString(ctx.getCommonIV()));

			System.out.println("Sender Key: " + Utils.toHexString(ctx.getSenderKey()));
			System.out.println("Recipient Key: " + Utils.toHexString(ctx.getRecipientKey()));
			Encryptor.EXTRA_LOGGING = true;
			Decryptor.EXTRA_LOGGING = true;
			ContextRederivation.EXTRA_LOGGING = true;
			KudosRederivation.EXTRA_LOGGING = true;
		}

		CoapServer server = null;

		// Use custom listen address or use default
		if (listenAddr != null) {
			server = new CoapServer();
			CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
			InetSocketAddress localAddr = new InetSocketAddress(listenAddr, localPort);
			builder.setInetSocketAddress(localAddr);
			CoapEndpoint endp = builder.build();
			server.addEndpoint(endp);
		} else {
			server = new CoapServer(localPort);
		}

		OSCoreResource hello = new OSCoreResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello Resource");
				exchange.respond(r);
			}

			@Override
			public void handlePOST(CoapExchange exchange) {
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
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				r.setPayload("Hello World!");
				exchange.respond(r);
			}

			@Override
			public void handlePOST(CoapExchange exchange) {
				System.out.println("Accessing hello/1 resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				r.setPayload("Hello World!");
				exchange.respond(r);
			}
		};

		server.add(hello.add(hello1));

		try {
			server.start();
		} catch (IllegalStateException e) {
			System.err.println("Failed to start server endpoint!");
			System.exit(1);
		}

		Endpoint testEndpoint = server.getEndpoint(localPort);
		if (testEndpoint.isStarted() == false) {
			System.err.println("Failed to start server endpoint!");
			System.exit(1);
		}
	}

	private static void printHelp() {
		System.out.println("");
		System.out.println("--msecret: Master Secret");
		System.out.println("--msalt: Master Salt");
		System.out.println("--sid: Sender ID");
		System.out.println("--rid: Recipient ID");
		System.out.println("--idcontext: ID Context");
		System.out.println("--debug: True/False - Enable or disable debug printing");
		System.out.println("--oscore: True/False - Use OSCORE");
		System.out.println("--appendixb2: True/False - Initiate the Appendix B.2 procedure");
		System.out.println("--kudos: True/False - Initiate the KUDOS procedure");
		System.out.println("--nonce-len: Length of nonces for Appendix B.2 and KUDOS");
		System.out.println("--listen-addr: Local IP address to listen to");
		System.exit(1);
	}

}
