/*******************************************************************************
 * Copyright (c) 2023 RISE SICS and others.
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
 *    Rikard Höglund (RISE) rikard.hoglund@ri.se
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.io.IOException;
import java.util.HashMap;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;

/**
 * 
 * Example OSCORE client using the Californium library.
 *
 */
public class CommandLineClient {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private static String defaultUri = "coap://localhost/hello";
	private static String uri;

	// OSCORE Security Context parameters
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	private static byte[] masterSecret = StringUtil.hex2ByteArray("0102030405060708090A0B0C0D0E0F10");
	private static byte[] masterSalt = StringUtil.hex2ByteArray("9e7ca92223786340");

	private static byte[] idContext = null;
	private final static Integer replayWindowSize = 32;

	private static byte[] sid = new byte[] { 0x02 };
	private static byte[] rid = new byte[] { 0x01 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	static String defaultRequestCount = "1";
	static int requestCount;

	static String defaultInitialSeq = "0";
	static int initialSeq;

	static String defaultDebugMode = "false";
	static boolean debugMode;

	static String defaultUseOscore = "true";
	static boolean useOscore;

	static String defaultUseAppendixB2 = "false";
	static boolean useAppendixB2;

	public static void main(String[] args) throws InterruptedException, ConnectorException, IOException {
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
			uri = cmdArgs.getOrDefault("--uri", defaultUri);
			requestCount = Integer.parseInt(cmdArgs.getOrDefault("--count", defaultRequestCount));
			initialSeq = Integer.parseInt(cmdArgs.getOrDefault("--seq", defaultInitialSeq));
			debugMode = Boolean.parseBoolean(cmdArgs.getOrDefault("--debug", defaultDebugMode));
			useOscore = Boolean.parseBoolean(cmdArgs.getOrDefault("--oscore", defaultUseOscore));
			useAppendixB2 = Boolean.parseBoolean(cmdArgs.getOrDefault("--appendixb2", defaultUseAppendixB2));
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

		// Create and set OSCORE Security Context
		OSCoreCtx ctx = null;
		try {
			ctx = new OSCoreCtx(masterSecret, true, alg, sid, rid, kdf, replayWindowSize, masterSalt, idContext,
					MAX_UNFRAGMENTED_SIZE);
			db.addContext(uri, ctx);
			ctx.setSenderSeq(initialSeq);
		} catch (Exception e) {
			printHelp();
		}

		if (useAppendixB2) {
			ctx.setContextRederivationEnabled(true);
			ctx.setContextRederivationPhase(PHASE.CLIENT_INITIATE);
		}

		OSCoreCoapStackFactory.useAsDefault(db);

		if (debugMode) {
			System.out.println("RID: " + Utils.toHexString(rid));
			System.out.println("SID: " + Utils.toHexString(sid));
			System.out.println("Common IV: " + Utils.toHexString(ctx.getCommonIV()));

			System.out.println("Sender Key: " + Utils.toHexString(ctx.getSenderKey()));
			System.out.println("Recipient Key: " + Utils.toHexString(ctx.getRecipientKey()));
			Encryptor.EXTRA_LOGGING = true;
			ContextRederivation.EXTRA_LOGGING = true;
		}

		CoapClient c = new CoapClient(uri);

		// Send normal request
		for (int i = 0; i < requestCount; i++) {
			System.out.println();
			System.out.println("==== Sending request #" + (i + 1) + " ===");
			Request req = new Request(Code.GET);
			req.setURI(uri);
			if (useOscore) {
				req.getOptions().setOscore(Bytes.EMPTY);
			}
			CoapResponse resp = c.advanced(req);

			System.out.println("Received Response #" + (i + 1));
			System.out.println(Utils.prettyPrint(resp));
			System.out.println("Payload bytes: " + Utils.toHexString(resp.getPayload()));
			Thread.sleep(1000);
		}

		c.shutdown();
	}

	private static void printHelp() {
		System.out.println("");
		System.out.println("--msecret: Master Secret");
		System.out.println("--msalt: Master Salt");
		System.out.println("--sid: Sender ID");
		System.out.println("--rid: Recipient ID");
		System.out.println("--idcontext: ID Context");
		System.out.println("--uri: URI / URL of server");
		System.out.println("--count: Number of messages to send");
		System.out.println("--seq: OSCORE Sender Sequence Number / Partial IV");
		System.out.println("--debug: True/False - Enable or disable debug printing");
		System.out.println("--oscore: True/False - Use OSCORE");
		System.out.println("--appendixb2: True/False - Initiate the Appendix B.2 procedure");
		System.exit(1);
	}

}
