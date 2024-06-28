/*******************************************************************************
 * Copyright (c) 2024 RISE SICS and others.
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
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

/**
 * Methods for perform re-derivation of contexts using the KUDOS procedure. It
 * uses 1 message exchange together with an exchange of nonces in the OSCORE
 * option to securely generate a new shared context.
 *
 * See https://datatracker.ietf.org/doc/draft-ietf-core-oscore-key-update/
 */
public class KudosRederivation {

	private static SecureRandom random = new SecureRandom();

	public static int NONCE_LENGTH = 8;
	public static boolean EXTRA_LOGGING = false;

	private static final String SCHEME = "coap://";

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(KudosRederivation.class);

	/**
	 * Prepare to initiate an outgoing KUDOS Request #1 from a client
	 * 
	 * @param db the OSCORE Security Context database
	 * @param uri the URI target of the request
	 * @throws ConnectorException on failure
	 * @throws OSException on failure
	 */
	static void initiateRequestKudos(OSCoreCtxDB db, String uri) throws ConnectorException, OSException {
	
		// Retrieve the context for the target URI
		OSCoreCtx ctx = db.getContext(uri);
	
		// Check that context re-derivation is enabled for this context
		if (ctx.getKudosContextRederivationEnabled() == false) {
			System.err.println("[KUDOS] Context re-derivation is not enabled for this context.");
			throw new IllegalStateException("[KUDOS] Context re-derivation is not enabled for this context.");
		}
	
		// Generate a random N1)
		byte[] n1 = Bytes.createBytes(random, NONCE_LENGTH);
	
		if (EXTRA_LOGGING) {
			System.out.println("[KUDOS] context re-derivation phase: " + ctx.getContextRederivationPhase());
			System.out.println("[KUDOS] N1 value: " + Utils.toHexString(n1));
		}
	
		// Create new context with the generated Nonce N1
		byte x = (byte) (NONCE_LENGTH - 1);
		byte[] xArray = new byte[] { x };
	
		// Build new OSCORE Context
		OSCoreCtx newCtx = updateCtx(xArray, n1, ctx);
	
		// Save the generated N1 value in the new context
		newCtx.setKudosN1(n1);
		newCtx.setKudosX1(x);
		newCtx.setKudosCtxOld(ctx);
		newCtx.setContextRederivationPhase(ContextRederivation.PHASE.KUDOS_CLIENT_PHASE1);
	
		db.removeContext(ctx);
		if (!uri.startsWith(SCHEME)) {
			uri = SCHEME + uri;
		}
		db.addContext(uri, newCtx);
	}

	/**
	 * Handle incoming requests for KUDOS procedure (handling of incoming
	 * Request #1)
	 * 
	 * @param db OSCORE OSCORE Security Context database
	 * @param ctx the specific OSCORE Security Context to update
	 * @param contextID the ID Context of this context
	 * @param rid the RID of this context
	 * @return a new OSCORE Security Context
	 * 
	 * @throws OSException on failure
	 */
	static OSCoreCtx incomingRequest(OSCoreCtxDB db, OSCoreCtx ctx, byte[] contextID, byte[] rid) throws OSException {

		// Try to retrieve the context based on the RID only if no context was
		// found. Since the ID Context in the initial request will be a new one
		// and not match existing contexts.
		if (ctx == null) {
			ctx = db.getContext(rid);
		}

		// No context found still
		if (ctx == null) {
			return null;
		}

		// First handle KUDOS context rederivation (server-side reception of
		// Request #1)
		if (ctx.getContextRederivationPhase() == PHASE.KUDOS_SERVER_PHASE1) {
			printStateLoggingKudos(ctx);

			// Build new OSCORE Context
			OSCoreCtx ctxOut = updateCtx(new byte[] { ctx.getKudosX1() }, ctx.getKudosN1(), ctx);

			ctxOut.setContextRederivationPhase(PHASE.KUDOS_SERVER_PHASE2);
			ctxOut.setKudosN1(ctx.getKudosN1());
			ctxOut.setKudosX1(ctx.getKudosX1());
			ctxOut.setKudosCtxOld(ctx);
			db.removeContext(ctx);

			String uri = ctx.getUri();
			if (!uri.startsWith(SCHEME)) {
				uri = SCHEME + uri;
			}
			db.addContext(uri, ctxOut);
			return ctxOut;
		}

		return ctx;
	}

	/**
	 * Handle incoming response messages (for client to handle incoming Response
	 * #1).
	 * 
	 * @param db the context db
	 * @param ctx the context
	 * @param contextID the context ID in the incoming response
	 * @return an updated context
	 * @throws OSException if context re-derivation fails
	 */
	static OSCoreCtx incomingResponse(OSCoreCtxDB db, OSCoreCtx ctx, byte[] contextID) throws OSException {
	
		// Check if context re-derivation is enabled for this context
		if (ctx.getKudosContextRederivationEnabled() == false) {
			LOGGER.debug("[KUDOS] Context re-derivation not considered due to it being disabled for this context");
			return ctx;
		}
	
		// Handle client phase 2 operations
		if (ctx.getContextRederivationPhase() == ContextRederivation.PHASE.KUDOS_CLIENT_PHASE2) {
	
			printStateLoggingKudos(ctx);
	
			byte[] n1 = ctx.getKudosN1();
			byte x1 = ctx.getKudosX1();
			byte[] n2 = ctx.getKudosN2();
			byte x2 = ctx.getKudosX2();
	
			if (EXTRA_LOGGING) {
				System.out.println("[KUDOS] context re-derivation phase: " + ctx.getContextRederivationPhase());
				System.out.println("[KUDOS] N1 value: " + Utils.toHexString(n1));
				System.out.println("[KUDOS] X1 value: " + x1);
				System.out.println("[KUDOS] N2 value: " + Utils.toHexString(n2));
			}
	
			byte[] xInput = comb(x1, x2);
			byte[] nInput = comb(n1, n2);
	
			if (EXTRA_LOGGING) {
				System.out.println("[KUDOS] X input to updateCtx(): " + Utils.toHexString(xInput));
				System.out.println("[KUDOS] N input to updateCtx(): " + Utils.toHexString(nInput));
			}
	
			// Generate new OSCORE Context
			OSCoreCtx ctxOld = ctx.getKudosCtxOld();
			OSCoreCtx newCtx = updateCtx(xInput, nInput, ctxOld);
	
			// Save the generated N2 value in the new context
			newCtx.setKudosN1(n1);
			newCtx.setKudosX1(x1);
			newCtx.setKudosN2(n2);
			newCtx.setKudosX2(x2);
			newCtx.setContextRederivationPhase(ContextRederivation.PHASE.INACTIVE);
	
			db.removeContext(ctx);
			String uri = ctx.getUri();
			if (!uri.startsWith(SCHEME)) {
				uri = SCHEME + uri;
			}
			db.addContext(uri, newCtx);
	
			return newCtx;
		}
	
		return ctx;
	}

	/**
	 * Handle outgoing response messages (for server processing of Response #1).
	 * 
	 * @param db the context db
	 * @param ctx the context
	 * @return an updated context
	 * @throws OSException if context re-derivation fails
	 */
	static OSCoreCtx outgoingResponse(OSCoreCtxDB db, OSCoreCtx ctx) throws OSException {

		// Check that context re-derivation is enabled for this context
		if (ctx.getKudosContextRederivationEnabled() == false) {
			System.err.println("[KUDOS] Context re-derivation is not enabled for this context.");
			throw new IllegalStateException("[KUDOS] Context re-derivation is not enabled for this context.");
		}

		// Check that the server is in the expected phase
		if (ctx.getContextRederivationPhase() != ContextRederivation.PHASE.KUDOS_SERVER_PHASE2) {
			return ctx;
		}

		byte[] n1 = ctx.getKudosN1();
		byte x1 = ctx.getKudosX1();

		// Generate a random N2
		byte[] n2 = Bytes.createBytes(random, NONCE_LENGTH);

		if (EXTRA_LOGGING) {
			System.out.println("[KUDOS] context re-derivation phase: " + ctx.getContextRederivationPhase());
			System.out.println("[KUDOS] N1 value: " + Utils.toHexString(n1));
			System.out.println("[KUDOS] X1 value: " + x1);
			System.out.println("[KUDOS] N2 value: " + Utils.toHexString(n2));
		}

		// Create new context with the generated Nonce N2 and the received N1
		byte x2 = (byte) (NONCE_LENGTH - 1);

		byte[] xInput = comb(x1, x2);
		byte[] nInput = comb(n1, n2);

		if (EXTRA_LOGGING) {
			System.out.println("[KUDOS] X input to updateCtx(): " + Utils.toHexString(xInput));
			System.out.println("[KUDOS] N input to updateCtx(): " + Utils.toHexString(nInput));
		}

		// Generate new OSCORE Context
		OSCoreCtx ctxOld = ctx.getKudosCtxOld();
		OSCoreCtx newCtx = updateCtx(xInput, nInput, ctxOld);

		// Save the generated N2 value in the new context
		newCtx.setKudosN1(n1);
		newCtx.setKudosX1(x1);
		newCtx.setKudosN2(n2);
		newCtx.setKudosX2(x2);
		newCtx.setContextRederivationPhase(ContextRederivation.PHASE.KUDOS_SERVER_PHASE3);

		db.removeContext(ctx);
		String uri = ctx.getUri();
		if (!uri.startsWith(SCHEME)) {
			uri = SCHEME + uri;
		}
		db.addContext(uri, newCtx);

		return newCtx;
	}

	/**
	 * Implements the KUDOS updateCtx function. See
	 * https://datatracker.ietf.org/doc/html/draft-ietf-core-oscore-key-update-07#figure-2
	 * 
	 * @param x input X parameter
	 * @param n input N parameter
	 * @param ctxIn input context
	 * 
	 * @return new OSCORE context
	 */
	static OSCoreCtx updateCtx(byte[] x, byte[] n, OSCoreCtx ctxIn) {
	
		byte[] X_cbor = CBORObject.FromObject(x).EncodeToBytes();
		byte[] N_cbor = CBORObject.FromObject(n).EncodeToBytes();
		byte[] X_N = concatenateArrays(X_cbor, N_cbor);
	
		byte[] masterSaltNew = n;
	
		// Generate new Master Secret
		int oscoreKeyLength = ctxIn.getMasterSecret().length;
		String label = "key update";
		byte[] masterSecretNew = null;
	
		try {

			// Build the info (ExpandLabel) structure
			ByteArrayOutputStream expandLabel = new ByteArrayOutputStream();
			byte[] length = ByteBuffer.allocate(2).putShort((short) oscoreKeyLength).array();
			expandLabel.write(length);

			byte[] labelBytes = ("oscore " + label).getBytes();
			expandLabel.write(labelBytes);

			expandLabel.write(X_N);

			byte[] info = expandLabel.toByteArray();
			System.out.println("[KUDOS] ExpandLabel: " + Utils.toHexString(info));

			masterSecretNew = hkdfExpand(ctxIn.getMasterSecret(), info, oscoreKeyLength);

		} catch (InvalidKeyException | NoSuchAlgorithmException | IOException e1) {
			System.err.println("Failed to generate new Master Secret when running KUDOS");
			e1.printStackTrace();
		}
	
		if (EXTRA_LOGGING) {
			System.out.println("[KUDOS] # In updateCtx() # ");
			System.out.println("[KUDOS] X_N value: " + Utils.toHexString(X_N));
			System.out.println("[KUDOS] Old Master Secret: " + Utils.toHexString(ctxIn.getMasterSecret()));
			System.out.println("[KUDOS] New Master Secret: " + Utils.toHexString(masterSecretNew));
			System.out.println("[KUDOS] New Master Salt: " + Utils.toHexString(masterSaltNew));
			System.out.println("[KUDOS] # End in updateCtx() # ");
		}
	
		// Derive the new OSCORE Security Context
		OSCoreCtx ctxOut = null;
		try {
			ctxOut = rederiveWithKudos(ctxIn, masterSecretNew, masterSaltNew);
		} catch (OSException e) {
			System.err.println("Failed to perform new OSCORE Security Context derivation when running KUDOS");
			e.printStackTrace();
		}
	
		return ctxOut;
	}

	/**
	 * Re-derive a context with the same input parameters except Master Secret
	 * and Master Salt. Also retain the same context re-derivation key.
	 * 
	 * @param ctx the OSCORE context to re-derive
	 * @param masterSecret the new Master Secret to use
	 * @param masterSalt the new Master Salt to use
	 * 
	 * @return the new re-derived context
	 * @throws OSException on failure
	 */
	private static OSCoreCtx rederiveWithKudos(OSCoreCtx ctx, byte[] masterSecret, byte[] masterSalt)
			throws OSException {
		OSCoreCtx newCtx = new OSCoreCtx(masterSecret, true, ctx.getAlg(), ctx.getSenderId(), ctx.getRecipientId(),
				ctx.getKdf(), ctx.getRecipientReplaySize(), masterSalt, ctx.getIdContext(),
				ctx.getMaxUnfragmentedSize());
		newCtx.setContextRederivationKey(ctx.getContextRederivationKey());
		newCtx.setKudosContextRederivationEnabled(ctx.getKudosContextRederivationEnabled());
		newCtx.setKudosCtxOld(ctx.getKudosCtxOld());
		return newCtx;
	}

	/**
	 * Implements the comb function, see
	 * https://datatracker.ietf.org/doc/html/draft-ietf-core-oscore-key-update-07#section-4.3-20
	 * 
	 * @param a the first byte array
	 * @param b the second byte array
	 * @return concatenated result after CBOR bstr wrapping
	 */
	static byte[] comb(byte[] a, byte[] b) {
	
		CBORObject aCbor = CBORObject.FromObject(a);
		CBORObject bCbor = CBORObject.FromObject(b);
	
		byte[] aCborBytes = aCbor.EncodeToBytes();
		byte[] bCborBytes = bCbor.EncodeToBytes();
	
		byte[] out = concatenateArrays(aCborBytes, bCborBytes);
	
		return out;
	}

	/**
	 * Comb method with non-array inputs
	 * 
	 * @param x1 byte one
	 * @param x2 byte two
	 * @return concatenated result
	 */
	private static byte[] comb(byte x1, byte x2) {
		return comb(new byte[] { x1 }, new byte[] { x2 });
	}

	/**
	 * Method for concatenating byte arrays
	 * 
	 * @param first the first array
	 * @param second the second array
	 * @return the concatenated result
	 */
	private static byte[] concatenateArrays(byte[] first, byte[] second) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		try {
			outputStream.write(first);
			outputStream.write(second);
		} catch (IOException e) {
			System.err.println("Failed to concatenate byte arrays");
			e.printStackTrace();
		}

		byte res[] = outputStream.toByteArray();
		return res;
	}

	/**
	 * Provides logging output indicating the current state. Uses debug level
	 * output for the inactive state since that is the default for typical use.
	 * 
	 * @param ctx the OSCORE context in use
	 */
	private static void printStateLoggingKudos(OSCoreCtx ctx) {

		if (LOGGER.isDebugEnabled() == false && EXTRA_LOGGING == false) {
			return;
		}

		PHASE currentPhase = ctx.getContextRederivationPhase();
		String supplemental = "";

		if (EXTRA_LOGGING == true) {
			System.out.println("[KUDOS] Context re-derivation phase: " + currentPhase + "(" + supplemental + ")");
		}

		if (currentPhase == PHASE.INACTIVE) {
			LOGGER.trace("[KUDOS] Context re-derivation phase: {} ({})", currentPhase, supplemental);
		} else {
			LOGGER.debug("[KUDOS] Context re-derivation phase: {} ({})", currentPhase, supplemental);
		}
	}

	/**
	 * HKDF-Expand.
	 * 
	 * @param prk the pseudorandom key
	 * @param info context and application specific information
	 * @param len length of output keying material in octets
	 * @return output keying material
	 * 
	 * @throws InvalidKeyException if the HMAC procedure fails
	 * @throws NoSuchAlgorithmException if an unknown HMAC is used
	 */
	static byte[] hkdfExpand(byte[] prk, byte[] info, int len) throws InvalidKeyException, NoSuchAlgorithmException {

		final String digest = "SHA256"; // Hash to use

		String HMAC_ALG_NAME = "Hmac" + digest;
		Mac hmac = Mac.getInstance(HMAC_ALG_NAME);
		int hashLen = hmac.getMacLength();

		// Perform expand
		hmac.init(new SecretKeySpec(prk, HMAC_ALG_NAME));
		int c = (len / hashLen) + 1;
		byte[] okm = new byte[len];
		int maxLen = (hashLen * c > len) ? hashLen * c : len;
		byte[] T = new byte[maxLen];
		byte[] last = new byte[0];
		for (int i = 0; i < c; i++) {
			hmac.reset();
			hmac.update(last);
			hmac.update(info);
			hmac.update((byte) (i + 1));
			last = hmac.doFinal();
			System.arraycopy(last, 0, T, i * hashLen, hashLen);
		}
		System.arraycopy(T, 0, okm, 0, len);
		return okm;
	}

}
