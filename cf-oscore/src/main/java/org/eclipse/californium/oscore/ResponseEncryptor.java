/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.oscore.group.GroupDeterministicSenderCtx;
import org.eclipse.californium.oscore.group.GroupSenderCtx;

/**
 * 
 * Encrypts an OSCORE Response.
 *
 */
public class ResponseEncryptor extends Encryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ResponseEncryptor.class);

	/**
	 * @param db the context DB
	 * @param response the response
	 * @param ctx the OSCore context
	 * @param newPartialIV boolean to indicate whether to use a new partial IV
	 *            or not
	 * @param outerBlockwise boolean to indicate whether the block-wise options
	 *            should be encrypted or not
	 * @param requestSequenceNr sequence number (Partial IV) from the request
	 *            (if encrypting a response)
	 * @param requestOption the OSCORE option of the corresponding request
	 * 
	 * @return the response with the encrypted OSCore option
	 * 
	 * @throws OSException when encryption fails
	 */
	public static Response encrypt(OSCoreCtxDB db, Response response, OSCoreCtx ctx, boolean newPartialIV,
			boolean outerBlockwise, int requestSequenceNr, byte[] requestOption) throws OSException {

		// DET_REQ
		boolean isDetReq = false; // Will be set to true in case of a deterministic request
		
		/*
		 * For a Group OSCORE context, get the specific Sender Context
		 * associated to this Recipient Context.
		 */
		if (ctx != null && ctx.isGroupContext()) {
			ctx = ctx.getSenderCtx();
			// Update this parameter from the now retrieved sender context
			newPartialIV |= ctx.getResponsesIncludePartialIV();
			assert (ctx instanceof GroupSenderCtx);
		}
		// DET_REQ
		else if (ctx != null && response.getOptions().getRequestHash() != null) {
			// This is a response to a deterministic request
			isDetReq = true;
			
			// Retrieve the Sender Context
			// Note: this is not the _deterministic_ Sender Context
			ctx = ctx.getSenderCtx();
			
			assert (ctx instanceof GroupSenderCtx);

		}
		// DET_REQ
		else if (ctx != null && response.getOptions().getRequestHash() != null) {
			// This is a response to a deterministic request
			isDetReq = true;
			
			// Retrieve the Sender Context
			// Note: this is not the _deterministic_ Sender Context
			ctx = ctx.getSenderCtx();

			assert (ctx instanceof GroupSenderCtx);

		}
		// DET_REQ
		else if (ctx != null && response.getOptions().getRequestHash() != null) {
			// This is a response to a deterministic request
			isDetReq = true;
			
			// Retrieve the Sender Context
			// Note: this is not the _deterministic_ Sender Context
			ctx = ctx.getSenderCtx();
			
			assert (ctx instanceof GroupSenderCtx);
		}

		if (ctx == null) {
			LOGGER.error(ErrorDescriptions.CTX_NULL);
			throw new OSException(ErrorDescriptions.CTX_NULL);
		}

		// Perform context re-derivation procedure if ongoing
		try {
			ctx = ContextRederivation.outgoingResponse(db, ctx);
		} catch (OSException e) {
			LOGGER.error(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			throw new OSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
		}

		int realCode = response.getCode().value;
		// DET_REQ
		if (isDetReq) {
			// Set fake code 2.05 (Content) if it is a response to a deterministic request
			response = OptionJuggle.setFakeCodeResponseToDeterministicRequest(response);
			
			// The response to a deterministic request includes a Max-Age option
			response.getOptions().setMaxAge(3600);
		}
		else {
			response = OptionJuggle.setFakeCodeResponse(response);
		}
		
		OptionSet options = response.getOptions();

		// Save block1 option in the case of outer block-wise to re-add later
		BlockOption block1Option = null;
		if (outerBlockwise) {
			block1Option = options.getBlock1();
			options.removeBlock1();
		}
		
		byte[] confidential = OSSerializer.serializeConfidentialData(options, response.getPayload(), realCode);
		Encrypt0Message enc = prepareCOSEStructure(confidential);
		byte[] cipherText = encryptAndEncode(enc, ctx, response, newPartialIV, requestSequenceNr, requestOption);

		compression(ctx, cipherText, response, newPartialIV);

		options = response.getOptions();
		response.setOptions(OptionJuggle.prepareUoptions(options));

		if (outerBlockwise) {
			response.setOptions(response.getOptions().setBlock1(block1Option));
		}

		//If new partial IV was generated for response increment sender seq nr.
		if (newPartialIV) {
			ctx.increaseSenderSeq();
		}
		
		if (ctx.isGroupContext()) {
			assert (ctx instanceof GroupSenderCtx);
		}

		return response;
	}
}
