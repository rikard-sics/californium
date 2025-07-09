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

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.option.BlockOption;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.elements.util.Bytes;

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
	 * 
	 * @return the response with the encrypted OSCore option
	 * 
	 * @throws OSException when encryption fails
	 */
	public static Response encrypt(OSCoreCtxDB db, Response response, OSCoreCtx ctx, boolean newPartialIV,
			boolean outerBlockwise, int requestSequenceNr) throws OSException {
		return encrypt(db, response, ctx, newPartialIV, outerBlockwise, requestSequenceNr, null);
	}
	
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
	 * @param instructions instructions to provide additional information for encryption
	 * 
	 * @return the response with the encrypted OSCore option
	 * 
	 * @throws OSException when encryption fails
	 */
	public static Response encrypt(OSCoreCtxDB db, Response response, OSCoreCtx ctx, boolean newPartialIV,
			boolean outerBlockwise, int requestSequenceNr, CBORObject[] instructions) throws OSException {

		if (ctx == null) {
			LOGGER.error(ErrorDescriptions.CTX_NULL);
			throw new OSException(ErrorDescriptions.CTX_NULL);
		}

		// Perform context re-derivation procedure if ongoing
		try {
			ctx = ContextRederivation.outgoingResponse(db, ctx);
			newPartialIV |= ctx.getResponsesIncludePartialIV();

			// Ensure that the first response in the procedure is a 4.01
			if (ctx.getContextRederivationPhase() == ContextRederivation.PHASE.SERVER_PHASE_2) {
				response = OptionJuggle.setRealCodeResponse(response, ResponseCode.UNAUTHORIZED);
				response.setPayload(Bytes.EMPTY);
			}
		} catch (OSException e) {
			LOGGER.error(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			throw new OSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
		}

		int realCode = response.getCode().value;
		response = OptionJuggle.setFakeCodeResponse(response);

		OptionSet options = response.getOptions();

		// Save block1 option in the case of outer block-wise to re-add later
		BlockOption block1Option = null;
		if (outerBlockwise) {
			block1Option = options.getBlock1();
			options.removeBlock1();
		}

		OptionSet[] optionsUAndE = OptionJuggle.filterOptions(options);

		OptionSet promotedOptions = OptionJuggle.promotion(optionsUAndE[0], true, instructions);
		optionsUAndE[1] = OptionJuggle.merge(optionsUAndE[1], promotedOptions);	

		byte[] confidential = OSSerializer.serializeConfidentialData(optionsUAndE[1], response.getPayload(), realCode);

		Encrypt0Message enc = prepareCOSEStructure(confidential);
		byte[] cipherText = encryptAndEncode(enc, ctx, response, newPartialIV, requestSequenceNr);

		compression(ctx, cipherText, response, newPartialIV);

		byte[] oscoreOption = response.getOptions().getOscore();

		// here the U options are prepared
		response.setOptions(OptionJuggle.postInstruction(optionsUAndE[0], instructions));
		response.getOptions().setOscore(oscoreOption);

		if (outerBlockwise) {
			response.setOptions(response.getOptions().setBlock1(block1Option));
		}

		//If new partial IV was generated for response increment sender seq nr.
		if (newPartialIV) {
			ctx.increaseSenderSeq();
		}

		return response;
	}
}
