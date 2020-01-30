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
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.cose.Encrypt0Message;

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
	 * @param response the response
	 * @param ctx the OSCore context
	 * @param newPartialIV boolean to indicate whether to use a new partial IV or not
	 * 
	 * @return the response with the encrypted OSCore option
	 * 
	 * @throws OSException when encryption fails
	 */
	public static Response encrypt(OSCoreCtxDB db, Response response, OSCoreCtx ctx, final boolean newPartialIV) throws OSException {
		if (ctx == null) {
			org.eclipse.californium.elements.MyLogger.LOG_error(ErrorDescriptions.CTX_NULL);
			throw new OSException(ErrorDescriptions.CTX_NULL);
		}

		// Perform context re-derivation procedure if ongoing
		try {
			ctx = ContextRederivation.outgoingResponse(db, ctx);
		} catch (OSException e) {
			org.eclipse.californium.elements.MyLogger.LOG_error(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			throw new OSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
		}

		int realCode = response.getCode().value;
		response = OptionJuggle.setFakeCodeResponse(response);

		OptionSet options = response.getOptions();

		byte[] confidential = OSSerializer.serializeConfidentialData(options, response.getPayload(), realCode);
		Encrypt0Message enc = prepareCOSEStructure(confidential);
		byte[] cipherText = encryptAndEncode(enc, ctx, response, newPartialIV);
		compression(ctx, cipherText, response, newPartialIV);

		options = response.getOptions();
		response.setOptions(OptionJuggle.prepareUoptions(options));

		//If new partial IV was generated for response increment sender seq nr.
		if (newPartialIV) {
			ctx.increaseSenderSeq();
		}
		
		return response;
	}
}
