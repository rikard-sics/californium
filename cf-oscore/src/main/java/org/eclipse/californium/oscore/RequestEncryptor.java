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

import java.util.Arrays;

import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.elements.util.Bytes;

/**
 * 
 * Encrypts an OSCORE Request.
 *
 */
public class RequestEncryptor extends Encryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(RequestEncryptor.class);

	/**
	 * @param request the request
	 * @param db the context database used
	 * 
	 * @return the request with the OSCore option
	 * @throws OSException if encryption fails
	 *
	 */
	public static Request encrypt(OSCoreCtxDB db, OSCoreCtx ctx, Request request, CBORObject[] instructions) throws OSException {
		OptionSet options = request.getOptions();

		if (Arrays.equals(options.getOscore(), Bytes.EMPTY)) {
			options.removeOscore();
		}

		if (ctx == null) {
			LOGGER.error(ErrorDescriptions.CTX_NULL);
			throw new OSException(ErrorDescriptions.CTX_NULL);
		}

		// Perform context re-derivation procedure if ongoing
		try {
			ctx = ContextRederivation.outgoingRequest(db, ctx);
		} catch (OSException e) {
			LOGGER.error(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			throw new OSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
		}

		int realCode = request.getCode().value;
		request = OptionJuggle.setFakeCodeRequest(request);

		// This decomposes the Proxy-URI option in the post set
		OptionJuggle.handleProxyURIInstruction(options, instructions);

		OptionSet[] optionsUAndE = OptionJuggle.filterOptions(options);

		OptionSet promotedOptions = OptionJuggle.promotion(optionsUAndE[0], instructions);

		optionsUAndE[1] = OptionJuggle.merge(optionsUAndE[1], promotedOptions);	

		// here the E options are set 
		byte[] confidential = OSSerializer.serializeConfidentialData(optionsUAndE[1], request.getPayload(), realCode);
		Encrypt0Message enc = prepareCOSEStructure(confidential);
		byte[] cipherText = encryptAndEncode(enc, ctx, request, false, null);

		// sets correct OSCORE option values here
		compression(ctx, cipherText, request, false);

		byte[] oscoreOption = request.getOptions().getOscore();

		// here the U options are set
		request.setOptions(OptionJuggle.postInstruction(optionsUAndE[0], instructions));
		request.getOptions().setOscore(oscoreOption);

		ctx.increaseSenderSeq();

		return request;
	}

}
