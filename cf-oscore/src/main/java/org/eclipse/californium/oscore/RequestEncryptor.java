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
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.oscore.group.GroupRecipientCtx;
import org.eclipse.californium.oscore.group.GroupSenderCtx;
import org.eclipse.californium.oscore.group.OptionEncoder;

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
	public static Request encrypt(OSCoreCtxDB db, Request request) throws OSException {

		String uri;
		if (request.getOptions().hasProxyUri()) {
			uri = request.getOptions().getProxyUri();
		} else {
			uri = request.getURI();
		}

		// TODO: Do I need this both here and in the ObjectSecurityLayer?
		// Check if parameters in the option was set by the application
		if (request.getOptions().getOscore() != null && request.getOptions().getOscore().length != 0) {
			// Use the URI from the option to find the correct context
			uri = OptionEncoder.getContextUri(request.getOptions().getOscore());
		}

		OSCoreCtx ctx = db.getContext(uri);
		
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

		OptionSet options = request.getOptions();
		byte[] confidential = OSSerializer.serializeConfidentialData(options, request.getPayload(), realCode);
		Encrypt0Message enc = prepareCOSEStructure(confidential);
		byte[] cipherText = encryptAndEncode(enc, ctx, request, false, null, null);
		
		// DET_REQ
		// If it is a deterministic request, switch to the Deterministic Sender Context
		boolean isDetReq = OptionEncoder.getDetReq(request.getOptions().getOscore());
		if (isDetReq) {
			ctx = ((GroupSenderCtx) ctx).getDeterministicSenderCtx();
		}
		
		compression(ctx, cipherText, request, false);

		request.setOptions(OptionJuggle.prepareUoptions(request.getOptions()));

		// DET_REQ
		// If it is a deterministic request, do not increment the Sender Sequence Number
		if (!isDetReq) {
			ctx.increaseSenderSeq();
		}
		
		// DET_REQ
		// If it is a deterministic request, force the outer code to FETCH
		if (isDetReq) {
			request = OptionJuggle.setFakeCodeDeterministicRequest(request);
		}
		
		if (ctx.isGroupContext()) {
			assert (ctx instanceof GroupSenderCtx);
		}
		
		return request;
	}

}
