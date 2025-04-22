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

import java.util.Objects;

import org.apache.hc.client5.http.utils.Hex;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.elements.EndpointContext;
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

		byte[] oldOscoreOption = request.getOptions().getOscore(); // can be null
		CBORObject[] instructions = OptionEncoder.decodeCBORSequence(oldOscoreOption);
		
		System.out.println("in request encryptor");
		OSCoreCtx ctx = db.getContext(request, true);

		OptionSet options = request.getOptions();
		
		boolean instructionsExists = Objects.nonNull(instructions);
		/*
		if (instructionsExists && (int) instructions[1].ToObject(int.class) != 2) {
			System.out.println("adding from instructions");
			System.out.println(Hex.encodeHexString(oldOscoreOption));
			System.out.println(Hex.encodeHexString(options.getOscore()));
			System.out.println(Hex.encodeHexString(instructions[0].ToObject(byte[].class)));

			options.setOscore(instructions[0].ToObject(byte[].class));
		}
		else if (db.getIfProxyable() && oldOscoreOption != null) {
			System.out.println(Hex.encodeHexString(oldOscoreOption));
			System.out.println(Hex.encodeHexString(options.getOscore()));
			System.out.println("adding from is proxy old option");
			options.setOscore(oldOscoreOption);
		}
		else {
			if (oldOscoreOption != null) {
				System.out.println(Hex.encodeHexString(oldOscoreOption));
			}
			if (options.getOscore() != null) {
				System.out.println(Hex.encodeHexString(options.getOscore()));
			}
			System.out.println("removing");
			options.removeOscore();
		}*/
		
		System.out.println("request options are: " + options);
		System.out.println("source context is: " + request.getSourceContext());

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


		OptionSet[] optionsUAndE = OptionJuggle.filterOptions(options);
		System.out.println("U OPTIONS ARE: " + optionsUAndE[0]);
		System.out.println("E OPTIONS ARE: " + optionsUAndE[1]);

		//if (instructionsExists) {
			OptionSet promotedOptions = OptionJuggle.promotion(optionsUAndE[0], instructions, true);
			System.out.println("U options:            " + optionsUAndE[0]);
			System.out.println("Promoted options are: " + promotedOptions);
			optionsUAndE[1] = OptionJuggle.merge(optionsUAndE[1], promotedOptions);	
		//}
				
		System.out.println("Eoptions are length: " + optionsUAndE[1]);
		
		System.out.println("payload is length: " + request.getPayload().length + " + 1 byte for payload marker");
		System.out.println("message code is: " + realCode + ", which should be 8 bits long, aka 1 byte");
		if (optionsUAndE[1].hasOscore()) {
			System.out.println("Total length is: " + (optionsUAndE[1].getOscore().length + 1 + request.getPayload().length + 1 + 1));
		}		// here the E options are set 
		byte[] confidential = OSSerializer.serializeConfidentialData(optionsUAndE[1], request.getPayload(), realCode);
		System.out.println("Confidential bytes are length: " + confidential.length);
		Encrypt0Message enc = prepareCOSEStructure(confidential);
		byte[] cipherText = encryptAndEncode(enc, ctx, request, false, null);
		System.out.println("Ciphertext is length: " + cipherText.length);
		// sets correct OSCORE option values here
		compression(ctx, cipherText, request, false);
		
		byte[] oscoreOption = request.getOptions().getOscore();

		// here the U options are set
		request.setOptions(optionsUAndE[0]);
		request.getOptions().setOscore(oscoreOption);
		
		ctx.increaseSenderSeq();

		return request;
	}

}
