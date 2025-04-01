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
		
		boolean instructionsExists = Objects.nonNull(instructions);
		
		
		OSCoreCtx ctx = db.getContext(request, true);

		EndpointContext srcCtx = request.getSourceContext();
		boolean isProxy = (srcCtx != null && srcCtx.entries().get(OSCoreEndpointContextInfo.FORWARD_PROXY_FLAG) != null );
		
		// what do when src endpoint is aware we are a reverse proxy?
		if (instructionsExists && (int) instructions[1].ToObject(int.class) != 2) {
			System.out.println("adding from instructions");
			request.getOptions().setOscore(instructions[0].ToObject(byte[].class));
		}
		else if (isProxy && oldOscoreOption != null) {
			System.out.println("adding from is proxy old option");
			request.getOptions().setOscore(oldOscoreOption);
		}
		else {
			System.out.println("removing");
			request.getOptions().removeOscore();
		}
		
		System.out.println("request options are: " + request.getOptions());
		System.out.println("source context is: " + request.getSourceContext());

/*
		
		if (srcCtx != null && srcCtx.entries().get(OSCoreEndpointContextInfo.FORWARD_PROXY_FLAG) != null ) {
			if (instructionsExists) { 
				System.out.println("instructions exist");
				if ((int) instructions[1].ToObject(int.class) != 2) {
					// set inner oscore option
					request.getOptions().setOscore(instructions[0].ToObject(byte[].class));
				}
				else {
					// do nothing and keep the old value
				}
				// this should be extended if proxy and wants to encrypt more, so it includes initial messages outermost
				// oscore option as the inner oscore option initially 
			}
		}
		
		
		else {
			*/
			/*
			try {// should have another check to see if proxy 
				// because a client who only encrypts once without instructions  
				// but includes a valid oscore option as the oscore option 
				// will set it to be included as inner although it shouldn't
				// perhaps another parameter? 
				
				//check if valid oscore option exists in options already
				OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(options.getOscore());
				System.out.println("Valid oscore option");
				System.out.println(Hex.encodeHexString(options.getOscore()));
				result[1].setOscore(options.getOscore());
			}
			catch (Exception e) {
				System.out.println("Invalid oscore option");
			}*/
		//}
		
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

		//remove from options, since it is handled either through instructions or compression
		options.removeObserve();
				
		//prepare options here, both E and U
		OptionSet[] optionsUAndE = OptionJuggle.prepareUandEOptions(options, instructions);
		// here the E options are set 
		byte[] confidential = OSSerializer.serializeConfidentialData(optionsUAndE[1], request.getPayload(), realCode);
		Encrypt0Message enc = prepareCOSEStructure(confidential);
		byte[] cipherText = encryptAndEncode(enc, ctx, request, false, null);
		
		// sets correct OSCORE option values here
		compression(ctx, cipherText, request, false);
		
		byte[] oscoreOption = request.getOptions().getOscore();

		// here the U options are set
		request.setOptions(optionsUAndE[0]);
		request.getOptions().setOscore(oscoreOption);
		//request.setOptions(OptionJuggle.prepareUoptions(request.getOptions()));
		
		ctx.increaseSenderSeq();

		return request;
	}

}
