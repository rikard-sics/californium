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

import java.io.ByteArrayInputStream;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

import org.apache.hc.client5.http.utils.Hex;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.oscore.group.InstructionIDRegistry;
import org.eclipse.californium.oscore.group.OptionEncoder;

/**
 * 
 * Decrypts an OSCORE encrypted Response.
 *
 */
public class ResponseDecryptor extends Decryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ResponseDecryptor.class);

	/**
	 * Decrypt the response.
	 *
	 * @param db the context database used
	 * @param response the response
	 * @param requestSequenceNr sequence number (Partial IV) from the request
	 *            (if encrypting a response)
	 * @param ctx the context from instructions, if any
	 * 
	 * @return the decrypted response
	 * 
	 * @throws OSException when decryption fails
	 * 
	 */
	public static Response decrypt(OSCoreCtxDB db, Response response, int requestSequenceNr, CBORObject[] instructions) throws OSException {
		discardEOptions(response);

		OSCoreCtx ctx;
		byte[] protectedData = response.getPayload();
		Encrypt0Message enc = null;
		Token token = response.getToken();
		boolean shouldHaveInnerOscoreOption = false;
		OptionSet uOptions = response.getOptions();
		int index = 0;

		if (token == null) {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new OSException(ErrorDescriptions.TOKEN_NULL);		
		}
		
		if (Objects.nonNull(instructions)) {
			index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);
			
			// get instruction
			CBORObject instruction = instructions[index];

			byte[] RID       = instruction.get(InstructionIDRegistry.KID).ToObject(byte[].class);
			byte[] IDCONTEXT = instruction.get(InstructionIDRegistry.IDContext).ToObject(byte[].class);

			ctx = db.getContext(RID, IDCONTEXT);

			if (index > InstructionIDRegistry.StartIndex) {
				shouldHaveInnerOscoreOption = true;
			}
		}
		else {
			ctx = db.getContextByToken(token);
		}
		
		if (ctx != null) {
			enc = decompression(protectedData, response);

		}
		else {
			LOGGER.error(ErrorDescriptions.TOKEN_INVALID);
			throw new OSException(ErrorDescriptions.TOKEN_INVALID);
		}
		
		// Retrieve Context ID (kid context)
		CBORObject kidContext = enc.findAttribute(CBORObject.FromObject(10));
		byte[] contextID = null;
		if (kidContext != null) {
			contextID = kidContext.GetByteString();
		}

		// Perform context re-derivation procedure if ongoing
		try {
			ctx = ContextRederivation.incomingResponse(db, ctx, contextID);
		} catch (OSException e) {
			LOGGER.error(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
			throw new OSException(ErrorDescriptions.CONTEXT_REGENERATION_FAILED);
		}

		//Check if parsing of response plaintext succeeds
		try {
			byte[] plaintext = decryptAndDecode(enc, response, ctx, requestSequenceNr);
			DatagramReader reader = new DatagramReader(new ByteArrayInputStream(plaintext));

			response = OptionJuggle.setRealCodeResponse(response,
					CoAP.ResponseCode.valueOf(reader.read(CoAP.MessageFormat.CODE_BITS)));

			// resets option so eOptions gets priority during parse
			response.setOptions(EMPTY);

			new UdpDataParser().parseOptionsAndPayload(reader, response);
			System.out.println("after parsing options and payload: " + response);

		} catch (Exception e) {
			LOGGER.error(ErrorDescriptions.DECRYPTION_FAILED);
			throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
		}


		OptionSet eOptions = response.getOptions();
		
		if (eOptions.hasOscore() && shouldHaveInnerOscoreOption) {
			// The message contains an inner OSCore option and it should
			System.out.println("Message has inner oscore and it should");
		}
		else if (!(eOptions.hasOscore()) && shouldHaveInnerOscoreOption) {
			// Message does not contain inner OSCore option but it should
			System.out.println("message does not contain inner oscore but it should");
			//remove outer oscore option to stop decrypting more
			uOptions.removeOscore();
			
		}
		else if (eOptions.hasOscore() && !shouldHaveInnerOscoreOption) {
			// Message has inner oscore without instructions
			System.out.println("Message has inner oscore without instructions");
			
			if (db.getIfProxyable()) {
				System.out.println("fine if we are proxy who forwards?"); // or reverse where client knows the server we stand in for			
			}
			else {
				LOGGER.warn("Maybe do throw error?");
				//System.out.println("WARNING maybe do throw error?");
			}
		}
		else {
			System.out.println("Message does not have inner oscore without instructions");
			System.out.println("Which is fine");
			//remove outer oscore option to stop decrypting more
			uOptions.removeOscore();
		}
		
		eOptions = OptionJuggle.merge(eOptions, uOptions);
		
		System.out.println("after decryptions, set " + eOptions + " as options on response");
		response.setOptions(eOptions);

		//Set information about the OSCORE context used in the endpoint context of this response
		OSCoreEndpointContextInfo.receivingResponse(ctx, response);

		return response;
	}
}
