/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
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
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;

/**
 * 
 * Applies EDHOC mechanics at stack layer.
 *
 */
public class EdhocLayer extends AbstractLayer {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(EdhocLayer.class);

	/**
	 * Map of existing EDHOC sessions
	 */
	Map<CBORObject, EdhocSession> edhocSessions;

	/**
	 * The OSCORE context database
	 */
	OSCoreCtxDB ctxDb;

	/**
	 * Build the EdhocLayer
	 * 
	 * @param ctxDb OSCORE context database
	 * @param edhocSessions map of current EDHOC sessions
	 */
	public EdhocLayer(OSCoreCtxDB ctxDb, Map<CBORObject, EdhocSession> edhocSessions) {
		this.ctxDb = ctxDb;
		this.edhocSessions = edhocSessions;

		LOGGER.warn("Initializing EDHOC layer");
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		LOGGER.warn("Sending request through EDHOC layer");

		if (request.getOptions().hasOscore() && request.getOptions().hasEdhoc()) {
			LOGGER.warn("Combined EDHOC+OSCORE request");
			
			
			// Retrieve the Security Context used to protect the request
			OSCoreCtx ctx = getContextForOutgoing(exchange);
			
			// DEBUG
			/*
			if (ctx == null) {
				System.out.println("Null");
			}
			else {
				System.out.println("Not Null");
			}
			*/
			
			// The connectionIdentifier C_R is the Recipient ID for this peer
			byte[] cR = ctx.getRecipientId();
			
			// Retrieve the EDHOC session associated to C_R and storing EDHOC message_3
			EdhocSession session = this.edhocSessions.get(CBORObject.FromObject(cR));
						
			// Extract CIPHERTEXT_3 as second element of EDHOC message_3
			byte[] message3 = session.getMessage3();
			CBORObject[] message3Elements = CBORObject.DecodeSequenceFromBytes(message3);
			byte[] ciphertext3 = message3Elements[1].GetByteString();
			
			// Original OSCORE payload from the request
			byte[] oldOscorePayload = request.getPayload();
			
			// DEBUG
			// Util.nicePrint("EDHOC+OSCORE: Message 3", message3);
			
			// DEBUG
			// Util.nicePrint("EDHOC+OSCORE: CIPHERTEXT_3", ciphertext3);
			
			// DEBUG
			// Util.nicePrint("EDHOC+OSCORE: Old OSCORE payload", oldOscorePayload);
			
			// Build the new OSCORE payload, as a CBOR sequence of two elements
			// 1. A CBOR byte string, i.e. EDHOC CIPHERTEXT_3 as is
			// 2. A CBOR byte string, with value the original OSCORE payload
			byte[] ciphertext3CBOR = CBORObject.FromObject(ciphertext3).EncodeToBytes();
			byte[] oldOscorePayloadCBOR = CBORObject.FromObject(oldOscorePayload).EncodeToBytes();
			byte[] newOscorePayload = new byte[ciphertext3CBOR.length + oldOscorePayloadCBOR.length];
			System.arraycopy(ciphertext3CBOR, 0, newOscorePayload, 0, ciphertext3CBOR.length);
			System.arraycopy(oldOscorePayloadCBOR, 0, newOscorePayload, ciphertext3CBOR.length, oldOscorePayloadCBOR.length);
			
			// DEBUG
			Util.nicePrint("EDHOC+OSCORE: New OSCORE payload", newOscorePayload);
			
			// Set the new OSCORE payload as payload of the EDHOC+OSCORE request
			request.setPayload(newOscorePayload);
			
		}
		
		super.sendRequest(exchange, request);
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {

		LOGGER.warn("Sending response through EDHOC layer");

		super.sendResponse(exchange, response);
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {

		LOGGER.warn("Receiving request through EDHOC layer");

		if (request.getOptions().hasEdhoc() && request.getOptions().hasOscore()) {
			LOGGER.warn("Combined EDHOC+OSCORE request");
			
			
			boolean error = false;
			byte[] errorMessage = new byte[] {};
			
			// Retrieve the received payload combining EDHOC CIPHERTEXT_3 and the real OSCORE payload
			byte[] oldPayload = request.getPayload();
			
			// CBOR objects included in the received CBOR sequence
			CBORObject[] receivedOjectList = CBORObject.DecodeSequenceFromBytes(oldPayload);
			
			if (receivedOjectList == null || receivedOjectList.length != 2) {
				error = true;
			}
			else if (receivedOjectList[0].getType() != CBORType.ByteString ||
					 receivedOjectList[1].getType() != CBORType.ByteString) {
				error = true;
			}
			
			// The EDHOC+OSCORE request is malformed
			if (error == true) {
				String responseString = new String("Invalid EDHOC+OSCORE request");
				errorMessage = responseString.getBytes(Constants.charset);
				Response errorResponse = new Response(ResponseCode.BAD_REQUEST);
				errorResponse.setPayload(errorMessage);
				exchange.sendResponse(errorResponse);
				return;
			}
			
			// Prepare the actual OSCORE request, by replacing the payload
			byte[] newPayload = receivedOjectList[1].GetByteString();
			request.setPayload(newPayload);
			
			
			// Rebuild the full EDHOC message_3

		    List<CBORObject> edhocObjectList = new ArrayList<>();
		    
		    // Add C_R, i.e. the 'kid' from the OSCORE option encoded as a bstr_identifier
			byte[] kid = getKid(request.getOptions().getOscore());
		    CBORObject cR = Util.encodeToBstrIdentifier(CBORObject.FromObject(kid));
		    edhocObjectList.add(cR);
		    
		    // Add CIPHERTEXT_3, i.e. the CBOR string as is from the received CBOR sequence
		    edhocObjectList.add(receivedOjectList[0]); // CIPHERTEXT_3
		    
		    // Assemble the full EDHOC message_3
		    byte[] edhocMessage3 = Util.buildCBORSequence(edhocObjectList);
		    
		    // Process EDHOC message_3
		    
		}
		
		super.receiveRequest(exchange, request);
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {

		LOGGER.warn("Receiving response through EDHOC layer");

		super.receiveResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.receiveEmptyMessage(exchange, message);
	}

	/**
	 * Returns the OSCORE Context that was used to protect this outgoing
	 * exchange (outgoing request or response).
	 * 
	 * @param e the exchange
	 * @return the OSCORE Context used to protect the exchange (if any)
	 */
	private OSCoreCtx getContextForOutgoing(Exchange e) {
		byte[] rid = e.getCryptographicContextID();
		if (rid == null) {
			return null;
		} else {
			return ctxDb.getContext(rid);
		}
	}

	/**
	 * Retrieve KID value from an OSCORE option.
	 * 
	 * @param oscoreOption the OSCORE option
	 * @return the KID value
	 */
	static byte[] getKid(byte[] oscoreOption) {
		if (oscoreOption.length == 0) {
			return null;
		}

		// Parse the flag byte
		byte flagByte = oscoreOption[0];
		int n = flagByte & 0x07;
		int k = flagByte & 0x08;
		int h = flagByte & 0x10;

		byte[] kid = null;
		int index = 1;

		// Partial IV
		index += n;

		// KID Context
		if (h != 0) {
			int s = oscoreOption[index];
			index += s + 1;
		}

		// KID
		if (k != 0) {
			kid = Arrays.copyOfRange(oscoreOption, index, oscoreOption.length);
		}

		return kid;
	}

}
