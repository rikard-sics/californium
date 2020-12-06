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

import java.util.ArrayList;
import java.util.List;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

public class MessageProcessor {
	
    /**
     *  Determine the type of a received EDHOC message
     * @param msg   The received EDHOC message, as a CBOR sequence
     * @return  The type of the EDHOC message, or -1 if it not a recognized type
     */
	public static int messageType(byte[] msg) {
		
		if (msg == null)
			return -1;
		
		CBORObject[] myObjects = CBORObject.DecodeSequenceFromBytes(msg);
		int count = myObjects.length;
		
		if (count < 1 || count > 5)
			return -1;
		
		// First check if it is the EDHOC Error Message
		if (count == 1) {
			if (myObjects[0].getType() == CBORType.TextString)
				return Constants.EDHOC_ERROR_MESSAGE;
		}
		if (count == 2) {
			if (myObjects[0].getType() == CBORType.TextString || myObjects[1].getType() == CBORType.TextString)
				return Constants.EDHOC_ERROR_MESSAGE;
		}
		if (count == 3) {
			if (myObjects[1].getType() == CBORType.TextString)
				return Constants.EDHOC_ERROR_MESSAGE;
		}
		
		// It is not an EDHOC Error Message. Check for other message types.

		if (count == 5)
			return Constants.EDHOC_MESSAGE_1;

		if (count == 3)
			return Constants.EDHOC_MESSAGE_2;
		
		if (count == 1 || count == 2)
			return Constants.EDHOC_MESSAGE_3;
		
		if (count == 4) {
			if (myObjects[1].getType() == CBORType.Array || myObjects[1].getType() == CBORType.Integer)
				return Constants.EDHOC_MESSAGE_1;
			if (myObjects[1].getType() == CBORType.ByteString)
				return Constants.EDHOC_MESSAGE_2;
		}
		
		return -1;
		
	}
	
    /**
     *  Prepare an EDHOC Error Message
     * @param cX   Connection identifier of the other peer, encoded as a bstr_identifier. It can be null
     * @param errMsg   The error message, encoded as a CBOR text string
     * @param suitesR   The cipher suites that the Responder supports. It is not null only in response to EDHOC Message 1
     * @return  The raw payload to transmit as EDHOC Error Message, or null in case of errors
     */
	public static byte[] writeErrorMessage(CBORObject cX, CBORObject errMsg, CBORObject suitesR) {
		
		if (errMsg == null)
			return null;
		
		byte[] payload = null;
		List<CBORObject> objectList = new ArrayList<CBORObject>();
		
		if (cX != null)
			objectList.add(cX);
		
		objectList.add(errMsg);
		
		if (suitesR != null)
			objectList.add(suitesR);
		
		return payload;
		
	}
	
    /**
     *  Parse an EDHOC Error Message
     * @param sequence   The CBOR sequence used as paylod of the EDHOC Error Message
     * @return  The elements of the EDHOC Error Message as CBOR objects, or null in case of errors
     */
	public static CBORObject[] readErrorMessage(byte[] sequence) {
		
		if (sequence == null)
			return null;
		
		return CBORObject.DecodeSequenceFromBytes(sequence);
		
	}
	
}