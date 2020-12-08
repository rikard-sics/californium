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

import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

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
     *  Parse an EDHOC Message1
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message1
     * @return  The elements of the EDHOC Message1 as CBOR objects, or null in case of errors
     */
	public static CBORObject[] readMessage1(byte[] sequence) {
		
		if (sequence == null)
			return null;
		
		return CBORObject.DecodeSequenceFromBytes(sequence);
		
	}
	
    /**
     *  Parse an EDHOC Message2
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message2
     * @return  The elements of the EDHOC Message2 as CBOR objects, or null in case of errors
     */
	public static CBORObject[] readMessage2(byte[] sequence) {
		
		if (sequence == null)
			return null;
		
		return CBORObject.DecodeSequenceFromBytes(sequence);
		
	}
	
    /**
     *  Parse an EDHOC Message3
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message3
     * @return  The elements of the EDHOC Message3 as CBOR objects, or null in case of errors
     */
	public static CBORObject[] readMessage3(byte[] sequence) {
		
		if (sequence == null)
			return null;
		
		return CBORObject.DecodeSequenceFromBytes(sequence);
		
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
	
    /**
     *  Prepare an EDHOC Message 1
     * @param session   The EDHOC session associated to this EDHOC message
     * @param ad1   The auxiliary data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 1, or null in case of errors
     */
	public static byte[] writeMessage1(EdhocSession session, byte[] ad1) {
		
		if (session == null)
			return null;
		
		int methodCorr = session.getMethodCorr();
		if (methodCorr < 0 || methodCorr > 15)
			return null;
		
		int numSuites = session.getSupportedCipherSuites().size();
		if (numSuites == 0)
			return null;
		int[] suitesI = new int[numSuites];
		int suitNr = 0;
		for (Integer i : session.getSupportedCipherSuites()) {
			suitesI[suitNr] = i.intValue();
			suitNr++;
		}
		
		byte[] gX = null;
		OneKey ephemeralKey = session.getEphemeralKey();
		if (ephemeralKey == null)
			return null;
		if (ephemeralKey.get(KeyKeys.KeyType) == KeyKeys.EC2_P256) {
			gX = ephemeralKey.get(KeyKeys.EC2_X).GetByteString();
		}
		else if (ephemeralKey.get(KeyKeys.KeyType) == KeyKeys.OKP_Ed25519 ||
				 ephemeralKey.get(KeyKeys.KeyType) == KeyKeys.OKP_X25519) {
			gX = ephemeralKey.get(KeyKeys.OKP_X).GetByteString();
		}
		else {
			return null;
		}
		if (gX == null)
			return null;
		
		byte[] cI = session.getConnectionId();
		if (cI == null)
			return null;
		
		List<CBORObject> objectList = new ArrayList<CBORObject>();
		
		objectList.add(CBORObject.FromObject(methodCorr));
		if (suitesI.length == 1)
			objectList.add(CBORObject.FromObject(suitesI[0]));
		else
			objectList.add(CBORObject.FromObject(suitesI));
		objectList.add(CBORObject.FromObject(gX));
		objectList.add(Util.encodeToBstrIdentifier(CBORObject.FromObject(cI)));
		if (ad1 != null)
			objectList.add(CBORObject.FromObject(ad1));
		
		session.setCurrentStep(Constants.EDHOC_BEFORE_M1);
		
		return Util.buildCBORSequence(objectList);
		
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
	
}