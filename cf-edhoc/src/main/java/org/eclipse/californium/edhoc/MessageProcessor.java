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
import java.util.Map;

import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.Utils;

public class MessageProcessor {
	
    /**
     *  Determine the type of a received EDHOC message
     * @param msg   The received EDHOC message, as a CBOR sequence
     * @return  The type of the EDHOC message, or -1 if it not a recognized type
     */
	public static int messageType(byte[] msg) {
		
		if (msg == null)
			return -1;
		
		CBORObject[] myObjects = null;
		
		try {
			myObjects = CBORObject.DecodeSequenceFromBytes(msg);
		} catch (CBORException e) {
			System.err.println("Error while parsing the CBOR sequence\n");
			return -1;
		}
		
		if (myObjects == null)
			return -1;
		
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
     *  Process an EDHOC Message 1
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message1
     * @param edhocSession   The EDHOC session of this peer 
     *                       The map label is C_X, i.e. the connection identifier
     *                       offered to the other peer in the session, as a bstr_identifier
     * @return   A list of CBOR Objects including up to two elements.
     *           The first element is always present. It it is a CBOR byte string, with value
     *           the payload to send as response, for either EDHOC Message 2 or EDHOC Error Message.
     *           The second element is optional. If present, it is a CBOR byte string, with value
     *           the application data AD1 to deliver to the application.
     */
	public static List<CBORObject> readMessage1(byte[] sequence,
												List<Integer> supportedCiphersuites,
												Map<CBORObject, EdhocSession> edhocSessions) {
		
		boolean hasSuites = false; // Will be set to True if SUITES_I is present and valid for further inspection
		boolean hasCI = false;  // Will be set to True if C_I is present and valid
		boolean hasApplicationData = false; // Will be set to True if Application Data is present as AD1
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		// Elements composing the response to be sent back to the client, as CBOR object
		List<CBORObject> objectListResponse = new ArrayList<CBORObject>();
		
		// Serialization of the response to be sent back to the client
		byte[] responsePayload = new byte[] {};
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		String errMsg = null; // The text string to be possibly returned as ERR_MSG in an EDHOC Error Message
		CBORObject suitesR = null; // The SUITE_R element to be possibly returned as SUITES_R in an EDHOC Error Message
		

		CBORObject[] objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		
		/* Consistency checks */
		
		// METHOD_CORR
		if (objectListRequest[0].getType() != CBORType.Integer) {
			errMsg = new String("METHOD_CORR must be an integer");
			error = true;
		}
		
		// SUITES_I
		if (error == false &&
			objectListRequest[1].getType() != CBORType.Integer &&
			objectListRequest[1].getType() != CBORType.Array) {
				errMsg = new String("SUITES_I must be an integer or an array");
				error = true;
		}
		if (error == false &&
			objectListRequest[1].getType() == CBORType.Integer &&
			objectListRequest[1].AsInt32() < 0) {
				errMsg = new String("SUITES_I as an integer must be greater than 0");
				error = true;
		}
		if (error == false &&
			objectListRequest[1].getType() == CBORType.Array) {
				if (objectListRequest[1].size() < 2) {
					errMsg = new String("SUITES_I as an array must have at least 2 elements");
					error = true;
				}
				else {
					for (int i = 0; i < objectListRequest[1].size(); i++) {
						if(objectListRequest[1].get(i).getType() != CBORType.Integer) {
							errMsg = new String("SUITES_I as an array must have integers as elements");
							error = true;
							break;
						}
						if(objectListRequest[1].get(i).AsInt32() < 0) {
							errMsg = new String("SUITES_I as an array must have integers greater than 0");
							error = true;
							break;
						}
					}
				}
		}
		if (error == false) {
			hasSuites = true;
		}
		
		// G_X
		if (error == false &&
			objectListRequest[2].getType() != CBORType.ByteString) {
				errMsg = new String("G_X must be a byte string");
				error = true;
		}
		
		// C_I
		if (error == false &&
			objectListRequest[3].getType() != CBORType.ByteString &&
			objectListRequest[3].getType() != CBORType.Integer) {
				errMsg = new String("C_I must be a byte string or an integer");
				error = true;
		}
		if (error == false && Util.decodeFromBstrIdentifier(objectListRequest[3]) == null) {
			errMsg = new String("C_I must be encoded as a valid bstr_identifier");
			error = true;
		}
		if (error == false) {
			hasCI = true;
		}
		
		// AD_1
		if (error == false && objectListRequest.length == 5) {
			if (objectListRequest[4].getType() != CBORType.ByteString) {
				errMsg = new String("AD_1 must be a byte string");
				error = true;
			}
			else {
				hasApplicationData = true;
			}
		}
		
		// Prepare SUITES_R for a potential EDHOC Error Message to send
		if (hasSuites == true) {
			boolean includeSuitesR = false;
			int selectedCiphersuite;
			
			if (objectListRequest[1].getType() == CBORType.Integer) {
				selectedCiphersuite = objectListRequest[1].AsInt32();
				// This peer does not support the selected ciphersuite
				if (!supportedCiphersuites.contains(Integer.valueOf(selectedCiphersuite))) {
					includeSuitesR = true;
				}
			}
			
			else if (objectListRequest[1].getType() == CBORType.Array) {
				selectedCiphersuite = objectListRequest[1].get(0).AsInt32();
				// This peer does not support the selected ciphersuite
				if (!supportedCiphersuites.contains(Integer.valueOf(selectedCiphersuite))) {
					includeSuitesR = true;
				}
				
				if (includeSuitesR == false) {
					int selectedIndex = -1;
					// Find the position of the selected ciphersuite in the provided list
					for (int i = 1; i < objectListRequest[1].size(); i++) {
						if (objectListRequest[1].get(i).AsInt32() == selectedCiphersuite)
							selectedIndex = i;
					}
					// The selected ciphersuite was not in the provided list
					if (selectedIndex == -1) {
						includeSuitesR = true;
					}
					else {
						for (int i = 1; i < selectedIndex; i++) {
							int cs = objectListRequest[1].get(i).AsInt32();
							// This peer supports ciphersuites prior to the selected one in the provided list
							if (supportedCiphersuites.contains(Integer.valueOf(cs))) {
								includeSuitesR = true;
								break;
							}
						}
					}
				}

			}
			
			if (includeSuitesR == true) {
				error = true;
				// This peer supports only one ciphersuite
				if (supportedCiphersuites.size() == 1) {
					int cs = supportedCiphersuites.get(0).intValue();
					suitesR = CBORObject.FromObject(cs);
				}
				// This peer supports multiple ciphersuites
				else {
					suitesR = CBORObject.NewArray();
					for (Integer i : supportedCiphersuites) {
						suitesR.Add(i.intValue());
					}
				}
				// In either case, any supported ciphersuite from SUITES_I will also be included in SUITES_R
			}
			
		}
		
		
		/* Prepare an EDHOC Error Message */
		
		if (error == true) {
			// Possibly include C_I as C_X in the upcoming EDHOC Error Message to send
			if (hasCI == true) {
				int correlation = objectListRequest[3].AsInt32() % 4;
				if (correlation == 0 || correlation == 2)
					objectListResponse.add(CBORObject.FromObject(correlation));
			}
			
			// Include ERR_MSG in the EDHOC Error Message
			objectListResponse.add(CBORObject.FromObject(errMsg));

			// Possibly include SUITES_R
			if (suitesR != null) {
				objectListResponse.add(suitesR);
			}

			responsePayload = Util.buildCBORSequence(objectListResponse);
			processingResult.add(CBORObject.FromObject(responsePayload));
						
			System.out.println("Completed preparation of EDHOC Error Message");
			return processingResult;
			
		}
		
		
		/* Prepare an EDHOC Message 2 */
		
		// Send a dummy response to EDHOC Message 1
		String responseString = new String("Your payload was " + Utils.bytesToHex(sequence));
		responsePayload = responseString.getBytes(Constants.charset);
		
		// Serialized EDHOC Message 2
		processingResult.add(CBORObject.FromObject(responsePayload));
		
		// Application Data from AD_1 (if present)
		if (hasApplicationData == true) {
			processingResult.add(objectListRequest[4]);
		}
		
		System.out.println("Completed preparation of EDHOC Message 1");
		return processingResult;
		
	}
	
    /**
     *  Process an EDHOC Message2
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message2
     * @return  The elements of the EDHOC Message2 as CBOR objects, or null in case of errors
     */
	public static CBORObject[] readMessage2(byte[] sequence) {
		
		if (sequence == null)
			return null;
		
		return CBORObject.DecodeSequenceFromBytes(sequence);
		
	}
	
    /**
     *  Process an EDHOC Message3
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
		int[] suitesI = null;
		if (numSuites == 1) {
		    suitesI = new int[1];
		    suitesI[0] = session.getSupportedCipherSuites().get(0).intValue();
		}
		else {
		    int index = 1;
		    suitesI = new int[numSuites + 1];
		    suitesI[0] = session.getSupportedCipherSuites().get(0).intValue();
		    for (Integer i : session.getSupportedCipherSuites()) {
		        suitesI[index] = i.intValue();
		        index++;
		    }
		}
		
		byte[] gX = null;
		OneKey ephemeralKey = session.getEphemeralKey();
		if (ephemeralKey == null)
			return null;
		if (ephemeralKey.get(KeyKeys.KeyType) == KeyKeys.EC2_P256) {
			gX = ephemeralKey.get(KeyKeys.EC2_X).GetByteString();
		}
		else if (ephemeralKey.get(KeyKeys.KeyType) == KeyKeys.OKP_X25519) {
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
	
}