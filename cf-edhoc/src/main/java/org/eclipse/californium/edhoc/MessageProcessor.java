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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.Utils;

public class MessageProcessor {
	
	private static final boolean debugPrint = true;
	
    /**
     *  Determine the type of a received EDHOC message
     * @param msg   The received EDHOC message, as a CBOR sequence
     * @param isReq   True if the EDHOC message to parse is a CoAP request, false if it is a CoAP response
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param cX   The connection identifier of this peer, it can be null and then it has to be retrieved from the message
     * @param appStatement   The applicability statement to use
     * @return  The type of the EDHOC message, or -1 if it not a recognized type
     */
	public static int messageType(byte[] msg, boolean isReq, Map<CBORObject, EdhocSession> edhocSessions,
			                      byte[] cX, AppStatement appStatement) {
		
		if (msg == null || appStatement == null)
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
		
		boolean useNullByte = appStatement.getUseNullByte();
				
		int count = myObjects.length;
		if (count == 0)
			return -1;
		
		// First check if it is an EDHOC Error Message
		boolean correlationFlag = appStatement.getCorrelation();
		
		if (isErrorMessage(myObjects, isReq, correlationFlag)) {
			return Constants.EDHOC_ERROR_MESSAGE;
		}
				
		// It is not an EDHOC Error Message. Check for other message types.

		
		if (correlationFlag == true) {
		// The used correlation is 1 or 2
		
			// It can be be message_3 or message_4
			if (count == 1 || count == 2) {
				return distinguishMessage3and4(myObjects, isReq, edhocSessions, cX, correlationFlag);
			}
			
			if (count == 3)
				return Constants.EDHOC_MESSAGE_2;
			
			// message_1 never starts with the CBOR simple value Null, i.e. the 0xf6 byte
			if (useNullByte == false) {
				if (count == 4) {
					
					if (myObjects[1].getType() == CBORType.Array || myObjects[1].getType() == CBORType.Integer) {
						if (!myObjects[0].equals(CBORObject.Null)) {
							// message_1 without EAD_1
							return Constants.EDHOC_MESSAGE_1;
						}
					}
					
					if (myObjects[1].getType() == CBORType.ByteString) {
						return Constants.EDHOC_MESSAGE_2;
					}
					
				}
				
				if (count >= 6 && !myObjects[0].equals(CBORObject.Null)) {
					// message_1 with EAD_1
					return Constants.EDHOC_MESSAGE_1;
				}
			}
			// message_1 always starts with the CBOR simple value Null, i.e. the 0xf6 byte
			else {
				if (count == 4)
					return Constants.EDHOC_MESSAGE_2;
				
				if (count == 5 || count >= 7) {
					// message_1 , without or with EAD_1, respectively
					if (myObjects[0].equals(CBORObject.Null))
						return Constants.EDHOC_MESSAGE_1;
				}
				
			}
		
		}
		else {
		// The used correlation is 0
		
			// It can be be message_3 or message_4
			if (count == 2) {
				return distinguishMessage3and4(myObjects, isReq, edhocSessions, cX, correlationFlag);
			}
			
			// message_1 never starts with the CBOR simple value Null, i.e. the 0xf6 byte
			if (useNullByte == false) {
				if (count == 4) {
					if (myObjects[1].getType() == CBORType.Array || myObjects[1].getType() == CBORType.Integer) {
						if (!myObjects[0].equals(CBORObject.Null)) {
							// message_1 without EAD_1
							return Constants.EDHOC_MESSAGE_1;
						}
					}
					if (myObjects[1].getType() == CBORType.ByteString)
						return Constants.EDHOC_MESSAGE_2;
				}
				
				if (count >= 6 && !myObjects[0].equals(CBORObject.Null))
					return Constants.EDHOC_MESSAGE_1;
			}
			// message_1 always starts with the CBOR simple value Null, i.e. the 0xf6 byte
			else {
				if (count == 4)
					return Constants.EDHOC_MESSAGE_2;
				
				if (count == 5 || count >= 7) {
					// message_1 , without or with EAD_1, respectively
					if (myObjects[0].equals(CBORObject.Null))
						return Constants.EDHOC_MESSAGE_1;
				}
				
			}
			
		}
			
		return -1;
		
	}
	
    /**
     *  Determine if a message is an EDHOC error message
     * @param myObjects   The message to check, as an array of CBOR objects extracted from a CBOR sequence
     * @param isReq   True if the message is a request, false otherwise
     * @param correlationFlag   True if the used correlation is 1 or 2, false if it is 0
     * @return  True if it is an EDHOC error message, or false otherwise
     */
	public static boolean isErrorMessage(CBORObject[] myObjects, boolean isReq, boolean correlationFlag) {
		
		int count = myObjects.length;

		if (correlationFlag == true) {
		// The used correlation is 1 or 2
		
			if (count == 2 && isReq == false) {
				if (myObjects[0].getType() == CBORType.Integer)
					return true;
			}
			
			if (count == 3 && isReq == true) {
				if (myObjects[1].getType() == CBORType.Integer)
					return true;
			}
		
		}
		else {
		// The used correlation is 0
			
			if (count == 3 && myObjects[1].getType() == CBORType.Integer)
				return true;
			
		}
		
		return false;
		
	}
	
    /**
     *  Determine if a message is an EDHOC error message
     * @param msg   The message to check, as a CBOR sequence
     * @param isReq   True if the message is a request, false otherwise
     * @param correlationFlag   True if the used correlation is 1 or 2, false if it is 0
     * @return  True if it is an EDHOC error message, or false otherwise
     */
	public static boolean isErrorMessage(byte[] msg, boolean isReq, boolean correlationFlag) {
		
		CBORObject[] myObjects = null;
		
		try {
			myObjects = CBORObject.DecodeSequenceFromBytes(msg);
		} catch (CBORException e) {
			System.err.println("Error while parsing the CBOR sequence\n");
			return false;
		}
		
		if (myObjects == null)
			return false;
		
		return isErrorMessage(myObjects, isReq, correlationFlag);
		
	}
	
    /**
     *  Determine if it is an EDHOC message_3 or message_4
     * @param myObjects   The message to check, as an array of CBOR objects extracted from a CBOR sequence
     * @param isReq   True if the EDHOC message to parse is a CoAP request, false if it is a CoAP response
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param cX   The connection identifier of this peer, it can be null and then it has to be retrieved from the message
     * @param correlationFlag   True if the used correlation is 1 or 2, false if it is 0
     * @return  The type of the parsed EDHOC message, or -1 in case of error
     */
	private static int distinguishMessage3and4(CBORObject[] myObjects, boolean isReq,
			                                  Map<CBORObject, EdhocSession> edhocSessions,
			                                  byte[] cX, boolean correlationFlag) {
		
		byte[] connectionIdentifier = null;
		int count = myObjects.length;
		
		// With Correlation 1
		// message_3 is a request [C_R, ENC]
		// message_4 is a response [ENC]
		
		// With Correlation 2
		// message_3 is a response [ENC]
		// message_4 is a request [C_I, ENC]
		
		if (correlationFlag == true) {
		// The used correlation is 1 or 2
			if (count == 1 && isReq == true)
				return -1;
			
			if (count == 2 && isReq == false)
				return -1;
		}
		else {
		// The used correlation is 0
			if (count != 2)
				return -1;
		}
		
		// Use the provided Connection Identifier to retrieve the EDHOC session.
		// This is the case for an incoming response message and for an outgoing request/response message
		if (cX != null) {
			connectionIdentifier = cX;
		}
		
		// The Connection Identifier to retrieve the EDHOC session was not provided.
		// This is the case for an incoming request message, where the Connection Identifier is the first element
		if (cX == null && count == 2) {
			if (myObjects[0].getType() == CBORType.ByteString ||
				myObjects[0].getType() == CBORType.Integer)  {
					CBORObject connectionIdentifierCBOR = Util.decodeFromBstrIdentifier(myObjects[0]);
					
					if (connectionIdentifierCBOR != null) {
						connectionIdentifier = connectionIdentifierCBOR.GetByteString();
					}
				}
		}
		
		if (connectionIdentifier != null) {
		
			EdhocSession session = edhocSessions.get(CBORObject.FromObject(connectionIdentifier));
		
			if (session != null) {
				boolean initiator = session.isInitiator();
				int currentStep = session.getCurrentStep();
				int correlation = session.getCorrelation();
				
				// Take the point of view of the Initiator
				if (initiator == true) {
					
					// The Initiator is the Client
					if (correlation == Constants.EDHOC_CORR_1) {
						if (isReq == true && currentStep == Constants.EDHOC_AFTER_M3)
							return Constants.EDHOC_MESSAGE_3;
						if (isReq == false && currentStep == Constants.EDHOC_SENT_M3)
							return Constants.EDHOC_MESSAGE_4;
					}
					// The Initiator is the Server
					if (correlation == Constants.EDHOC_CORR_2) {
						if (isReq == false && currentStep == Constants.EDHOC_AFTER_M3)
							return Constants.EDHOC_MESSAGE_3;
						if (isReq == true && currentStep == Constants.EDHOC_SENT_M3)
							return Constants.EDHOC_MESSAGE_4;
					}

				}
				
				// Take the point of view of the Responder
				if (initiator == false) {					

					// The Responder is the Server
					if (correlation == Constants.EDHOC_CORR_1) {
						if (isReq == true && currentStep == Constants.EDHOC_SENT_M2)
							return Constants.EDHOC_MESSAGE_3;
						if (isReq == false && currentStep == Constants.EDHOC_AFTER_M4)
							return Constants.EDHOC_MESSAGE_4;
					}
					// The Responder is the Client
					if (correlation == Constants.EDHOC_CORR_2) {
						if (isReq == false && currentStep == Constants.EDHOC_SENT_M2)
							return Constants.EDHOC_MESSAGE_3;
						if (isReq == true && currentStep == Constants.EDHOC_AFTER_M4)
							return Constants.EDHOC_MESSAGE_4;
					}
				
				}
				
			}
		
		}
		
		return -1;
		
	}
	
    /**
     *  Process an EDHOC Message 1
     * @param expectedCorr   The expected Correlation to see advertised in EDHOC Message 1 
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 1
     * @param supportedCipherSuites   The list of cipher suites supported by this peer 
     * @param appStatement   The applicability statement to use
     * @return   A list of CBOR Objects including up to two elements.
     * 
     *           The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC Message 2 can be prepared; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *             
     *           In case (i), the second element is optionally present as a CBOR array, with elements
     *           the same elements of the external authorization data EAD1 to deliver to the application.
     *           In case (ii), the second element is present as a CBOR integer,
     *           with value the CoAP response code to use for the EDHOC Error Message.
     */
	public static List<CBORObject> readMessage1(int expectedCorr,
												byte[] sequence,
												List<Integer> supportedCiphersuites,
												AppStatement appStatement) {
		
		if (sequence == null || supportedCiphersuites == null)
				return null;
		
		CBORObject[] ead1 = null; // Will be set if External Authorization Data is present as EAD1
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		// Serialization of the message to be sent back to the Initiator
		byte[] replyPayload = new byte[] {};
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		int correlation = -1; // The correlation indicated by METHOD_CORR, or left to -1 in case on invalid message
		CBORObject cI = null; // The Connection Identifier C_I, or left to null in case of invalid message
		CBORObject suitesR = null; // The SUITE_R element to be possibly returned as SUITES_R in an EDHOC Error Message
		

		CBORObject[] objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		int index = -1;
		
		/* Consistency checks */
		
    	if (appStatement == null) {
			errMsg = new String("Impossible to retrieve the applicability statement");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
    	}
    	else {
            // If indicated in the applicability statement, the first element
            // of message_1 is the CBOR simple value Null, i.e. the byte 0xf6
	    	if (appStatement.getUseNullByte()) {
	    		index++;
	    		if (!objectListRequest[index].equals(CBORObject.Null)) {
	    			errMsg = new String("The first element must be the CBOR simple value Null");
	    			responseCode = ResponseCode.BAD_REQUEST;
	    			error = true;
	    		}
	        }
    	}
		
    	
		// METHOD_CORR
    	index++;
    	if (error == false) {
			if (objectListRequest[index].getType() != CBORType.Integer) {
				errMsg = new String("METHOD_CORR must be an integer");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				// Check that the indicated correlation is as expected
				int methodCorr = objectListRequest[index].AsInt32(); 
				correlation = methodCorr % 4;
				if (correlation != expectedCorr) {
					errMsg = new String("Expected correlation " + expectedCorr + " but it was " + correlation);
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
				}
				// Check that the indicated authentication method is supported
				else {
			    	int method = methodCorr / 4;
			    	if (!appStatement.isAuthMethodSupported(method)) {
						errMsg = new String("Authentication method " + method + " is not supported");
						responseCode = ResponseCode.BAD_REQUEST;
						error = true;
			    	}
			    	
			    }
			}
		}
		
		// SUITES_I
		index++;
		if (error == false &&
			objectListRequest[index].getType() != CBORType.Integer &&
			objectListRequest[index].getType() != CBORType.Array) {
				errMsg = new String("SUITES_I must be an integer or an array");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false &&
			objectListRequest[index].getType() == CBORType.Integer &&
			objectListRequest[index].AsInt32() < 0) {
				errMsg = new String("SUITES_I as an integer must be greater than 0");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false &&
			objectListRequest[index].getType() == CBORType.Array) {
				if (objectListRequest[index].size() < 2) {
					errMsg = new String("SUITES_I as an array must have at least 2 elements");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
				}
				else {
					for (int i = 0; i < objectListRequest[index].size(); i++) {
						if(objectListRequest[index].get(i).getType() != CBORType.Integer) {
							errMsg = new String("SUITES_I as an array must have integers as elements");
							responseCode = ResponseCode.BAD_REQUEST;
							error = true;
							break;
						}
						if(objectListRequest[index].get(i).AsInt32() < 0) {
							errMsg = new String("SUITES_I as an array must have integers greater than 0");
							responseCode = ResponseCode.BAD_REQUEST;
							error = true;
							break;
						}
					}
				}
		}
		
		// Check if the selected ciphersuite is supported
		if (error == false) {
			int selectedCiphersuite;
			
			if (objectListRequest[index].getType() == CBORType.Integer) {
				selectedCiphersuite = objectListRequest[index].AsInt32();
				// This peer does not support the selected ciphersuite
				if (!supportedCiphersuites.contains(Integer.valueOf(selectedCiphersuite))) {
					errMsg = new String("The selected ciphersuite is not supported");
					errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
				}
			}
			
			else if (objectListRequest[index].getType() == CBORType.Array) {
				selectedCiphersuite = objectListRequest[index].get(0).AsInt32();
				// This peer does not support the selected ciphersuite
				if (!supportedCiphersuites.contains(Integer.valueOf(selectedCiphersuite))) {
					errMsg = new String("The selected ciphersuite is not supported");
					errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
				}
				
				else {
					int selectedIndex = -1;
					// Find the position of the selected ciphersuite in the provided list
					for (int i = 1; i < objectListRequest[index].size(); i++) {
						if (objectListRequest[index].get(i).AsInt32() == selectedCiphersuite)
							selectedIndex = i;
					}
					// The selected ciphersuite was not in the provided list
					if (selectedIndex == -1) {
						errMsg = new String("The selected ciphersuite is not in the provided list");
						errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
						responseCode = ResponseCode.BAD_REQUEST;
						error = true;
					}
					else {
						for (int i = 1; i < selectedIndex; i++) {
							int cs = objectListRequest[1].get(i).AsInt32();
							// This peer supports ciphersuites prior to the selected one in the provided list
							if (supportedCiphersuites.contains(Integer.valueOf(cs))) {
								errMsg = new String("Supported ciphersuites prior to the selected one in the provided list");
								errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
								responseCode = ResponseCode.BAD_REQUEST;
								error = true;
								break;
							}
						}
					}
				}

			}
			
		}
		
		// G_X
		index++;
		if (error == false &&
			objectListRequest[index].getType() != CBORType.ByteString) {
				errMsg = new String("G_X must be a byte string");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		
		// C_I
		index++;
		if (error == false &&
			objectListRequest[index].getType() != CBORType.ByteString &&
			objectListRequest[index].getType() != CBORType.Integer) {
				errMsg = new String("C_I must be a byte string or an integer");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false && Util.decodeFromBstrIdentifier(objectListRequest[index]) == null) {
			errMsg = new String("C_I must be encoded as a valid bstr_identifier");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		else {
			cI = objectListRequest[index];
		}
		
		// EAD_1
		index++;
		if (error == false && objectListRequest.length > index) {
			
			// EAD_1 has to start with a CBOR integer and includes at least 2 CBOR objects
			if ( (objectListRequest[index].getType() != CBORType.Integer) ||
				 (objectListRequest.length < (index+2)) ) {
				errMsg = new String("Malformed or invalid EAD_1");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				int length = objectListRequest.length - index;
				ead1 = new CBORObject[length];
				for (int i = index; i < length; i++) {
					// Make a hard copy
					byte[] serializedObject = objectListRequest[i].EncodeToBytes();
					CBORObject element = CBORObject.DecodeFromBytes(serializedObject);
					ead1[i] = element;
				}
			}
		}
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			
			// Prepare SUITES_R
			
			// In either case, any supported ciphersuite from SUITES_I will also be included in SUITES_R
			suitesR = Util.buildSuitesR(supportedCiphersuites);
			
			return processError(errorCode, Constants.EDHOC_MESSAGE_1, correlation, cI, errMsg, suitesR, responseCode);
			
		}
		
		
		/* Return an indication to prepare EDHOC Message 2, possibly with the provided External Authorization Data */
		
		// A CBOR byte string with zero length, indicating that the EDHOC Message 2 can be prepared
		processingResult.add(CBORObject.FromObject(replyPayload));
		
		// External Authorization Data from EAD_1 (if present)
		if (ead1 != null) {
			CBORObject eadArray = CBORObject.NewArray();
			for (int i = 0; i < ead1.length; i++) {
				eadArray.Add(ead1[i]);
			}
			processingResult.add(eadArray);
		}
		
		System.out.println("Completed processing of EDHOC Message 1");
		return processingResult;
		
	}
		
    /**
     *  Process an EDHOC Message 2
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 2
     * @param cI   The connection identifier of the Initiator; set to null if expected in the EDHOC Message 2
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param peerPublicKeys   The list of the long-term public keys of authorized peers
     * @param peerCredentials   The list of CRED of the long-term public keys of authorized peers
     * @param usedConnectionIds   The collection of already allocated Connection Identifiers
     * @return   A list of CBOR Objects including up to two elements.
     * 
     *           The first element is always present. It it is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC Message 3 can be prepared; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *             
     *           In case (i), the second element is optionally present as a CBOR array, with elements
     *           the same elements of the external authorization data EAD1 to deliver to the application.
	 *           In case (ii), the second element is present as a CBOR integer,
	 *           with value the CoAP response code to use for the EDHOC Error Message.
     */
	public static List<CBORObject> readMessage2(byte[] sequence, CBORObject cI, Map<CBORObject,
			                                    EdhocSession> edhocSessions, Map<CBORObject, OneKey> peerPublicKeys,
			                                    Map<CBORObject, CBORObject> peerCredentials, List<Set<Integer>> usedConnectionIds) {
		
		if (sequence == null || edhocSessions == null ||
		    peerPublicKeys == null || peerCredentials == null || usedConnectionIds == null)
			return null;
		
		CBORObject connectionIdentifier = null; // The Connection Identifier C_I
		
		CBORObject[] ead2 = null; // Will be set if External Authorization Data is present as EAD2
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		int correlation = -1; // The correlation to retrieve from the session, or left to -1 in case on invalid message
		CBORObject cR = null; // The Connection Identifier C_R, or left to null in case of invalid message
		EdhocSession session = null; // The session used for this EDHOC execution
		
		CBORObject[] objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		
		/* Consistency checks */
		
		int index = 0;
		
		if (cI == null && objectListRequest.length != 4) {
			errMsg = new String("C_I must be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		if (error == false && cI != null && objectListRequest.length != 3) {
			errMsg = new String("C_I must not be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		// C_I is present as first element
		if (error == false && cI == null) {
			if (error == false && objectListRequest[index].getType() != CBORType.ByteString &&
				objectListRequest[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_I must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
			
			if (error == false && Util.decodeFromBstrIdentifier(objectListRequest[index]) == null) {
				errMsg = new String("C_I must be encoded as a valid bstr_identifier");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				connectionIdentifier = Util.decodeFromBstrIdentifier(objectListRequest[index]);
				index++;
			}
		}
		
		if (error == false && cI != null) {
			connectionIdentifier = Util.decodeFromBstrIdentifier(cI);
		}
		
		if (error == false) {
			session = edhocSessions.get(connectionIdentifier);
			
			if (session == null) {
				errMsg = new String("EDHOC session not found");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else if (session.isInitiator() == false) {
				errMsg = new String("EDHOC Message 2 is intended only to an Initiator");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else if (session.getCurrentStep() != Constants.EDHOC_SENT_M1) {
				errMsg = new String("The protocol state is not waiting for an EDHOC Message 2");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				correlation = session.getCorrelation();
			}
		}
		
		// G_Y
		if (error == false && objectListRequest[index].getType() != CBORType.ByteString) {
				errMsg = new String("G_Y must be a byte string");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false) {
			// Set the ephemeral public key of the Responder
			OneKey peerEphemeralKey = null;
			
			byte[] gY = objectListRequest[index].GetByteString();
	    	if (debugPrint) {
	    		Util.nicePrint("G_Y", gY);
	    	}
			int selectedCipherSuite = session.getSelectedCiphersuite();
			
			if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_0 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_1) {
				peerEphemeralKey = SharedSecretCalculation.buildCurve25519OneKey(null, gY);
			}
			if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_2 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_3) {
				peerEphemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(null, gY, null);
			}
			
			if (peerEphemeralKey == null) {
				errMsg = new String("Invalid ephemeral public key G_Y");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				session.setPeerEphemeralPublicKey(peerEphemeralKey);
		    	if (debugPrint) {
		    		Util.nicePrint("PeerEphemeralKey", peerEphemeralKey.AsCBOR().EncodeToBytes());
		    	}
				index++;
			}
		}
		
		
		// C_R
		if (error == false) {
			cR = Util.decodeFromBstrIdentifier(objectListRequest[index]);
			
			if (cR == null) {
				errMsg = new String("Invalid format for the Connection Identifier C_R");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				session.setPeerConnectionId(cR.GetByteString());
				index++;
			}
		}
		
		
		// CIPHERTEXT_2
		byte[] ciphertext2 = null;
		if (error == false && objectListRequest[index].getType() != CBORType.ByteString) {
			errMsg = new String("CIPHERTEXT_2 must be a byte string");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		else {
			ciphertext2 = objectListRequest[index].GetByteString();
			session.setCiphertext2(ciphertext2);
		}
		
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
		}
		
		
		/* Decrypt CIPHERTEXT_2 */
			
        // Compute TH2
		
        byte[] th2 = null;
        byte[] message1 = session.getMessage1(); // message_1 as a CBOR sequence
        List<CBORObject> objectListData2 = new ArrayList<>();
        for (int i = 0; i < objectListRequest.length - 1; i++)
        	objectListData2.add(objectListRequest[i]);
        byte[] data2 = Util.buildCBORSequence(objectListData2); // data_2 as a CBOR sequence
        
        th2 = computeTH2(session, message1, data2);
        if (th2 == null) {
        	errMsg = new String("Error when computing TH2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_2", th2);
    	}
        session.setTH2(th2);
        session.cleanMessage1();
        
        
        // Compute the key material
		
        byte[] prk2e = null;
        byte[] prk3e2m = null;
        
        // Compute the Diffie-Hellman secret G_XY
        byte[] dhSecret = SharedSecretCalculation.generateSharedSecret(session.getEphemeralKey(),
        															   session.getPeerEphemeralPublicKey());
    	if (dhSecret == null) {
        	errMsg = new String("Error when computing the Diffie-Hellman secret G_XY");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("G_XY", dhSecret);
    	}
        
        // Compute PRK_2e
    	prk2e = computePRK2e(dhSecret);
    	dhSecret = null;
    	if (prk2e == null) {
        	errMsg = new String("Error when computing PRK_2e");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("PRK_2e", prk2e);
    	}
    	session.setPRK2e(prk2e);
    	
    	// Compute KEYSTREAM_2
    	byte[] keystream2 = computeKeystream2(session, ciphertext2.length);
    	if (keystream2 == null) {
        	errMsg = new String("Error when computing KEYSTREAM_2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("KEYSTREAM_2", keystream2);
    	}
		
    	// Compute the outer plaintext
    	
    	if (debugPrint && ciphertext2 != null) {
    		Util.nicePrint("CIPHERTEXT_2", ciphertext2);
    	}
    	byte[] outerPlaintext = Util.arrayXor(ciphertext2, keystream2);
    	if (debugPrint && outerPlaintext != null) {
    		Util.nicePrint("Plaintext retrieved from CIPHERTEXT_2", outerPlaintext);
    	}
    	
    	// Parse the outer plaintext as a CBOR sequence
    	CBORObject[] plaintextElementList = CBORObject.DecodeSequenceFromBytes(outerPlaintext);
	    
    	error = false;
    	if (plaintextElementList.length != 2 && plaintextElementList.length != 3) {
        	errMsg = new String("Invalid format of the content encrypted as CIPHERTEXT_2");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	else if (plaintextElementList[0].getType() != CBORType.ByteString &&
    			 plaintextElementList[0].getType() != CBORType.Integer &&
    			 plaintextElementList[0].getType() != CBORType.Map) {
        	errMsg = new String("ID_CRED_R must be a CBOR map or a bstr_identifier");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	else if (plaintextElementList[1].getType() != CBORType.ByteString) {
        	errMsg = new String("Signature_or_MAC_2 must be a byte string");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	else if (plaintextElementList.length > 2) {
    		if (plaintextElementList[2].getType() != CBORType.Integer || plaintextElementList.length < 4) {
	        	errMsg = new String("Malformed or invalid EAD_2");
	        	responseCode = ResponseCode.BAD_REQUEST;
	        	error = true;
    		}
    		else {
    	        int length = plaintextElementList.length - 2;
    	        ead2 = new CBORObject[length];
    	        for (int i = 2; i < length; i++) {
    	            // Make a hard copy
    	            byte[] serializedObject = plaintextElementList[i].EncodeToBytes();
    	            CBORObject element = CBORObject.DecodeFromBytes(serializedObject);
    	            ead2[i] = element;
    	        }
    		}
    	}
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	
    	
    	// Verify that the identity of the Responder is an allowed identity
    	CBORObject idCredR = CBORObject.NewMap();
    	CBORObject rawIdCredR = plaintextElementList[0];
    	error = false;
    	
    	// ID_CRED_R is a CBOR map with only 'kid', and only 'kid' was transported as bstr_identifier
    	if (rawIdCredR.getType() == CBORType.Integer) {
    		CBORObject kidCBOR = Util.decodeFromBstrIdentifier(rawIdCredR);
    		if (kidCBOR == null) {
	        	errMsg = new String("Invalid format for ID_CRED_R");
	        	responseCode = ResponseCode.BAD_REQUEST;
    			error = true;
    		}
    		else {
	    		idCredR.Add(HeaderKeys.KID.AsCBOR(), kidCBOR);
	    		
	    		if (!peerPublicKeys.containsKey(idCredR)) {
		        	errMsg = new String("The identity expressed by ID_CRED_R is not recognized");
		        	responseCode = ResponseCode.BAD_REQUEST;
	    			error = true;
	    		}
    		}
    	}
    	else if (rawIdCredR.getType() == CBORType.ByteString) {
    		
    		// First check the case where ID_CRED_R is a CBOR map with only 'kid', and only 'kid' was transported as bstr_identifier
    		CBORObject kidCBOR = Util.decodeFromBstrIdentifier(rawIdCredR);
    		if (kidCBOR != null) {
    			idCredR.Add(HeaderKeys.KID.AsCBOR(), kidCBOR);
    		}
    		if (!peerPublicKeys.containsKey(idCredR)) {
    			// If not found yet, check the case where the byte string is the serialization of a whole CBOR map
    			// TODO: Again, this requires something better to ensure a deterministic encoding, if the map has more than 2 elements
    			idCredR = CBORObject.DecodeFromBytes(rawIdCredR.GetByteString());
    			
    			if (!peerPublicKeys.containsKey(idCredR)) {
		        	errMsg = new String("The identity expressed by ID_CRED_R is not recognized");
		        	responseCode = ResponseCode.BAD_REQUEST;
	    			error = true;
    			}
    		}
    	}
    	else if (rawIdCredR.getType() == CBORType.Map) {
    		idCredR = rawIdCredR;
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	
    	session.setPeerIdCred(idCredR);
    	OneKey peerKey = peerPublicKeys.get(idCredR);
    	session.setPeerLongTermPublicKey(peerKey);
    	
    	
    	// Compute PRK_3e2m
    	prk3e2m = computePRK3e2m(session, prk2e);
    	if (prk3e2m == null) {
        	errMsg = new String("Error when computing PRK_3e2m");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
	    		Util.nicePrint("PRK_3e2m", prk3e2m);
    	}
    	session.setPRK3e2m(prk3e2m);
    	
    	
    	// Compute K_2m and IV_2m to protect the inner COSE object

    	byte[] k2m = computeKey(Constants.EDHOC_K_2M, session);
    	if (k2m == null) {
        	errMsg = new String("Error when computing K_2M");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_2m", k2m);
    	}

    	byte[] iv2m = computeIV(Constants.EDHOC_IV_2M, session);
    	if (iv2m == null) {
        	errMsg = new String("Error when computing IV_2M");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV_2m", iv2m);
    	}
    	
    	
    	// Compute MAC_2
    	
    	CBORObject peerCredentialCBOR = peerCredentials.get(idCredR);
    	if (peerCredentialCBOR == null) {
        	errMsg = new String("Unable to retrieve the peer credential");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	byte[] peerCredential = peerCredentialCBOR.GetByteString();
    	
    	// Prepare the External Data
    	byte[] externalData = computeExternalData(th2, peerCredential, ead2);
    	if (externalData == null) {
        	errMsg = new String("Error when computing External Data for MAC_2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to compute MAC_2", externalData);
    	}
    	
        // Prepare the inner plaintext, as empty
        byte[] innerPlaintext = new byte[] {};
        
        
    	// Encrypt the inner COSE object and take the ciphertext as MAC_2

    	byte[] mac2 = computeMAC2(session.getSelectedCiphersuite(), idCredR,
    			                  externalData, innerPlaintext, k2m, iv2m);
    	if (mac2 == null) {
        	errMsg = new String("Error when computing MAC_2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_2", mac2);
    	}
        
    	
    	// Verify Signature_or_MAC_2
    	
    	byte[] signatureOrMac2 = plaintextElementList[1].GetByteString();
    	if (debugPrint && signatureOrMac2 != null) {
    		Util.nicePrint("Signature_or_MAC_2", signatureOrMac2);
    	}
        
    	if (!verifySignatureOrMac2(session, signatureOrMac2, externalData, mac2)) {
        	errMsg = new String("Non valid Signature_or_MAC_2");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation, cR, errMsg, null, responseCode);
    	}
		
		/* Return an indication to prepare EDHOC Message 3, possibly with the provided External Authorization Data */
		
		// A CBOR byte string with zero length, indicating that the EDHOC Message 3 can be prepared
		byte[] reply = new byte[] {};
		processingResult.add(CBORObject.FromObject(reply));
		
		// External Authorization from EAD_2 (if present)
		if (ead2 != null) {
		    CBORObject eadArray = CBORObject.NewArray();
		    for (int i = 0; i< ead2.length; i++) {
		        eadArray.Add(ead2[i]);
		    }
		    processingResult.add(eadArray);
		}
		
		System.out.println("Completed processing of EDHOC Message 2");
		return processingResult;
		
	}
	
    /**
     *  Process an EDHOC Message 3
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 3
     * @param cR   The connection identifier of the Responder; set to null if expected in the EDHOC Message 3
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param peerPublicKeys   The list of the long-term public keys of authorized peers
     * @param peerCredentials   The list of CRED of the long-term public keys of authorized peers
     * @param usedConnectionIds   The collection of already allocated Connection Identifiers
     * @return   A list of CBOR Objects including up to three elements.
     * 
     *           The first element is always present. It it is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the protocol has successfully completed; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *           
     *           In case (i), the second element is a CBOR byte string, and is relevant only if the protocol
     *           has successfully completed. In such a case, it specifies  the Connection Identifier
     *           of the Responder in the used EDHOC session, i.e. C_R.
     *           In case (ii), the second element is present as a CBOR integer,
     *           with value the CoAP response code to use for the EDHOC Error Message.
     *           
     *           The third element is optional and relevant only in case (i). If present, it is a CBOR array,
     *           with elements the same elements of the external authorization data EAD1 to deliver to the application.
     */
	public static List<CBORObject> readMessage3(byte[] sequence, CBORObject cR, Map<CBORObject,
            								EdhocSession> edhocSessions, Map<CBORObject, OneKey> peerPublicKeys,
            								Map<CBORObject, CBORObject> peerCredentials, List<Set<Integer>> usedConnectionIds) {
		
		if (sequence == null || edhocSessions == null ||
			peerPublicKeys == null || peerCredentials == null || usedConnectionIds == null)
			return null;
		
		CBORObject connectionIdentifier = null; // The Connection Identifier C_R
		
		CBORObject[] ead3 = null; // Will be set if External Authorization Data is present as EAD3
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		int correlation = -1; // The correlation to retrieve from the session, or left to -1 in case on invalid message
		CBORObject cI = null; // The Connection Identifier C_I, or left to null in case of invalid message
		EdhocSession session = null; // The session used for this EDHOC execution
		
		CBORObject[] objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		
		/* Consistency checks */
		
		int index = 0;
		
		if (cR == null && objectListRequest.length != 2) {
			errMsg = new String("C_R must be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		if (error == false && cR != null && objectListRequest.length != 1) {
			errMsg = new String("C_R must not be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		// C_R is present as first element
		if (error == false && cR == null) {
			if (error == false && objectListRequest[index].getType() != CBORType.ByteString &&
				objectListRequest[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_R must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
			
			if (error == false && Util.decodeFromBstrIdentifier(objectListRequest[index]) == null) {
				errMsg = new String("C_R must be encoded as a valid bstr_identifier");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				connectionIdentifier = Util.decodeFromBstrIdentifier(objectListRequest[index]);
				index++;
			}
		}
		
		if (error == false && cR != null) {
			connectionIdentifier = Util.decodeFromBstrIdentifier(cR);
		}
			
		if (error == false) {
			session = edhocSessions.get(connectionIdentifier);
			
			if (session == null) {
				errMsg = new String("EDHOC session not found");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else if (session.isInitiator() == true) {
				errMsg = new String("EDHOC Message 3 is intended only to a Responder");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else if (session.getCurrentStep() != Constants.EDHOC_SENT_M2) {
				errMsg = new String("The protocol state is not waiting for an EDHOC Message 3");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				correlation = session.getCorrelation();
			}
		}
		
		if (session != null) {
			if (session.getPeerConnectionId() != null)
				cI = CBORObject.FromObject(session.getPeerConnectionId());
		}
		
		
		// CIPHERTEXT_3
		byte[] ciphertext3 = null;
		if (error == false && objectListRequest[index].getType() != CBORType.ByteString) {
			errMsg = new String("CIPHERTEXT_3 must be a byte string");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		else {
			ciphertext3 = objectListRequest[index].GetByteString();
		}
		
		
		/* Send an EDHOC Error Message */
		
		if (error == true) {
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
		}
		
		
		/* Decrypt CIPHERTEXT_3 */
		
        // Compute TH3
        byte[] th2 = session.getTH2(); // TH_2 as plain bytes
        byte[] th2SerializedCBOR = CBORObject.FromObject(th2).EncodeToBytes();
        byte[] ciphertext2 = session.getCiphertext2(); // CIPHERTEXT_2 as plain bytes
        byte[] ciphertext2SerializedCBOR = CBORObject.FromObject(ciphertext2).EncodeToBytes(); 
        List<CBORObject> objectListData3 = new ArrayList<>();
        for (int i = 0; i < objectListRequest.length - 1; i++)
        	objectListData3.add(objectListRequest[i]);
        byte[] data3 = Util.buildCBORSequence(objectListData3); // data_3 as a CBOR sequence
        
        byte[] th3 = computeTH3(session, th2SerializedCBOR, ciphertext2SerializedCBOR, data3);
        if (th3 == null) {
        	errMsg = new String("Error when computing TH3");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_3", th3);
    	}
        session.setTH3(th3);
		
		
    	// Compute K_3ae and IV_3ae to protect the outer COSE object
    	byte[] k3ae = computeKey(Constants.EDHOC_K_3AE, session);
    	if (k3ae == null) {
        	errMsg = new String("Error when computing TH3");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_3ae", k3ae);
    	}
    	
    	byte[] iv3ae = computeIV(Constants.EDHOC_IV_3AE, session);
    	if (iv3ae == null) {
        	errMsg = new String("Error when computing IV_3ae");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV_3ae", iv3ae);
    	}
    	
    	// Prepare the external_aad as including only TH3
    	byte[] externalData = th3;

    	
    	// Compute the outer plaintext
    	
    	if (debugPrint && ciphertext3 != null) {
    		Util.nicePrint("CIPHERTEXT_3", ciphertext3);
    	}

    	byte[] outerPlaintext = decryptCiphertext3(session, externalData, ciphertext3, k3ae, iv3ae);
    	if (outerPlaintext == null) {
        	errMsg = new String("Error when decrypting CIPHERTEXT_3");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("Plaintext retrieved from CIPHERTEXT_3", outerPlaintext);
    	}
    	
    	// Parse the outer plaintext as a CBOR sequence
    	CBORObject[] plaintextElementList = CBORObject.DecodeSequenceFromBytes(outerPlaintext);
    	
    	error = false;
    	if (plaintextElementList.length != 2 && plaintextElementList.length != 3) {
        	errMsg = new String("Invalid format of the content encrypted as CIPHERTEXT_3");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	else if (plaintextElementList[0].getType() != CBORType.ByteString &&
    			 plaintextElementList[0].getType() != CBORType.Integer &&
    			 plaintextElementList[0].getType() != CBORType.Map) {
        	errMsg = new String("ID_CRED_I must be a CBOR map or a bstr_identifier");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	else if (plaintextElementList[1].getType() != CBORType.ByteString) {
        	errMsg = new String("Signature_or_MAC_3 must be a byte string");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	else if (plaintextElementList.length > 2) {
    	    if (plaintextElementList[2].getType() != CBORType.Integer || plaintextElementList.length < 4) {
    	        errMsg = new String("Malformed or invalid EAD_3");
    	        responseCode = ResponseCode.BAD_REQUEST;
    	        error = true;
    	    }
    	    else {
    	        int length = plaintextElementList.length - 2;
    	        ead3 = new CBORObject[length];
    	        for (int i = 2; i < length; i++) {
    	            // Make a hard copy
    	            byte[] serializedObject = plaintextElementList[i].EncodeToBytes();
    	            CBORObject element = CBORObject.DecodeFromBytes(serializedObject);
    	            ead3[i] = element;
    	        }
    	    }
    	}
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	
    	// Verify that the identity of the Initiator is an allowed identity
    	CBORObject idCredI = CBORObject.NewMap();
    	CBORObject rawIdCredI = plaintextElementList[0];
    	error = false;
    	
    	// ID_CRED_I is a CBOR map with only 'kid', and only 'kid' was transported as bstr_identifier
    	if (rawIdCredI.getType() == CBORType.Integer) {
    		CBORObject kidCBOR = Util.decodeFromBstrIdentifier(rawIdCredI);
    		if (kidCBOR == null) {
	        	errMsg = new String("Invalid format for ID_CRED_I");
	        	responseCode = ResponseCode.BAD_REQUEST;
    			error = true;
    		}
    		else {
	    		idCredI.Add(HeaderKeys.KID.AsCBOR(), kidCBOR);
	    		
	    		if (!peerPublicKeys.containsKey(idCredI)) {
		        	errMsg = new String("The identity expressed by ID_CRED_I is not recognized");
		        	responseCode = ResponseCode.BAD_REQUEST;
	    			error = true;
	    		}
    		}
    	}
    	else if (rawIdCredI.getType() == CBORType.ByteString) {
    		
    		// First check the case where ID_CRED_R is a CBOR map with only 'kid', and only 'kid' was transported as bstr_identifier
    		CBORObject kidCBOR = Util.decodeFromBstrIdentifier(rawIdCredI);
    		if (kidCBOR != null) {
    			idCredI.Add(HeaderKeys.KID.AsCBOR(), kidCBOR);
    		}
    		if (!peerPublicKeys.containsKey(idCredI)) {
    			// If not found yet, check the case where the byte string is the serialization of a whole CBOR map
    			// TODO: Again, this requires something better to ensure a deterministic encoding, if the map has more than 2 elements
    			idCredI = CBORObject.DecodeFromBytes(rawIdCredI.GetByteString());
    			
    			if (!peerPublicKeys.containsKey(idCredI)) {
		        	errMsg = new String("The identity expressed by ID_CRED_I is not recognized");
		        	responseCode = ResponseCode.BAD_REQUEST;
	    			error = true;
    			}
    		}
    	}
    	else if (rawIdCredI.getType() == CBORType.Map) {
    		idCredI = rawIdCredI;
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	
    	session.setPeerIdCred(idCredI);
    	OneKey peerKey = peerPublicKeys.get(idCredI);
    	session.setPeerLongTermPublicKey(peerKey);

    	/* Start computing the inner COSE object */
    	
    	CBORObject peerCredentialCBOR = peerCredentials.get(idCredI);
    	if (peerCredentialCBOR == null) {
        	errMsg = new String("Unable to retrieve the peer credential");
        	responseCode = ResponseCode.BAD_REQUEST;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
    		return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	byte[] peerCredential = peerCredentialCBOR.GetByteString();
    	
        // Compute the external data for the external_aad, as a CBOR sequence
    	externalData = computeExternalData(th3, peerCredential, ead3);
    	if (externalData == null) {
    		errMsg = new String("Error when computing the external data for MAC_3");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
    		return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to compute MAC_3", externalData);
    	}
    	
        // Prepare the plaintext, as empty
        
        byte[] plaintext = new byte[] {};
        
        
        // Compute the key material
        
        byte[] prk4x3m = computePRK4x3m(session);
    	if (prk4x3m == null) {
    		errMsg = new String("Error when computing PRK_4x3m");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("PRK_4x3m", prk4x3m);
    	}
    	session.setPRK4x3m(prk4x3m);
        
    	
    	// Compute K_3m and IV_3m to protect the inner COSE object

    	byte[] k3m = computeKey(Constants.EDHOC_K_3M, session);
    	if (k3m == null) {
    		errMsg = new String("Error when computing K_3m");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_3m", k3m);
    	}
    	
    	byte[] iv3m = computeIV(Constants.EDHOC_IV_3M, session);
    	if (iv3m == null) {
    		errMsg = new String("Error when computing IV_3m");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV_3m", iv3m);
    	}
    	
    	
    	// Encrypt the inner COSE object and take the ciphertext as MAC_3

    	byte[] mac3 = computeMAC3(session.getSelectedCiphersuite(), idCredI, externalData, plaintext, k3m, iv3m);
    	if (mac3 == null) {
    		errMsg = new String("Error when computing MAC_3");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_3", mac3);
    	}
    	
    	
    	// Verify Signature_or_MAC_3
    	
    	byte[] signatureOrMac3 = plaintextElementList[1].GetByteString();
    	if (debugPrint && signatureOrMac3 != null) {
    		Util.nicePrint("Signature_or_MAC_3", signatureOrMac3);
    	}
    	if (!verifySignatureOrMac3(session, signatureOrMac3, externalData, mac3)) {
        	errMsg = new String("Non valid Signature_or_MAC_3");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
    	}
    	
    	
    	/* Compute TH4 */
    	
        byte[] th3SerializedCBOR = CBORObject.FromObject(th3).EncodeToBytes();
        byte[] ciphertext3SerializedCBOR = CBORObject.FromObject(ciphertext3).EncodeToBytes();
    	byte[] th4 = computeTH4(session, th3SerializedCBOR, ciphertext3SerializedCBOR);
        if (th4 == null) {
        	errMsg = new String("Error when computing TH_4");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
        	return processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation, cI, errMsg, null, responseCode);
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_4", th4);
    	}
        session.setTH4(th4);
    	
    	
    	/* Delete ephemeral keys and other temporary material */
    	
    	session.deleteTemporaryMaterial();
    	
    	
		/* Return an indication that the protocol is completed, possibly with the provided External Authorization Data */
		
		// A CBOR byte string with zero length, indicating that the protocol has successfully completed
		byte[] reply = new byte[] {};
		processingResult.add(CBORObject.FromObject(reply));
		
		// The Connection Identifier C_R used by the Responder
		processingResult.add(connectionIdentifier);
		
		// External Authorization Data from EAD_3 (if present)
		if (ead3 != null) {
		    CBORObject eadArray = CBORObject.NewArray();
		    for (int i = 0; i< ead3.length; i++) {
		        eadArray.Add(ead3[i]);
		    }
		    processingResult.add(eadArray);
		}
		
		session.setCurrentStep(Constants.EDHOC_AFTER_M3);
		
		System.out.println("Completed processing of EDHOC Message 3\n");
		return processingResult;
		
	}
	
	
    /**
     *  Process an EDHOC Message 4
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 4
     * @param cI   The connection identifier of the Initiator; set to null if expected in the EDHOC Message 4
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param usedConnectionIds   The collection of already allocated Connection Identifiers
     * @return   A list of CBOR Objects including up to two elements.
     * 
     * 			 The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC Message 4 was correct; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *             
     *           In case (ii), the second element is present as a CBOR integer,
     *           with value the CoAP response code to use for the EDHOC Error Message.
     */
	public static List<CBORObject> readMessage4(byte[] sequence, CBORObject cI,
			                                    Map<CBORObject,EdhocSession> edhocSessions,
			                                    List<Set<Integer>> usedConnectionIds) {
		
		if (sequence == null || edhocSessions == null || usedConnectionIds == null)
			return null;
		
		CBORObject connectionIdentifier = null; // The Connection Identifier C_I
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		int correlation = -1; // The correlation to retrieve from the session, or left to -1 in case on invalid message
		CBORObject cR = null; // The Connection Identifier C_R, or left to null in case of invalid message
		EdhocSession session = null; // The session used for this EDHOC execution
		
		CBORObject[] objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		
		/* Consistency checks */
		
		int index = 0;
		
		if (cI == null && objectListRequest.length != 2) {
			errMsg = new String("C_I must be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		if (error == false && cI != null && objectListRequest.length != 1) {
			errMsg = new String("C_I must not be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		// C_I is present as first element
		if (error == false && cI == null) {
			if (error == false && objectListRequest[index].getType() != CBORType.ByteString &&
				objectListRequest[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_I must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
			
			if (error == false && Util.decodeFromBstrIdentifier(objectListRequest[index]) == null) {
				errMsg = new String("C_I must be encoded as a valid bstr_identifier");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				connectionIdentifier = Util.decodeFromBstrIdentifier(objectListRequest[index]);
				index++;
			}
		}
		
		if (error == false && cI != null) {
			connectionIdentifier = Util.decodeFromBstrIdentifier(cI);
		}
		
		if (error == false) {
			session = edhocSessions.get(connectionIdentifier);
			
			if (session == null) {
				errMsg = new String("EDHOC session not found");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else if (session.isInitiator() == false) {
				errMsg = new String("EDHOC Message 4 is intended only to an Initiator");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else if (session.getApplicabilityStatement().getUseMessage4() == false) {
				errMsg = new String("EDHOC Message 4 is not used for this applicability statement");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else if (session.getCurrentStep() != Constants.EDHOC_SENT_M3) {
				errMsg = new String("The protocol state is not waiting for an EDHOC Message 4");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				correlation = session.getCorrelation();
			}
		}
		
		if (session != null) {
			if (session.getPeerConnectionId() != null)
				cR = CBORObject.FromObject(session.getPeerConnectionId());
		}
		
		
		// MAC_4
		byte[] mac4 = null;
		if (error == false && objectListRequest[index].getType() != CBORType.ByteString) {
			errMsg = new String("MAC_4 must be a byte string");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		else {
			mac4 = objectListRequest[index].GetByteString();
			if (mac4 == null) {
				errMsg = new String("Error when retrieving MAC_4");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
		}
		
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_4, correlation, cR, errMsg, null, responseCode);
		}
		
		
		/* Start recomputing MAC_4 */
		
        // Compute the external data for the external_aad
		
        byte[] th4 = session.getTH4(); // TH_4 as plain bytes
    	byte[] externalData = null;
    	externalData = CBORObject.FromObject(th4).EncodeToBytes();

    	if (externalData == null) {
    		errMsg = new String("Error when computing the external data for MAC_4");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to compute MAC_4", externalData);
    	}
    	

        // Prepare the plaintext, as empty
        
        byte[] plaintext = new byte[] {};
    	
        
        // Compute the key material
      
    	// Compute K_4m and IV_4m to protect the inner COSE object
    	
    	byte[] k4m = computeKey(Constants.EDHOC_K_4M, session);
    	if (k4m == null) {
    		errMsg = new String("Error when computing K_4m");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_4m", k4m);
    	}

    	byte[] iv4m = computeIV(Constants.EDHOC_IV_4M, session);
    	if (iv4m == null) {
    		errMsg = new String("Error when computing IV_4m");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV_4m", iv4m);
    	}
        
		
    	// Encrypt the inner COSE object and take the ciphertext as MAC_4

    	byte[] recomputedMac4 = computeMAC4(session.getSelectedCiphersuite(), externalData, plaintext, k4m, iv4m);
    	if (recomputedMac4 == null) {
    		errMsg = new String("Error when computing MAC_4");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_4", recomputedMac4);
    	}
    	
        /* End recomputing MAC_4 */
    	
    	
    	// Verify MAC_4
    	
    	if (!Arrays.equals(recomputedMac4, mac4)) {
    		errMsg = new String("Non valid MAC_4");
    		responseCode = ResponseCode.BAD_REQUEST;
    		error = true;
    	}
    	
    	
    	// Return an EDHOC Error Message
    	if (error == true) {
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_4, correlation, cR, errMsg, null, responseCode);
    	}
    	
		
		/* Return an indication that message_4 is fine */
		
		// A CBOR byte string with zero length, indicating that the EDHOC Message 4 is fine
		byte[] reply = new byte[] {};
		processingResult.add(CBORObject.FromObject(reply));
				
    	session.setCurrentStep(Constants.EDHOC_AFTER_M4);
		
		System.out.println("Completed processing of EDHOC Message 4");
		return processingResult;
		
	}
	
	
    /**
     *  Parse an EDHOC Error Message
     * @param sequence   The CBOR sequence used as paylod of the EDHOC Error Message
     * @param cX   The connection identifier of the recipient; set to null if expected in the EDHOC Error Message
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @return  The elements of the EDHOC Error Message as CBOR objects, or null in case of errors
     */
	public static CBORObject[] readErrorMessage(byte[] sequence, CBORObject cX, Map<CBORObject, EdhocSession> edhocSessions) {
		
		if (edhocSessions == null || sequence == null) {
			System.err.println("Error when processing EDHOC Error Message");
			return null;
		}
		
		int index = 0;
		EdhocSession mySession = null;
		CBORObject[] objectList = CBORObject.DecodeSequenceFromBytes(sequence);
		
		if (objectList.length == 0 || objectList.length > 3) {
			System.err.println("Error when processing EDHOC Error Message - Zero or too many elements");
			return null;
		}
		
		// C_X is provided by the method caller
		if (cX != null) {
			mySession = edhocSessions.get(Util.decodeFromBstrIdentifier(cX));
		}
		
		// The connection identifier is expected as first element in the EDHOC Error Message
		else {
			
			if (objectList[index].getType() == CBORType.ByteString || objectList[index].getType() == CBORType.Integer) {
				mySession = edhocSessions.get(Util.decodeFromBstrIdentifier(objectList[index]));
				index++;		
			}
			else {
				System.err.println("Error when processing EDHOC Error Message - Invalid format of C_X");
				return null;
			}
			
		}
		
		// No session for this Connection Identifier
		if (mySession == null) {
			System.err.println("Error when processing EDHOC Error Message - Impossible to retrieve a session from C_X");
			return null;
		}
		
		boolean initiator = mySession.isInitiator();
		
		if (objectList[index].getType() != CBORType.Integer) {
			System.err.println("Error when processing EDHOC Error Message - Invalid format of ERR_CODE");
			return null;
		}
		
		// Retrieve ERR_CODE
		int errorCode = objectList[index].AsInt32();
		index++;
		
		// Check that the rest of the message is consistent
		if (objectList.length == index){
			System.err.println("Error when processing EDHOC Error Message - ERR_INFO expected but not included");
			return null;
		}
		if (objectList.length > (index + 1)){
			System.err.println("Error when processing EDHOC Error Message - Unexpected parameters following ERR_INFO");
			return null;
		}
		if (errorCode == Constants.ERR_CODE_SUCCESS) {
			// Do nothing
		}
		else if (errorCode == Constants.ERR_CODE_UNSPECIFIED) {
			if (objectList[index].getType() != CBORType.TextString) {
				System.err.println("Error when processing EDHOC Error Message - Invalid format of DIAG_MSG");
				return null;
			}
		}
		else if (errorCode == Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
			if (initiator == true && mySession.getCurrentStep() == Constants.EDHOC_SENT_M1) {
				if (objectList[index].getType() != CBORType.Array && objectList[index].getType() != CBORType.Integer) {
					System.err.println("Error when processing EDHOC Error Message - Invalid format for SUITES_R");
					return null;
				}
				if (objectList[index].getType() == CBORType.Array) {
					for (int i = 0; i < objectList[index].size(); i++) {
						if (objectList[index].get(i).getType() != CBORType.Integer) {
							System.err.println("Error when processing EDHOC Error Message - Invalid format for elements of SUITES_R");
							return null;
						}
					}
				}
			}
			else {
				System.err.println("Unexpected EDHOC Error Message with Error Code " +
								    Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE +
								    " (Wrong selected cipher suite)");
				return null;
			}
			
		}
		else {
			// Unknown error code
			System.err.println("Unknown error code in EDHOC Error Message: " + errorCode);
			return null;
		}
		
		return objectList;
		
	}
	
    /**
     *  Write an EDHOC Message 1
     * @param session   The EDHOC session associated to this EDHOC message
     * @param ead1   A CBOR array including the elements of the External Authorization Data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 1, or null in case of errors
     */
	public static byte[] writeMessage1(EdhocSession session, CBORObject[] ead1) {
		
        // Prepare the list of CBOR objects to build the CBOR sequence
        List<CBORObject> objectList = new ArrayList<>();
        
        // If indicated in the applicability statement, the first element
        // of message_1 is the CBOR simple value Null, i.e. the byte 0xf6
        AppStatement appStatement = session.getApplicabilityStatement(); 
    	if (appStatement == null) {
    		System.err.println("Impossible to retrieve the applicability statement");
    		return null;
    	}
        if (appStatement.getUseNullByte()) {
        	objectList.add(CBORObject.Null);
        }
        
        // METHOD_CORR as CBOR integer
        int methodCorr = session.getMethodCorr();
        objectList.add(CBORObject.FromObject(methodCorr));
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("EDHOC Message 1 content:\n");
        	CBORObject obj = CBORObject.FromObject(methodCorr);
        	byte[] objBytes = obj.EncodeToBytes();
        	Util.nicePrint("METHOD_CORR", objBytes);
        }
        
        // SUITES_I as CBOR integer or CBOR array
        List<Integer> supportedCiphersuites = session.getSupportedCipherSuites();
        List<Integer> peerSupportedCiphersuites = session.getPeerSupportedCipherSuites();
        
    	int selectedSuite = -1;
    	
    	// No SUITES_R has been received, so it is not known what ciphersuites the responder supports
    	if (peerSupportedCiphersuites == null) {
    		// The selected ciphersuite is the most preferred by the initiator
    		selectedSuite = supportedCiphersuites.get(0).intValue();
    	}
    	// SUITES_R has been received, so it is known what ciphersuites the responder supports
    	else {
    		// Pick the selected ciphersuite as the most preferred by the Initiator from the ones supported by the Responder
    		for (Integer i : supportedCiphersuites) {
    			if (peerSupportedCiphersuites.contains(i)) {
    				selectedSuite = i.intValue();
    				break;
    			}
    		}
    	}
    	if (selectedSuite == -1) {
    		System.err.println("Impossible to agree on a mutually supported ciphersuite");
    		return null;
    	}
    	
        if(supportedCiphersuites.size() == 1) {
        	objectList.add(CBORObject.FromObject(selectedSuite));
            if (debugPrint) {
            	CBORObject obj = CBORObject.FromObject(selectedSuite);
            	byte[] objBytes = obj.EncodeToBytes();
            	Util.nicePrint("SUITES_I", objBytes);
            }
        }
        else {
        	CBORObject myArray = CBORObject.NewArray();
        	myArray.Add(CBORObject.FromObject(selectedSuite));
        	for (int i = 0; i < supportedCiphersuites.size(); i++) {
        		int suiteListElement =  supportedCiphersuites.get(i).intValue();
        		myArray.Add(CBORObject.FromObject(suiteListElement));
        		
        		// SUITES_R has been received - Truncate the list of supported cipher suites, with the selected one as last one 
        		if (peerSupportedCiphersuites != null) {
        			if (suiteListElement == selectedSuite)
        				break;
        		}
        		
        	}
        	objectList.add(CBORObject.FromObject(myArray));
            if (debugPrint) {
            	CBORObject obj = CBORObject.FromObject(myArray);
            	byte[] objBytes = obj.EncodeToBytes();
            	Util.nicePrint("SUITES_I", objBytes);
            }
        }
                
        // The session has been reused, e.g. following an EDHOC Error Message
        // Generate new ephemeral key, according to the (updated) selected ciphersuite
        if (session.getFirstUse() == false) {
        	session.setEphemeralKey();
        }
        
        // G_X as a CBOR byte string
        CBORObject gX = null;
		if (selectedSuite == Constants.EDHOC_CIPHER_SUITE_0 || selectedSuite == Constants.EDHOC_CIPHER_SUITE_1) {
			gX = session.getEphemeralKey().PublicKey().get(KeyKeys.OKP_X);
		}
		else if (selectedSuite == Constants.EDHOC_CIPHER_SUITE_2 || selectedSuite == Constants.EDHOC_CIPHER_SUITE_3) {
			gX = session.getEphemeralKey().PublicKey().get(KeyKeys.EC2_X);
		}
		objectList.add(gX);
        if (debugPrint) {
        	CBORObject obj = CBORObject.FromObject(gX);
        	byte[] objBytes = obj.EncodeToBytes();
        	Util.nicePrint("G_X", objBytes);
        }
		
		// C_I as bstr_identifier
        byte[] connectionId = session.getConnectionId();
		CBORObject cI = CBORObject.FromObject(connectionId);
		objectList.add(Util.encodeToBstrIdentifier(cI));
        if (debugPrint) {
        	CBORObject obj = CBORObject.FromObject(Util.encodeToBstrIdentifier(cI));
        	byte[] objBytes = obj.EncodeToBytes();
        	Util.nicePrint("C_I", objBytes);
        }
        
        // EAD_1, if provided
        if (ead1 != null) {
        	for (int i = 0; i < ead1.length; i++)
        		objectList.add(ead1[i]);
        }
        if (debugPrint) {
        	System.out.println("===================================");
        }
		
        // Mark the session as used - Possible reusage will trigger the generation of new ephemeral keys
        session.setAsUsed();
        
        
    	/* Prepare EDHOC Message 1 */
    	
    	if (debugPrint) {
    		Util.nicePrint("EDHOC Message 1", Util.buildCBORSequence(objectList));
    	}
        
        return Util.buildCBORSequence(objectList);
		
	}

	
    /**
     *  Write an EDHOC Message 2
     * @param session   The EDHOC session associated to this EDHOC message
     * @param ead2   A CBOR array including the elements of the External Authorization Data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 2 or EDHOC Error Message; or null in case of errors
     */
	public static byte[] writeMessage2(EdhocSession session, CBORObject[] ead2) {
		
		List<CBORObject> objectList = new ArrayList<>();
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 2:\n");
        }
		
        /* Start preparing data_2 */
        
		// C_I as a bstr_identifier
		int correlationMethod = session.getCorrelation();
		if (correlationMethod == Constants.EDHOC_CORR_0 || correlationMethod == Constants.EDHOC_CORR_2) {
			CBORObject cI = CBORObject.FromObject(session.getPeerConnectionId());
			objectList.add(Util.encodeToBstrIdentifier(cI));
	        if (debugPrint) {
	        	CBORObject obj = CBORObject.FromObject(Util.encodeToBstrIdentifier(cI));
	        	byte[] objBytes = obj.EncodeToBytes();
	        	Util.nicePrint("C_I", objBytes);
	        }
		}
		
		// G_Y as a CBOR byte string
		int selectedSuite = session.getSelectedCiphersuite();
        CBORObject gY = null;
        if (selectedSuite == Constants.EDHOC_CIPHER_SUITE_0 || selectedSuite == Constants.EDHOC_CIPHER_SUITE_1) {
			gY = session.getEphemeralKey().PublicKey().get(KeyKeys.OKP_X);
		}
		else if (selectedSuite == Constants.EDHOC_CIPHER_SUITE_2 || selectedSuite == Constants.EDHOC_CIPHER_SUITE_3) {
			gY = session.getEphemeralKey().PublicKey().get(KeyKeys.EC2_X);
		}
		objectList.add(gY);
        if (debugPrint) {
        	Util.nicePrint("G_Y", gY.GetByteString());
        }
		
		// C_R as a bstr_identifier
		CBORObject cR = CBORObject.FromObject(session.getConnectionId());
		CBORObject obj = Util.encodeToBstrIdentifier(cR);
		objectList.add(obj);
        if (debugPrint) {
        	Util.nicePrint("C_R", obj.EncodeToBytes());
        }
		
        /* End preparing data_2 */
        
        
        /* Start computing the inner COSE object */
        
        // Compute TH_2
        
        byte[] message1 = session.getMessage1(); // message_1 as a CBOR sequence
        byte[] data2 = Util.buildCBORSequence(objectList); // data_2 as a CBOR sequence
        
        byte[] th2 = computeTH2(session, message1, data2);
        if (th2 == null) {
    		System.err.println("Error when computing TH_2");
    		errMsg = new String("Error when computing TH_2");
    		error = true;
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_2", th2);
    	}
        session.setTH2(th2);
        session.cleanMessage1();
        
        
        // Compute the external data for the external_aad, as a CBOR sequence
    	byte[] externalData = computeExternalData(th2, session.getCred(), ead2);
    	if (externalData == null) {
    		System.err.println("Error when computing the external data for MAC_2");
    		errMsg = new String("Error when computing the external data for MAC_2");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to compute MAC_2", externalData);
    	}
        
    	
        // Prepare the plaintext, as empty
        
        byte[] plaintext = new byte[] {};
        
        
        // Compute the key material
        
        byte[] prk2e = null;
        byte[] prk3e2m = null;
        
        // Compute the Diffie-Hellman secret G_XY
        byte[] dhSecret = SharedSecretCalculation.generateSharedSecret(session.getEphemeralKey(),
        		                                                       session.getPeerEphemeralPublicKey());
    	
        if (dhSecret == null) {
    		System.err.println("Error when computing the Diffie-Hellman Secret");
    		errMsg = new String("Error when computing the Diffie-Hellman Secret");
    		error = true;
        }
        else if (debugPrint) {
    		Util.nicePrint("G_XY", dhSecret);
    	}
        
        // Compute PRK_2e
    	prk2e = computePRK2e(dhSecret);
    	dhSecret = null;
    	if (prk2e == null) {
    		System.err.println("Error when computing PRK_2e");
    		errMsg = new String("Error when computing PRK_2e");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("PRK_2e", prk2e);
    	}
        session.setPRK2e(prk2e);
        
        // Compute PRK_3e2m
    	prk3e2m = computePRK3e2m(session, prk2e);
    	if (prk3e2m == null) {
    		System.err.println("Error when computing PRK_3e2m");
    		errMsg = new String("Error when computing PRK_3e2m");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("PRK_3e2m", prk3e2m);
    	}
    	session.setPRK3e2m(prk3e2m);
        
    	
    	// Compute K_2m and IV_2m to protect the inner COSE object    	

    	byte[] k2m = computeKey(Constants.EDHOC_K_2M, session);
    	if (k2m == null) {
    		System.err.println("Error when computing K_2m");
    		errMsg = new String("Error when computing K_2m");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_2m", k2m);
    	}
    	
    	byte[] iv2m = computeIV(Constants.EDHOC_IV_2M, session);
    	if (iv2m == null) {
    		System.err.println("Error when computing IV_2m");
    		errMsg = new String("Error when computing IV_2m");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV_2m", iv2m);
    	}
    	
    	
    	// Encrypt the inner COSE object and take the ciphertext as MAC_2

    	byte[] mac2 = computeMAC2(session.getSelectedCiphersuite(), session.getIdCred(), externalData, plaintext, k2m, iv2m);
    	if (mac2 == null) {
    		System.err.println("Error when computing MAC_2");
    		errMsg = new String("Error when computing MAC_2");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_2", mac2);
    	}
    	
    	
    	// Compute Signature_or_MAC_2
    	
    	byte[] signatureOrMac2 = computeSignatureOrMac2(session, mac2, externalData);
    	if (signatureOrMac2 == null) {
    		System.err.println("Error when computing Signature_or_MAC_2");
    		errMsg = new String("Error when computing Signature_or_MAC_2");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("Signature_or_MAC_2", signatureOrMac2);
    	}
    	
    	
        /* End computing the inner COSE object */
    
    	
    	/* Start computing CIPHERTEXT_2 */
    
    	// Prepare the plaintext
    	List<CBORObject> plaintextElementList = new ArrayList<>();
    	CBORObject plaintextElement = null;
    	if (session.getIdCred().size() == 1 && session.getIdCred().ContainsKey(HeaderKeys.KID.AsCBOR())) {
    		// ID_CRED_R is composed of only 'kid', which is the only thing to include, as a bstr_identifier
    		CBORObject kid = session.getIdCred().get(HeaderKeys.KID.AsCBOR());
    		plaintextElement = Util.encodeToBstrIdentifier(kid);
    	}
    	else {
    		// TODO: Again, this requires something better to ensure a deterministic encoding, if the map has more than 2 elements
    		plaintextElement = session.getIdCred();
    	}
    	plaintextElementList.add(plaintextElement);
    	plaintextElementList.add(CBORObject.FromObject(signatureOrMac2));
    	if (ead2 != null) {
    		for (int i = 0; i < ead2.length; i++)
    			plaintextElementList.add(ead2[i]);
    	}
    	plaintext = Util.buildCBORSequence(plaintextElementList);
    	if (debugPrint && plaintext != null) {
    		Util.nicePrint("Plaintext to compute CIPHERTEXT_2", plaintext);
    	}
    	
    	
    	// Compute KEYSTREAM_2
    	byte[] keystream2 = computeKeystream2(session, plaintext.length);
    	if (keystream2== null) {
    		System.err.println("Error when computing KEYSTREAM_2");
    		errMsg = new String("Error when computing KEYSTREAM_2");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("KEYSTREAM_2", keystream2);
    	}

    	
    	// Compute CIPHERTEXT_2 and add it to the outer CBOR sequence
    	
    	byte[] ciphertext2 = Util.arrayXor(plaintext, keystream2);
    	objectList.add(CBORObject.FromObject(ciphertext2));
    	session.setCiphertext2(ciphertext2);
    	if (debugPrint && ciphertext2 != null) {
    		Util.nicePrint("CIPHERTEXT_2", ciphertext2);
    	}
    	        
    	/* End computing CIPHERTEXT_2 */
    	
    	
		/* Prepare an EDHOC Error Message */
		
		if (error == true) {
			int correlation = session.getCorrelation();
			
			// Prepare C_I
			CBORObject cI = CBORObject.FromObject(session.getPeerConnectionId());
			
			// Prepare SUITES_R
			List<Integer> supportedCiphersuites = session.getSupportedCipherSuites();
			CBORObject suitesR = Util.buildSuitesR(supportedCiphersuites);
			
			List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_1, correlation,
															 cI, errMsg, suitesR, responseCode);
			return processingResult.get(0).GetByteString();
			
		}
    	
    	
    	/* Prepare EDHOC Message 2 */
    	
    	if (debugPrint) {
    		Util.nicePrint("EDHOC Message 2", Util.buildCBORSequence(objectList));
    	}
        return Util.buildCBORSequence(objectList);
		
	}
	
    /**
     *  Write an EDHOC Message 3
     * @param session   The EDHOC session associated to this EDHOC message
     * @param ead3   A CBOR array including the elements of the External Authorization Data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 3 or EDHOC Error Message; or null in case of errors
     */
	public static byte[] writeMessage3(EdhocSession session, CBORObject[] ead3) {
		
		List<CBORObject> objectList = new ArrayList<>();
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 3:\n");
        }
		
        /* Start preparing data_3 */
		
		// C_R as a bstr_identifier
		int correlationMethod = session.getCorrelation();
		if (correlationMethod == Constants.EDHOC_CORR_0 || correlationMethod == Constants.EDHOC_CORR_1) {
			CBORObject cR = CBORObject.FromObject(session.getPeerConnectionId());
			objectList.add(Util.encodeToBstrIdentifier(cR));
	        if (debugPrint) {
	        	CBORObject obj = CBORObject.FromObject(Util.encodeToBstrIdentifier(cR));
	        	byte[] objBytes = obj.EncodeToBytes();
	        	Util.nicePrint("C_R", objBytes);
	        }
		}
        
		/* End preparing data_3 */
		
		
		/* Start computing the inner COSE object */
		
        // Compute TH_3
        
        byte[] th2 = session.getTH2(); // TH_2 as plain bytes
        byte[] th2SerializedCBOR = CBORObject.FromObject(th2).EncodeToBytes();
        byte[] ciphertext2 = session.getCiphertext2(); // CIPHERTEXT_2 as plain bytes
        byte[] ciphertext2SerializedCBOR = CBORObject.FromObject(ciphertext2).EncodeToBytes(); 
        byte[] data3 = null;
        if (objectList.size() > 0) {
        	data3 = Util.buildCBORSequence(objectList); // data_3 as a CBOR sequence
        }

        byte[] th3 = computeTH3(session, th2SerializedCBOR, ciphertext2SerializedCBOR, data3);
        if (th3 == null) {
        	System.err.println("Error when computing TH_3");
    		errMsg = new String("Error when computing TH_3");
    		error = true;
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_3", th3);
    	}
        session.setTH3(th3);
		
    	
        // Compute the external data for the external_aad, as a CBOR sequence
    	
    	byte[] externalData = computeExternalData(th3, session.getCred(), ead3);
    	if (externalData == null) {
    		System.err.println("Error when computing the external data for MAC_3");
    		errMsg = new String("Error when computing the external data for MAC_3");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to compute MAC_3", externalData);
    	}
		
    	
        // Prepare the plaintext, as empty
        
        byte[] plaintext = new byte[] {};
    	
        
        // Compute the key material
        
        byte[] prk4x3m = computePRK4x3m(session);
    	if (prk4x3m == null) {
    		System.err.println("Error when computing PRK_4x3m");
    		errMsg = new String("Error when computing PRK_4x3m");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("PRK_4x3m", prk4x3m);
    	}
    	session.setPRK4x3m(prk4x3m);
        
    	
    	// Compute K_3m and IV_3m to protect the inner COSE object
    	
    	byte[] k3m = computeKey(Constants.EDHOC_K_3M, session);
    	if (k3m == null) {
    		System.err.println("Error when computing K_3m");
    		errMsg = new String("Error when computing K_3m");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_3m", k3m);
    	}

    	byte[] iv3m = computeIV(Constants.EDHOC_IV_3M, session);
    	if (iv3m == null) {
    		System.err.println("Error when computing IV_3m");
    		errMsg = new String("Error when computing IV_3m");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV_3m", iv3m);
    	}
        
		
    	// Encrypt the inner COSE object and take the ciphertext as MAC_3

    	byte[] mac3 = computeMAC3(session.getSelectedCiphersuite(), session.getIdCred(), externalData, plaintext, k3m, iv3m);
    	if (mac3 == null) {
    		System.err.println("Error when computing MAC_3");
    		errMsg = new String("Error when computing MAC_3");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_3", mac3);
    	}
    	
    	
    	// Compute Signature_or_MAC_3
    	
    	byte[] signatureOrMac3 = computeSignatureOrMac3(session, mac3, externalData);
    	if (signatureOrMac3 == null) {
    		System.err.println("Error when computing Signature_or_MAC_3");
    		errMsg = new String("Error when computing Signature_or_MAC_3");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("Signature_or_MAC_3", signatureOrMac3);
    	}
    	
    	
        /* End computing the inner COSE object */
    	
    	
    	/* Start computing CIPHERTEXT_3 */
    	
    	// Compute K_3ae and IV_3ae to protect the outer COSE object

    	byte[] k3ae = computeKey(Constants.EDHOC_K_3AE, session);
    	if (k3ae == null) {
    		System.err.println("Error when computing K_3ae");
    		errMsg = new String("Error when computing K_3ae");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_3ae", k3ae);
    	}
    	
    	byte[] iv3ae = computeIV(Constants.EDHOC_IV_3AE, session);
    	if (iv3ae == null) {
    		System.err.println("Error when computing IV_3ae");
    		errMsg = new String("Error when computing IV_3ae");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV_3ae", iv3ae);
    	}
    	    	
    	// Prepare the external_aad as including only TH3
    	externalData = th3;
    	
    	// Prepare the plaintext
    	List<CBORObject> plaintextElementList = new ArrayList<>();
    	CBORObject plaintextElement = null;
    	if (session.getIdCred().size() == 1 && session.getIdCred().ContainsKey(HeaderKeys.KID.AsCBOR())) {
    		// ID_CRED_I is composed of only 'kid', which is the only thing to include, as a bstr_identifier
    		CBORObject kid = session.getIdCred().get(HeaderKeys.KID.AsCBOR());
    		plaintextElement = Util.encodeToBstrIdentifier(kid);
    	}
    	else {
    		// TODO: Again, this requires something better to ensure a deterministic encoding, if the map has more than 2 elements
    		plaintextElement = session.getIdCred();
    	}
    	plaintextElementList.add(plaintextElement);
    	plaintextElementList.add(CBORObject.FromObject(signatureOrMac3));
    	if (ead3 != null) {
    		for (int i = 0; i < ead3.length; i++)
    			plaintextElementList.add(ead3[i]);
    	}    	
    	plaintext = Util.buildCBORSequence(plaintextElementList);
    	if (debugPrint && plaintext != null) {
    		Util.nicePrint("Plaintext to compute CIPHERTEXT_3", plaintext);
    	}
    	
    	
    	// Compute CIPHERTEXT_3 and add it to the outer CBOR sequence
    	
    	byte[] ciphertext3 = computeCiphertext3(session, externalData, plaintext, k3ae, iv3ae);
    	objectList.add(CBORObject.FromObject(ciphertext3));
    	if (debugPrint && ciphertext3 != null) {
    		Util.nicePrint("CIPHERTEXT_3", ciphertext3);
    	}
    	
    	/* End computing CIPHERTEXT_3 */
    	
    	
    	/* Compute TH4 */
    	
        byte[] th3SerializedCBOR = CBORObject.FromObject(th3).EncodeToBytes();
        byte[] ciphertext3SerializedCBOR = CBORObject.FromObject(ciphertext3).EncodeToBytes(); 
    	byte[] th4 = computeTH4(session, th3SerializedCBOR, ciphertext3SerializedCBOR);
        if (th4 == null) {
        	System.err.println("Error when computing TH_4");
    		errMsg = new String("Error when computing TH_4");
    		error = true;
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_4", th4);
    	}
    	session.setTH4(th4);
    	
    	session.setCurrentStep(Constants.EDHOC_AFTER_M3);
    	
    	
    	/* Delete ephemeral keys and other temporary material */
    	
    	session.deleteTemporaryMaterial();
    	
    	
    	/* Prepare an EDHOC Error Message */

    	if (error == true) {
    	    int correlation = session.getCorrelation();
    	    
    	    // Prepare C_R
    	    CBORObject cR = CBORObject.FromObject(session.getPeerConnectionId());
    	    
    	    List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_2, correlation,
    	    												 cR, errMsg, null, responseCode);
    	    return processingResult.get(0).GetByteString();
    	    
    	}
    	
    	
    	/* Prepare EDHOC Message 3 */
    	
    	if (debugPrint) {
    		Util.nicePrint("EDHOC Message 3", Util.buildCBORSequence(objectList));
    	}
    	
        return Util.buildCBORSequence(objectList);
		
	}
	
	
    /**
     *  Write an EDHOC Message 4
     * @param session   The EDHOC session associated to this EDHOC message
     * @return  The raw payload to transmit as EDHOC Message 4 or EDHOC Error Message; or null in case of errors
     */
	public static byte[] writeMessage4(EdhocSession session) {
		
		List<CBORObject> objectList = new ArrayList<>();
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 4:\n");
        }
		
        /* Start preparing data_4 */
		
		// C_I as a bstr_identifier
		int correlationMethod = session.getCorrelation();
		if (correlationMethod == Constants.EDHOC_CORR_0 || correlationMethod == Constants.EDHOC_CORR_2) {
			CBORObject cI = CBORObject.FromObject(session.getPeerConnectionId());
			objectList.add(Util.encodeToBstrIdentifier(cI));
	        if (debugPrint) {
	        	CBORObject obj = CBORObject.FromObject(Util.encodeToBstrIdentifier(cI));
	        	byte[] objBytes = obj.EncodeToBytes();
	        	Util.nicePrint("C_I", objBytes);
	        }
		}
        
		/* End preparing data_4 */
		
		
		/* Start computing the inner COSE object */
		
        // Compute the external data for the external_aad
		
        byte[] th4 = session.getTH4(); // TH_4 as plain bytes
    	byte[] externalData = null;
    	externalData = CBORObject.FromObject(th4).EncodeToBytes();

    	if (externalData == null) {
    		System.err.println("Error when computing the external data for MAC_4");
    		errMsg = new String("Error when computing the external data for MAC_4");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to compute MAC_4", externalData);
    	}
    	

        // Prepare the plaintext, as empty
        
        byte[] plaintext = new byte[] {};
    	
        
        // Compute the key material
      
    	// Compute K_4m and IV_4m to protect the inner COSE object
    	
    	byte[] k4m = computeKey(Constants.EDHOC_K_4M, session);
    	if (k4m == null) {
    		System.err.println("Error when computing K_4m");
    		errMsg = new String("Error when computing K_4m");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_4m", k4m);
    	}

    	byte[] iv4m = computeIV(Constants.EDHOC_IV_4M, session);
    	if (iv4m == null) {
    		System.err.println("Error when computing IV_4m");
    		errMsg = new String("Error when computing IV_4m");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV_4m", iv4m);
    	}
        
		
    	// Encrypt the inner COSE object and take the ciphertext as MAC_4

    	byte[] mac4 = computeMAC4(session.getSelectedCiphersuite(), externalData, plaintext, k4m, iv4m);
    	if (mac4 == null) {
    		System.err.println("Error when computing MAC_4");
    		errMsg = new String("Error when computing MAC_4");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_4", mac4);
    	}
    	
        /* End computing the inner COSE object */

    	
    	/* Prepare an EDHOC Error Message */

    	if (error == true) {
    	    int correlation = session.getCorrelation();
    	    
    	    // Prepare C_I
    	    CBORObject cI = CBORObject.FromObject(session.getPeerConnectionId());
    	    
    	    List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_3, correlation,
    	    												 cI, errMsg, null, responseCode);
    	    return processingResult.get(0).GetByteString();
    	    
    	}
    	
    	
    	/* Prepare EDHOC Message 4 */
    	
    	objectList.add(CBORObject.FromObject(mac4));
    	if (debugPrint) {
    		Util.nicePrint("EDHOC Message 4", Util.buildCBORSequence(objectList));
    	}
    	
    	session.setCurrentStep(Constants.EDHOC_AFTER_M4);
    	
        return Util.buildCBORSequence(objectList);
		
	}

	
    /**
     *  Write an EDHOC Error Message
     * @param errorCode   The error code for the EDHOC Error Message
     * @param replyTo   The message to which this EDHOC Error Message is intended to reply to
     * @param corr   The used correlation
     * @param cX   The connection identifier of the intended recipient of the EDHOC Error Message, it can be null
     * @param errMsg   The text string to include in the EDHOC Error Message
     * @param suitesR   The cipher suite(s) supported by the Responder, it can be null;
     *                  (MUST be present in response to EDHOC Message 1)
     * @return  The raw payload to transmit as EDHOC Error Message, or null in case of errors
     */
	public static byte[] writeErrorMessage(int errorCode, int replyTo, int corr,
			                               CBORObject cX, String errMsg, CBORObject suitesR) {
		
		if (replyTo != Constants.EDHOC_MESSAGE_1 && replyTo != Constants.EDHOC_MESSAGE_2 &&
			replyTo != Constants.EDHOC_MESSAGE_3 && replyTo != Constants.EDHOC_MESSAGE_4) {
				   return null;
		}
		
		if (suitesR != null && suitesR.getType() != CBORType.Integer && suitesR.getType() != CBORType.Array)
			return null;
		
		if (suitesR != null && suitesR.getType() == CBORType.Array) {
			for (int i = 0 ; i < suitesR.size(); i++) {
				if (suitesR.get(i).getType() != CBORType.Integer)
					return null;
			}
		}
		
		List<CBORObject> objectList = new ArrayList<CBORObject>();
		boolean includeIdentifier = false;
		byte[] payload;
			
		// Possibly include C_X - This might not have been included if the incoming EDHOC message was malformed
		if (cX != null) {
			
			if (replyTo == Constants.EDHOC_MESSAGE_1 || replyTo == Constants.EDHOC_MESSAGE_3) {
				if (corr == Constants.EDHOC_CORR_0 || corr == Constants.EDHOC_CORR_2) {
					includeIdentifier = true;
				}
			}
			else if (replyTo == Constants.EDHOC_MESSAGE_2 || replyTo == Constants.EDHOC_MESSAGE_4) {
				if (corr == Constants.EDHOC_CORR_0 || corr == Constants.EDHOC_CORR_1) {
					includeIdentifier = true;
				}
			}
		
			if (includeIdentifier == true) {		
				CBORObject bstrIdentifier = Util.encodeToBstrIdentifier(cX);
				objectList.add(CBORObject.FromObject(bstrIdentifier));
			}
			
		}

		// Include ERR_CODE
		objectList.add(CBORObject.FromObject(errorCode));
		
		// Include ERR_INFO
		if (errorCode == Constants.ERR_CODE_UNSPECIFIED) {
			if (errMsg == null)
				return null;
			
			// Include DIAG_MSG
			objectList.add(CBORObject.FromObject(errMsg));
		}
		else if (errorCode == Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
			if (replyTo != Constants.EDHOC_MESSAGE_1)
				return null;
			
			// Possibly include SUITES_R - This implies that EDHOC Message 1 was good enough and yielding a suite negotiation
			if (suitesR != null)
				objectList.add(suitesR);
		}
		
		
		// Encode the EDHOC Error Message, as a CBOR sequence
		payload = Util.buildCBORSequence(objectList);
		
		System.out.println("Completed preparation of EDHOC Error Message");
		
		return payload;
		
	}
	
	
    /**
     *  Prepare a list of CBOR objects to return, anticipating the sending of an EDHOC Error Message
     * @param errorCode   The error code for the EDHOC Error Message
     * @param replyTo   The message to which this EDHOC Error Message is intended to reply to
     * @param corr   The used correlation
     * @param cX   The connection identifier of the intended recipient of the EDHOC Error Message, it can be null
     * @param errMsg   The text string to include in the EDHOC Error Message
     * @param suitesR   The cipher suite(s) supported by the Responder (only in response to EDHOC Message 1), it can be null
     * @return  A list of CBOR objects, including the EDHOC Error Message and the CoAP response code to use
     */
	public static List<CBORObject> processError(int errorCode, int replyTo, int corr, CBORObject cX, String errMsg,
											    CBORObject suitesR, ResponseCode responseCode) {
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		byte[] replyPayload = writeErrorMessage(errorCode, replyTo, corr, cX, errMsg, suitesR);
		
		// EDHOC Error Message, as a CBOR byte string
		processingResult.add(CBORObject.FromObject(replyPayload));
		
		// CoAP response code as a CBOR integer
		processingResult.add(CBORObject.FromObject(responseCode.value));
		
		if (errMsg != null) {
			System.err.println(errMsg);
		}
		
		return processingResult;
		
	}
	
	
    /**
     *  Create a new EDHOC session as an Initiator
     * @param authenticationMethod   The authentication method signaled by the Initiator
     * @param correlationMethod   The correlation signaled by the Initiator
     * @param keyPair   The identity key of the Initiator
     * @param idCredI   ID_CRED_I for the identity key of the Initiator
     * @param credI   CRED_I for the identity key of the Initiator
     * @param supportedCipherSuites   The list of ciphersuites supported by the Initiator
     * @param usedConnectionIds   The list of allocated Connection Identifiers for the Initiator
     * @param appStatement   The applicability statement used for this session
     * @param epd   The processor of External Authentication Data used for this session
     * @return  The newly created EDHOC session
     */
	public static EdhocSession createSessionAsInitiator(int authenticationMethod, int correlationMethod,
												  OneKey keyPair, CBORObject idCredI, byte[] credI,
			  									  List<Integer> supportedCiphersuites,
			  									  List<Set<Integer>> usedConnectionIds,
			  									  AppStatement appStatement, EDP epd) {
		
		int methodCorr = (4 * authenticationMethod) + correlationMethod;
		
		//byte[] connectionId = Util.getConnectionId(usedConnectionIds, null);
		byte[] connectionId = new byte[] {(byte) 0x16}; // Forced and aligned with the test vector
		
        EdhocSession mySession = new EdhocSession(true, methodCorr, connectionId, keyPair,
        										  idCredI, credI, supportedCiphersuites, appStatement, epd);
		
		return mySession;
		
	}
	
    /**
     *  Create a new EDHOC session as a Responder
     * @param message1   The payload of the received EDHOC Message 1
     * @param keyPair   The identity key of the Responder
     * @param idCredR   ID_CRED_R for the identity key of the Responder
     * @param credR   CRED_R for the identity key of the Responder
     * @param supportedCipherSuites   The list of ciphersuites supported by the Responder
     * @param usedConnectionIds   The list of allocated Connection Identifiers for the Responder
     * @param appStatement   The applicability statement used for this session
     * @param epd   The processor of External Authentication Data used for this session
     * @return  The newly created EDHOC session
     */
	public static EdhocSession createSessionAsResponder(byte[] message1, OneKey keyPair, CBORObject idCredR, byte[] credR,
			  									  List<Integer> supportedCiphersuites, List<Set<Integer>> usedConnectionIds,
			  									  AppStatement appStatement, EDP epd) {
		
		CBORObject[] objectListMessage1 = CBORObject.DecodeSequenceFromBytes(message1);
		int index = -1;
		
		// Retrieve elements from EDHOC Message 1
		
	    // If indicated in the applicability statement, the first element
	    // of message_1 is the CBOR simple value Null, i.e. the byte 0xf6
	    if (appStatement.getUseNullByte()) {
	        index++;
	    }
		
		// METHOD_CORR
	    index++;
		int methodCorr = objectListMessage1[index].AsInt32();
		
		// Selected ciphersuites from SUITES_I
		index++;
		int selectedCipherSuite = -1;
		if (objectListMessage1[index].getType() == CBORType.Integer)
			selectedCipherSuite = objectListMessage1[index].AsInt32();
		else if (objectListMessage1[index].getType() == CBORType.Array)
			selectedCipherSuite = objectListMessage1[index].get(0).AsInt32();
		
		// G_X
		index++;
		byte[] gX = objectListMessage1[index].GetByteString();
		
		// C_I
		index++;
		byte[] cI = Util.decodeFromBstrIdentifier(objectListMessage1[index]).GetByteString();
		
		
		// Create a new EDHOC session
		
		//byte[] connectionId = Util.getConnectionId(usedConnectionIds, null);
		byte[] connectionId = new byte[] {(byte) 0x00}; // Forced and aligned with the test vector
		
		EdhocSession mySession = new EdhocSession(false, methodCorr, connectionId, keyPair,
												  idCredR, credR, supportedCiphersuites, appStatement, epd);
		
		// Set the selected cipher suite
		mySession.setSelectedCiphersuite(selectedCipherSuite);
		
		// Set the Connection Identifier of the peer
		mySession.setPeerConnectionId(cI);
		
		// Set the ephemeral public key of the initiator
		OneKey peerEphemeralKey = null;
		
		if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_0 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_1) {
			peerEphemeralKey = SharedSecretCalculation.buildCurve25519OneKey(null, gX);
		}
		if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_2 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_3) {
			peerEphemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(null, gX, null);
		}
		mySession.setPeerEphemeralPublicKey(peerEphemeralKey);
				
		// Store the EDHOC Message 1
		mySession.setMessage1(message1);
		
		return mySession;
		
	}
	
	
	/**
    *  Compute one of the temporary keys
    * @param keyName   The name of the key to compute
    * @param session   The used EDHOC session
    * @return  The computed key
    */
	public static byte[] computeKey(int keyName, EdhocSession session) {
	    
	    int keyLength = 0;
	    byte[] key = null;
	    
	    switch (session.getSelectedCiphersuite()) {
	        case Constants.EDHOC_CIPHER_SUITE_0:
	        case Constants.EDHOC_CIPHER_SUITE_1:
	        case Constants.EDHOC_CIPHER_SUITE_2:
	        case Constants.EDHOC_CIPHER_SUITE_3:
	            keyLength = 16;
	    }
	    if (keyLength == 0)
	        return null;
	    
	    key = new byte[keyLength];
	    String label = null;
	    
	    try {
	        switch(keyName) {
	            case Constants.EDHOC_K_2M:
	            	label = new String("K_2m");
	                key = session.edhocKDF(session.getPRK3e2m(), session.getTH2(), label, keyLength);
	                break;
	            case Constants.EDHOC_K_3M:
	            	label = new String("K_3m");
	                key = session.edhocKDF(session.getPRK4x3m(), session.getTH3(), label, keyLength);
	                break;
	            case Constants.EDHOC_K_3AE:
	            	label = new String("K_3ae");
	                key = session.edhocKDF(session.getPRK3e2m(), session.getTH3(), label, keyLength);
	                break;
	            case Constants.EDHOC_K_4M:
	            	label = new String("EDHOC_message_4_Key");
	                key = session.edhocExporter(label, keyLength);
	                break;
	            default:
	            	key = null;
	            	break;
	        }
	    } catch (InvalidKeyException e) {
	        System.err.println("Error when generating " + label + "\n" + e.getMessage());
	    } catch (NoSuchAlgorithmException e) {
	        System.err.println("Error when generating " + label + "\n" + e.getMessage());
	    }
	    
	    return key;
	    
	}
	
	
	/**
    *  Compute one of the temporary IVs
    * @param ivName   The name of the IV to compute
    * @param session   The used EDHOC session
    * @return  The computed key IV_2m
    */
	public static byte[] computeIV(int ivName, EdhocSession session) {
	    
	    int ivLength = 0;
	    byte[] iv = null;
	    
	    switch (session.getSelectedCiphersuite()) {
	        case Constants.EDHOC_CIPHER_SUITE_0:
	        case Constants.EDHOC_CIPHER_SUITE_1:
	        case Constants.EDHOC_CIPHER_SUITE_2:
	        case Constants.EDHOC_CIPHER_SUITE_3:
	            ivLength = 13;
	    }
	    if (ivLength == 0)
	        return null;
	    
	    iv = new byte[ivLength];
	    String label = null;
	    
	    try {
	        switch(ivName) {
            case Constants.EDHOC_IV_2M:
            	label = new String("IV_2m");
                iv = session.edhocKDF(session.getPRK3e2m(), session.getTH2(), label, ivLength);
                break;
            case Constants.EDHOC_IV_3M:
            	label = new String("IV_3m");
                iv = session.edhocKDF(session.getPRK4x3m(), session.getTH3(), label, ivLength);
                break;
            case Constants.EDHOC_IV_3AE:
            	label = new String("IV_3ae");
                iv = session.edhocKDF(session.getPRK3e2m(), session.getTH3(), label, ivLength);
                break;
            case Constants.EDHOC_IV_4M:
            	label = new String("EDHOC_message_4_Nonce");
                iv = session.edhocExporter(label, ivLength);
                break;
            default:
            	iv = null;
            	break;
        }
	    } catch (InvalidKeyException e) {
	    	System.err.println("Error when generating " + label + "\n" + e.getMessage());
	        return null;
	    } catch (NoSuchAlgorithmException e) {
	    	System.err.println("Error when generating " + label + "\n" + e.getMessage());
	        return null;
	    }
	    
	    return iv;
	    
	}

	
    /**
     *  Compute the keystream KEYSTREAM_2
     * @param session   The used EDHOC session
     * @param length   The desired length in bytes for the keystream KEYSTREAM_2
     * @return  The computed keystream KEYSTREAM_2
     */
	public static byte[] computeKeystream2(EdhocSession session, int length) {
		
		byte[] keystream2 = new byte[length];
		try {
			keystream2 = session.edhocKDF(session.getPRK2e(), session.getTH2(), "KEYSTREAM_2", length);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating KEYSTREAM_2\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating KEYSTREAM_2\n" + e.getMessage());
			return null;
		}

		return keystream2;
		
	}

	
    /**
     *  Compute the key PRK_2e
     * @param dhSecret   The Diffie-Hellman secret
     * @return  The computed key PRK_2e
     */
	public static byte[] computePRK2e(byte[] dhSecret) {
	
		byte[] prk2e = null;
	    try {
			prk2e = Hkdf.extract(new byte[] {}, dhSecret);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating PRK_2e\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating PRK_2e\n" + e.getMessage());
			return null;
		}
	    
	    return prk2e;
		
	}
	
	
    /**
     *  Compute the key PRK_3e2m
     * @param session   The used EDHOC session
     * @param prk2e   The key PRK_2e
     * @return  The computed key PRK_3e2m
     */
	public static byte[] computePRK3e2m(EdhocSession session, byte[] prk2e) {
		
		byte[] prk3e2m = null;
		int authenticationMethod = session.getMethod();
		
        if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_2) {
        	// The responder uses signatures as authentication method, then PRK_3e2m is equal to PRK_2e 
        	prk3e2m = new byte[prk2e.length];
        	System.arraycopy(prk2e, 0, prk3e2m, 0, prk2e.length);
        }
        else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_1 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_3) {
        		// The responder does not use signatures as authentication method, then PRK_3e2m has to be computed
            	byte[] dhSecret;
            	OneKey privateKey = null;
            	OneKey publicKey = null;
            	
            	if (session.isInitiator() == false) {
            		// Use the long-term key of the Responder as private key
                	OneKey identityKey = session.getLongTermKey();
                	
            		// Use the ephemeral key of the Initiator as public key
            		publicKey = session.getPeerEphemeralPublicKey();
            		
	            	if (identityKey.get(KeyKeys.OKP_Curve).AsInt32() == KeyKeys.OKP_Ed25519.AsInt32()) {
	                	// Convert the identity key from Edward to Montgomery form
	                	try {
	                		privateKey = SharedSecretCalculation.convertEd25519ToCurve25519(identityKey);
						} catch (CoseException e) {
							System.err.println("Error when converting the Responder identity key" + 
									           "from Edward to Montgomery format\n" + e.getMessage());
							return null;
						}
	            	}
	            	else {
	            		privateKey = identityKey;
	            	}
            	}
            	else if (session.isInitiator() == true) {
            		// Use the ephemeral key of the Initiator as private key
            		privateKey = session.getEphemeralKey();
            		
            		// Use the long-term key of the Responder as public key
            		OneKey peerIdentityKey = session.getPeerLongTermPublicKey();
            		
            		
	            	if (peerIdentityKey.get(KeyKeys.OKP_Curve).AsInt32() == KeyKeys.OKP_Ed25519.AsInt32()) {
	                	// Convert the identity key from Edward to Montgomery form
	                	try {
							publicKey = SharedSecretCalculation.convertEd25519ToCurve25519(peerIdentityKey);
						} catch (CoseException e) {
							System.err.println("Error when converting the Responder identity key" + 
									           "from Edward to Montgomery format\n" + e.getMessage());
							return null;
						}
	            	}
	            	else {
	            		publicKey = peerIdentityKey;
	            	}
	            	
            	}
            	
    			// Consistency check of key type and curve against the selected ciphersuite
            	int selectedCipherSuite = session.getSelectedCiphersuite();
            	
            	if (Util.checkDiffieHellmanKeyAgainstCiphersuite(privateKey, selectedCipherSuite) == false) {
            		System.err.println("Error when computing the Diffie-Hellman Secret");
            		return null;
            	}
            	if (Util.checkDiffieHellmanKeyAgainstCiphersuite(publicKey, selectedCipherSuite) == false) {
            		System.err.println("Error when computing the Diffie-Hellman Secret");
            		return null;
            	}
            	
            	dhSecret = SharedSecretCalculation.generateSharedSecret(privateKey, publicKey);
            	
                if (dhSecret == null) {
            		System.err.println("Error when computing the Diffie-Hellman Secret");
            		return null;
                }
            	
            	if (debugPrint) {
            		Util.nicePrint("G_RX", dhSecret);
            	}
            	try {
					prk3e2m = Hkdf.extract(prk2e, dhSecret);
				} catch (InvalidKeyException e) {
					System.err.println("Error when generating PRK_3e2m\n" + e.getMessage());
					return null;
				} catch (NoSuchAlgorithmException e) {
					System.err.println("Error when generating PRK_3e2m\n" + e.getMessage());
					return null;
				}
            	finally {
            		dhSecret = null;
            	}
    	}
        
        return prk3e2m;
        
	}
	
	
    /**
     *  Compute the key PRK_4x3m
     * @param session   The used EDHOC session
     * @return  The computed key PRK_4x3m
     */
	public static byte[] computePRK4x3m(EdhocSession session) {
		
		byte[] prk4x3m = null;
		byte[] prk3e2m = session.getPRK3e2m();
		int authenticationMethod = session.getMethod();
		
        if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_1) {
        	// The initiator uses signatures as authentication method, then PRK_4x3m is equal to PRK_3e2m 
        	prk4x3m = new byte[prk3e2m.length];
        	System.arraycopy(prk3e2m, 0, prk4x3m, 0, prk3e2m.length);
        }
        else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_2 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_3) {
        		// The initiator does not use signatures as authentication method, then PRK_4x3m has to be computed
            	byte[] dhSecret;
            	OneKey privateKey = null;
            	OneKey publicKey = null;
            	
            	if (session.isInitiator() == false) {
            		// Use the ephemeral key of the Responder as private key
                	privateKey = session.getEphemeralKey();
                	
            		// Use the long-term key of the Initiator as public key
            		OneKey identityKey = session.getPeerLongTermPublicKey();
            		
	            	if (identityKey.get(KeyKeys.OKP_Curve).AsInt32() == KeyKeys.OKP_Ed25519.AsInt32()) {
	                	// Convert the identity key from Edward to Montgomery form
	                	try {
	                		publicKey = SharedSecretCalculation.convertEd25519ToCurve25519(identityKey);
						} catch (CoseException e) {
							System.err.println("Error when converting the Responder identity key" + 
									           "from Edward to Montgomery format\n" + e.getMessage());
							return null;
						}
	            	}
	            	else {
	            		publicKey = identityKey;
	            	}
            	}
            	else if (session.isInitiator() == true) {
            		// Use the ephemeral key of the Responder as public key
            		publicKey = session.getPeerEphemeralPublicKey();
            		
            		// Use the long-term key of the Initiator as private key
            		OneKey identityKey = session.getLongTermKey();
            		
	            	if (identityKey.get(KeyKeys.OKP_Curve).AsInt32() == KeyKeys.OKP_Ed25519.AsInt32()) {
	                	// Convert the identity key from Edward to Montgomery form
	                	try {
							privateKey = SharedSecretCalculation.convertEd25519ToCurve25519(identityKey);
						} catch (CoseException e) {
							System.err.println("Error when converting the Responder identity key" + 
									           "from Edward to Montgomery format\n" + e.getMessage());
							return null;
						}
	            	}
	            	else {
	            		privateKey = identityKey;
	            	}
	            	
            	}
            	
            	dhSecret = SharedSecretCalculation.generateSharedSecret(privateKey, publicKey);
            	
                if (dhSecret == null) {
            		System.err.println("Error when computing the Diffie-Hellman Secret");
            		return null;
                }
            	
            	if (debugPrint) {
            		Util.nicePrint("G_IY", dhSecret);
            	}
            	try {
					prk4x3m = Hkdf.extract(prk3e2m, dhSecret);
				} catch (InvalidKeyException e) {
					System.err.println("Error when generating PRK_4x3m\n" + e.getMessage());
					return null;
				} catch (NoSuchAlgorithmException e) {
					System.err.println("Error when generating PRK_4x3m\n" + e.getMessage());
					return null;
				}
            	finally {
            		dhSecret = null;
            	}
    	}
        
        return prk4x3m;
        
	}	
	
	
    /**
     *  Compute External_Data_2 / External_Data_3 for computing/verifying Signature_or_MAC_2 and Signature_or_MAC_3
     * @param th   The transcript hash TH2 or TH3
     * @param cred   The CRED of the long-term public key of the caller
     * @param ad   The array of CBOR objects composing the External Authorization Data, it can be null
     * @return  The external data for computing/verifying Signature_or_MAC_2 and Signature_or_MAC_3, or null in case of error
     */
	public static byte[] computeExternalData(byte[] th, byte[] cred, CBORObject[] ead) {
		
		if (th == null || cred == null)
			return null;
		
		List<CBORObject> externalDataList = new ArrayList<>();
		
        // TH2 / TH3 is the first element of the CBOR Sequence
        byte[] thSerializedCBOR = CBORObject.FromObject(th).EncodeToBytes();
        externalDataList.add(CBORObject.FromObject(thSerializedCBOR));
        
        // CRED_R / CRED_I is the second element of the CBOR Sequence
        byte[] credSerializedCBOR = cred;
        externalDataList.add(CBORObject.FromObject(credSerializedCBOR));
        
        // EAD_2 / EAD_3 is the third element of the CBOR Sequence (if provided)
        if (ead != null) {
        	byte[] eadSequence = null;
        	List<CBORObject> objectList = new ArrayList<CBORObject>();
        	
	    	for (int i = 0; i < ead.length; i++) {
		    		objectList.add(ead[i]);
		    }
	    	// Rebuild how EAD was in the EDHOC message
		    eadSequence = Util.buildCBORSequence(objectList);
    		    	
            externalDataList.add(CBORObject.FromObject(eadSequence)); 
        }
		
		return Util.concatenateByteArrays(externalDataList);
		
	}
	
    /**
     *  Compute External_Data_4 for computing/verifying MAC_4
     * @param th   The transcript hash TH4
     * @return  The external data for computing/verifying MAC_4, or null in case of error
     */
	public static byte[] computeExternalData(byte[] th) {
		
		if (th == null)
			return null;
		
		// TH4 is the only element to consider 
        return CBORObject.FromObject(th).EncodeToBytes();
        
	}
	
    /**
     *  Compute MAC_2
     * @param session   The used EDHOC session
     * @param idCredR   The ID_CRED_R associated to the long-term public key of the Responder
     * @param externalData   The External Data for the encryption process
     * @param plaintext   The plaintext to encrypt
     * @param k2m   The encryption key
     * @param iv2m   The initialization vector
     * @return  The computed MAC_2
     */
	public static byte[] computeMAC2(int selectedCiphersuite, CBORObject idCredR, byte[] externalData,
			                         byte[] plaintext, byte[] k2m, byte[] iv2m) {
		
		
    	AlgorithmID alg = null;
    	byte[] mac2 = null;
    	switch (selectedCiphersuite) {
    		case Constants.EDHOC_CIPHER_SUITE_0:
    		case Constants.EDHOC_CIPHER_SUITE_2:
    			alg = AlgorithmID.AES_CCM_16_64_128;
    			break;
    		case Constants.EDHOC_CIPHER_SUITE_1:
    		case Constants.EDHOC_CIPHER_SUITE_3:
    			alg = AlgorithmID.AES_CCM_16_128_128;
    			break;
    	}
    	try {
			mac2 = Util.encrypt(idCredR, externalData, plaintext, alg, iv2m, k2m);
		} catch (CoseException e) {
			System.err.println("Error when computing MAC_2\n" + e.getMessage());
			return null;
		}
		
		return mac2;
		
	}
	
	
    /**
     *  Compute MAC_3
     * @param session   The used EDHOC session
     * @param idCredI   The ID_CRED_I associated to the long-term public key of the Initiator
     * @param externalData   The External Data for the encryption process
     * @param plaintext   The plaintext to encrypt
     * @param k3m   The encryption key
     * @param iv3m   The initialization vector
     * @return  The computed MAC_3
     */
	public static byte[] computeMAC3(int selectedCiphersuite, CBORObject idCredI, byte[] externalData,
			                         byte[] plaintext, byte[] k3m, byte[] iv3m) {
		
		
    	AlgorithmID alg = null;
    	byte[] mac3 = null;
    	switch (selectedCiphersuite) {
    		case Constants.EDHOC_CIPHER_SUITE_0:
    		case Constants.EDHOC_CIPHER_SUITE_2:
    			alg = AlgorithmID.AES_CCM_16_64_128;
    			break;
    		case Constants.EDHOC_CIPHER_SUITE_1:
    		case Constants.EDHOC_CIPHER_SUITE_3:
    			alg = AlgorithmID.AES_CCM_16_128_128;
    			break;
    	}
    	try {
			mac3 = Util.encrypt(idCredI, externalData, plaintext, alg, iv3m, k3m);
		} catch (CoseException e) {
			System.err.println("Error when computing MAC_3\n" + e.getMessage());
			return null;
		}
		
		return mac3;
		
	}
	
	
	
	
	
	
    /**
     *  Compute MAC_4
     * @param session   The used EDHOC session
     * @param externalData   The External Data for the encryption process
     * @param plaintext   The plaintext to encrypt
     * @param k4m   The encryption key
     * @param iv4m   The initialization vector
     * @return  The computed MAC_4
     */
	public static byte[] computeMAC4(int selectedCiphersuite, byte[] externalData,
			                         byte[] plaintext, byte[] k4m, byte[] iv4m) {
		
		
    	AlgorithmID alg = null;
    	byte[] mac4 = null;
    	switch (selectedCiphersuite) {
    		case Constants.EDHOC_CIPHER_SUITE_0:
    		case Constants.EDHOC_CIPHER_SUITE_2:
    			alg = AlgorithmID.AES_CCM_16_64_128;
    			break;
    		case Constants.EDHOC_CIPHER_SUITE_1:
    		case Constants.EDHOC_CIPHER_SUITE_3:
    			alg = AlgorithmID.AES_CCM_16_128_128;
    			break;
    	}
    	try {
			mac4 = Util.encrypt(null, externalData, plaintext, alg, iv4m, k4m);
		} catch (CoseException e) {
			System.err.println("Error when computing MAC_4\n" + e.getMessage());
			return null;
		}
		
		return mac4;
		
	}
	
	
	
	
	
	
	
    /**
     *  Compute CIPHERTEXT_3
     * @param session   The used EDHOC session
     * @param externalData   The External Data for the encryption process
     * @param plaintext   The plaintext to encrypt
     * @param k3ae   The encryption key
     * @param iv3ae   The initialization vector
     * @return  The computed CIPHERTEXT_3
     */
	public static byte[] computeCiphertext3(EdhocSession session, byte[] externalData,
			                                byte[] plaintext, byte[] k3ae, byte[] iv3ae) {
		
    	AlgorithmID alg = null;
    	byte[] ciphertext3 = null;
    	
    	int selectedCiphersuite = session.getSelectedCiphersuite();
    	switch (selectedCiphersuite) {
    		case Constants.EDHOC_CIPHER_SUITE_0:
    		case Constants.EDHOC_CIPHER_SUITE_2:
    			alg = AlgorithmID.AES_CCM_16_64_128;
    			break;
    		case Constants.EDHOC_CIPHER_SUITE_1:
    		case Constants.EDHOC_CIPHER_SUITE_3:
    			alg = AlgorithmID.AES_CCM_16_128_128;
    			break;
    	}
    	
    	// Prepare the empty content for the COSE protected header
    	CBORObject emptyMap = CBORObject.NewMap();
    	
    	try {
    		ciphertext3 = Util.encrypt(emptyMap, externalData, plaintext, alg, iv3ae, k3ae);
		} catch (CoseException e) {
			System.err.println("Error when computing CIPHERTEXT_3\n" + e.getMessage());
			return null;
		}
		
		return ciphertext3;
		
	}
	
	
    /**
     *  Decrypt CIPHERTEXT_3
     * @param session   The used EDHOC session
     * @param externalData   The External Data for the encryption process
     * @param plaintext   The ciphertext to decrypt
     * @param k3ae   The decryption key
     * @param iv3ae   The initialization vector
     * @return  The plaintext recovered from CIPHERTEXT_3
     */
	public static byte[] decryptCiphertext3(EdhocSession session, byte[] externalData,
			                                byte[] ciphertext, byte[] k3ae, byte[] iv3ae) {
		
    	AlgorithmID alg = null;
    	byte[] plaintext = null;
    	
    	int selectedCiphersuite = session.getSelectedCiphersuite();
    	switch (selectedCiphersuite) {
    		case Constants.EDHOC_CIPHER_SUITE_0:
    		case Constants.EDHOC_CIPHER_SUITE_2:
    			alg = AlgorithmID.AES_CCM_16_64_128;
    			break;
    		case Constants.EDHOC_CIPHER_SUITE_1:
    		case Constants.EDHOC_CIPHER_SUITE_3:
    			alg = AlgorithmID.AES_CCM_16_128_128;
    			break;
    	}
    	
    	// Prepare the empty content for the COSE protected header
    	CBORObject emptyMap = CBORObject.NewMap();
    	
    	try {
    		plaintext = Util.decrypt(emptyMap, externalData, ciphertext, alg, iv3ae, k3ae);
		} catch (CoseException e) {
			System.err.println("Error when decrypting CIPHERTEXT_3\n" + e.getMessage());
			return null;
		}
		
		return plaintext;
		
	}
	
	
    /**
     *  Compute Signature_or_MAC_2 - Only for the Responder
     * @param session   The used EDHOC session
     * @param mac2   The MAC_2 value
     * @param externalData   The external data for the possible signature process, it can be null
     * @return  The computed Signature_or_MAC_2, or null in case of error
     */
	public static byte[] computeSignatureOrMac2(EdhocSession session, byte[] mac2, byte[] externalData) {
		
		byte[] signatureOrMac2 = null;
    	int authenticationMethod = session.getMethod();
    	
    	if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_1 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_3) {
    		// The responder does not use signatures as authentication method, then Signature_or_MAC_2 is equal to MAC_2
    		signatureOrMac2 = new byte[mac2.length];
    		System.arraycopy(mac2, 0, signatureOrMac2, 0, mac2.length);
    	}
    	else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_2) {
    		// The responder uses signatures as authentication method, then Signature_or_MAC_2 has to be computed
    		try {
    			OneKey identityKey = session.getLongTermKey();
    			int selectedCipherSuite = session.getSelectedCiphersuite();
    			
    			// Consistency check of key type and curve against the selected ciphersuite
    			if (Util.checkSignatureKeyAgainstCiphersuite(identityKey, selectedCipherSuite) == false) {
    				System.err.println("Error when signing MAC_2 to produce Signature_or_MAC_2\n");
    				return null;
    			}

				signatureOrMac2 = Util.computeSignature(session.getIdCred(), externalData, mac2, identityKey);
				
			} catch (CoseException e) {
				System.err.println("Error when signing MAC_2 to produce Signature_or_MAC_2\n" + e.getMessage());
				return null;
			}
    	}
		
    	return signatureOrMac2;
    	
	}
	
	
    /**
     *  Compute Signature_or_MAC_3 - Only for the Initiator
     * @param session   The used EDHOC session
     * @param mac3   The MAC_3 value
     * @param externalData   The external data for the possible signature process, it can be null
     * @return  The computed Signature_or_MAC_3, or null in case of error
     */
	public static byte[] computeSignatureOrMac3(EdhocSession session, byte[] mac3, byte[] externalData) {
		
		byte[] signatureOrMac3 = null;
    	int authenticationMethod = session.getMethod();
    	
    	if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_2 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_3) {
    		// The initiator does not use signatures as authentication method, then Signature_or_MAC_3 is equal to MAC_3
    		signatureOrMac3 = new byte[mac3.length];
    		System.arraycopy(mac3, 0, signatureOrMac3, 0, mac3.length);
    	}
    	else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_1) {
    		// The initiator uses signatures as authentication method, then Signature_or_MAC_3 has to be computed
    		try {
    			OneKey identityKey = session.getLongTermKey();
    			int selectedCipherSuite = session.getSelectedCiphersuite();
    			
    			// Consistency check of key type and curve against the selected ciphersuite
    			if (Util.checkSignatureKeyAgainstCiphersuite(identityKey, selectedCipherSuite) == false) {
    				System.err.println("Error when signing MAC_3 to produce Signature_or_MAC_3\n");
    				return null;
    			}
    			
				signatureOrMac3 = Util.computeSignature(session.getIdCred(), externalData, mac3, identityKey);
				
			} catch (CoseException e) {
				System.err.println("Error when signing MAC_3 to produce Signature_or_MAC_3\n" + e.getMessage());
				return null;
			}
    	}
		
    	return signatureOrMac3;
    	
	}
	
	
    /**
     *  Verify Signature_or_MAC_2, when this contains an actual signature - Only for the Initiator
     * @param session   The used EDHOC session
     * @param signatureOrMac2   The signature value specified as Signature_or_MAC_2
     * @param externalData   The external data for the possible signature process, it can be null
     * @param mac2   The MAC_2 whose signature has to be verified
     * @return  True in case of successful verification, false otherwise
     */
	public static boolean verifySignatureOrMac2(EdhocSession session, byte[] signatureOrMac2, byte[] externalData, byte[] mac2) {
		
		int authenticationMethod = session.getMethod();
		
    	if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_1 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_3) {
    		// The responder does not use signatures as authentication method, then Signature_or_MAC_2 has to be equal to MAC_2
    		return Arrays.equals(signatureOrMac2, mac2);
    	}
    	else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_2) {
    		// The responder uses signatures as authentication method, then Signature_or_MAC_2 is a signature to verify
    		
    		OneKey peerIdentityKey = session.getPeerLongTermPublicKey();
			int selectedCipherSuite = session.getSelectedCiphersuite();
			
			// Consistency check of key type and curve against the selected ciphersuite
			if (Util.checkSignatureKeyAgainstCiphersuite(peerIdentityKey, selectedCipherSuite) == false) {
				System.err.println("Error when verifying the signature of Signature_or_MAC_2\n");
				return false;
			}
    		
			try {
				return Util.verifySignature(signatureOrMac2, session.getPeerIdCred(),
						                    externalData, mac2, peerIdentityKey);
			} catch (CoseException e) {
				System.err.println("Error when verifying the signature of Signature_or_MAC_2\n" + e.getMessage());
				return false;
			}
		}
		
		return false;
		
	}
	
	
    /**
     *  Verify Signature_or_MAC_3, when this contains an actual signature - Only for the Responder
     * @param session   The used EDHOC session
     * @param signatureOrMac3   The signature value specified as Signature_or_MAC_3
     * @param externalData   The external data for the possible signature process, it can be null
     * @param mac3   The MAC_3 whose signature has to be verified
     * @return  True in case of successful verification, false otherwise
     */
	public static boolean verifySignatureOrMac3(EdhocSession session, byte[] signatureOrMac3, byte[] externalData, byte[] mac3) {
		
		int authenticationMethod = session.getMethod();
		
    	if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_2 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_3) {
    		// The initiator does not use signatures as authentication method, then Signature_or_MAC_3 has to be equal to MAC_3
    		return Arrays.equals(signatureOrMac3, mac3);
    	}
    	else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_1) {
    		// The initiator uses signatures as authentication method, then Signature_or_MAC_3 is a signature to verify

    		OneKey peerIdentityKey = session.getPeerLongTermPublicKey();
			int selectedCipherSuite = session.getSelectedCiphersuite();
			
			// Consistency check of key type and curve against the selected ciphersuite
			if (Util.checkSignatureKeyAgainstCiphersuite(peerIdentityKey, selectedCipherSuite) == false) {
				System.err.println("Error when verifying the signature of Signature_or_MAC_3\n");
				return false;
			}
    		
			try {
				return Util.verifySignature(signatureOrMac3, session.getPeerIdCred(),
						                    externalData, mac3, peerIdentityKey);
			} catch (CoseException e) {
				System.err.println("Error when verifying the signature of Signature_or_MAC_3\n" + e.getMessage());
				return false;
			}
		}
		
		return false;
		
	}
	
	
    /**
     *  Compute the transcript hash TH2
     * @param session   The used EDHOC session
     * @param message1   The payload of the EDHOC Message 1, as a serialized CBOR byte string
     * @param data2   The data_2 information from the EDHOC Message 2, as a serialized CBOR byte string
     * @return  The computed TH2
     */
	public static byte[] computeTH2(EdhocSession session, byte[] message1, byte[] data2) {
	
        byte[] th2 = null;
        
        String hashAlgorithm = null;
        int selectedCiphersuite = session.getSelectedCiphersuite();
        switch (selectedCiphersuite) {
        	case Constants.EDHOC_CIPHER_SUITE_0:
        	case Constants.EDHOC_CIPHER_SUITE_1:
        	case Constants.EDHOC_CIPHER_SUITE_2:
        	case Constants.EDHOC_CIPHER_SUITE_3:
        		hashAlgorithm = "SHA-256";
        		break;
        }
        
        byte[] hashInput = new byte[message1.length + data2.length];
        System.arraycopy(message1, 0, hashInput, 0, message1.length);
        System.arraycopy(data2, 0, hashInput, message1.length, data2.length);
        try {
			th2 = Util.computeHash(hashInput, hashAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Invalid hash algorithm when computing TH2\n" + e.getMessage());
			return null;
			
		}
		
		return th2;
		
	}
	
	
    /**
     *  Compute the transcript hash TH3
     * @param session   The used EDHOC session
     * @param th2   The transcript hash TH2, as a serialized CBOR byte string
     * @param ciphertext2   The CIPHERTEXT_2 from EDHOC Message 2, as a serialized CBOR byte string
     * @param data3   The data_3 information from the EDHOC Message 3, as a serialized CBOR byte string. It can be null
     * @return  The computed TH3
     */
	public static byte[] computeTH3(EdhocSession session, byte[] th2, byte[] ciphertext2, byte[] data3) {
	
        byte[] th3 = null;
        int inputLength = th2.length + ciphertext2.length;
        if (data3 != null)
        	inputLength += data3.length;
        
        String hashAlgorithm = null;
        int selectedCiphersuite = session.getSelectedCiphersuite();
        switch (selectedCiphersuite) {
        	case Constants.EDHOC_CIPHER_SUITE_0:
        	case Constants.EDHOC_CIPHER_SUITE_1:
        	case Constants.EDHOC_CIPHER_SUITE_2:
        	case Constants.EDHOC_CIPHER_SUITE_3:
        		hashAlgorithm = "SHA-256";
        		break;
        }
        
        int offset = 0;
        byte[] hashInput = new byte[inputLength];
        System.arraycopy(th2, 0, hashInput, offset, th2.length);
        offset += th2.length;
        System.arraycopy(ciphertext2, 0, hashInput, offset, ciphertext2.length);
        if (data3 != null) {
        	offset += ciphertext2.length;
            System.arraycopy(data3, 0, hashInput, offset, data3.length);
        }
        try {
			th3 = Util.computeHash(hashInput, hashAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Invalid hash algorithm when computing TH3\n" + e.getMessage());
			return null;
			
		}
		
		return th3;
		
	}
	
	
    /**
     *  Compute the transcript hash TH4
     * @param session   The used EDHOC session
     * @param th3   The transcript hash TH3, as a serialized CBOR byte string
     * @param ciphertext3   The CIPHERTEXT_3 from EDHOC Message 3, as a serialized CBOR byte string
     * @return  The computed TH4
     */
	public static byte[] computeTH4(EdhocSession session, byte[] th3, byte[] ciphertext3) {
	
        byte[] th4 = null;
        int inputLength = th3.length + ciphertext3.length;
        
        String hashAlgorithm = null;
        int selectedCiphersuite = session.getSelectedCiphersuite();
        switch (selectedCiphersuite) {
        	case Constants.EDHOC_CIPHER_SUITE_0:
        	case Constants.EDHOC_CIPHER_SUITE_1:
        	case Constants.EDHOC_CIPHER_SUITE_2:
        	case Constants.EDHOC_CIPHER_SUITE_3:
        		hashAlgorithm = "SHA-256";
        		break;
        }
        
        byte[] hashInput = new byte[inputLength];
        System.arraycopy(th3, 0, hashInput, 0, th3.length);
        System.arraycopy(ciphertext3, 0, hashInput, th3.length, ciphertext3.length);
        try {
        	th4 = Util.computeHash(hashInput, hashAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Invalid hash algorithm when computing TH4\n" + e.getMessage());
			return null;
			
		}
		
		return th4;
		
	}
	
}