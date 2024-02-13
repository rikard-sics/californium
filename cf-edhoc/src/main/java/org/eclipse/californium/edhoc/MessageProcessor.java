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
import java.util.HashMap;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.HashMapCtxDB;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

public class MessageProcessor {
	
	private static final boolean debugPrint = true;
	
    /**
     *  Determine the type of a received EDHOC message
     *  
     *  Note: This method DOES NOT recognize EDHOC message_1 as a CoAP response.
     *        This has to be separately handled by the handler of the EDHOC resource
     *        when receiving the "trigger request" from the client.
     *  
     * @param msg   The received EDHOC message, as a CBOR sequence
     * @param isReq   True if the EDHOC message to parse is a CoAP request, false if it is a CoAP response
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param connectionIdentifier   The connection identifier of this peer.
     *             					 It can be null and then it has to be retrieved from the message
     * @return  The type of the EDHOC message, or -1 if it not a recognized type
     */
	public static int messageType(byte[] msg, boolean isReq,
								  HashMap<CBORObject, EdhocSession> edhocSessions,
								  byte[] connectionIdentifier) {
				
		CBORObject[] myObjects = null;
		
		if (msg == null)
			return -1;
		
		try {
			myObjects = CBORObject.DecodeSequenceFromBytes(msg);
		} catch (CBORException e) {
			System.err.println("Error while parsing the CBOR sequence\n");
			return -1;
		}
		
		if (myObjects == null || myObjects.length == 0)
			return -1;
		
		CBORObject connectionIdentifierCbor = null;
		
		if (isReq == true) {
			// A request always starts with C_X
			CBORObject elem = myObjects[0];
			
			if (elem.equals(CBORObject.True)) {
				// If C_X is equal to 'true' (0xf5), this is EDHOC message_1
				return Constants.EDHOC_MESSAGE_1;
			}
			if (isErrorMessage(myObjects, isReq)) {
				// Check if it is an EDHOC error message
				return Constants.EDHOC_ERROR_MESSAGE;
			}
			
			if (connectionIdentifier != null) {
				connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
			}
			else {
				// The Connection Identifier to retrieve the EDHOC session was not provided.
				// It is present in the message as first element of the CBOR sequence.
				
			    if (elem.getType() == CBORType.ByteString || elem.getType() == CBORType.Integer) {
			    	connectionIdentifier = MessageProcessor.decodeIdentifier(myObjects[0]);
			    	if (connectionIdentifier != null)
						connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
			    }

			}
		}
		
		if (isReq == false) {
			// A response never starts with C_X
			
			if (isErrorMessage(myObjects, isReq)) {
				// Check if it is an EDHOC error message
				return Constants.EDHOC_ERROR_MESSAGE;
			}
			
			// Use the provided Connection Identifier to retrieve the EDHOC session.
			connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
			
		}

	    if (connectionIdentifierCbor != null) {
	    	
	        EdhocSession session = edhocSessions.get(connectionIdentifierCbor);
	        
	        if (session != null) {
	            boolean initiator = session.isInitiator();
	            int currentStep = session.getCurrentStep();
	            boolean clientInitiated = session.isClientInitiated();
	            	            
	            // Take the point of view of the Initiator
	            if (initiator == true) {
	                
	                if (clientInitiated == true) {
		                // The Initiator is the Client
	                    if (isReq == false && currentStep == Constants.EDHOC_SENT_M1)
	                        return Constants.EDHOC_MESSAGE_2;
	                    if (isReq == true && currentStep == Constants.EDHOC_AFTER_M3)
	                        return Constants.EDHOC_MESSAGE_3;
	                    if (isReq == false && currentStep == Constants.EDHOC_SENT_M3)
	                        return Constants.EDHOC_MESSAGE_4;
	                }
	                else {
		                // The Initiator is the Server
	                    if (isReq == true && currentStep == Constants.EDHOC_SENT_M1)
	                        return Constants.EDHOC_MESSAGE_2;
	                	if (isReq == false && currentStep == Constants.EDHOC_AFTER_M3)
	                        return Constants.EDHOC_MESSAGE_3;
	                    if (isReq == true && currentStep == Constants.EDHOC_SENT_M3)
	                        return Constants.EDHOC_MESSAGE_4;
	                }

	            }
	            
	            // Take the point of view of the Responder
	            if (initiator == false) {					

	                if (clientInitiated == true) {
		                // The Responder is the Server
	                    if (isReq == false && currentStep == Constants.EDHOC_AFTER_M2)
	                        return Constants.EDHOC_MESSAGE_2;
	                    if (isReq == true && currentStep == Constants.EDHOC_SENT_M2)
	                        return Constants.EDHOC_MESSAGE_3;
	                    if (isReq == false && currentStep == Constants.EDHOC_AFTER_M4)
	                        return Constants.EDHOC_MESSAGE_4;
	                }
	                else {
		                // The Responder is the Client
	                    if (isReq == true && currentStep == Constants.EDHOC_AFTER_M2)
	                        return Constants.EDHOC_MESSAGE_2;
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
     *  Determine if a message is an EDHOC error message
     * @param myObjects   The message to check, as an array of CBOR objects extracted from a CBOR sequence
     * @param isReq   True if the message is a request, false otherwise
     * @return  True if it is an EDHOC error message, or false otherwise
     */
	public static boolean isErrorMessage(CBORObject[] myObjects, boolean isReq) {
		
		// A CoAP message including an EDHOC error message is a CBOR sequence of at least two elements
		if (myObjects.length < 2)
			return false;
		
		if (isReq == true) {
			// If in a request, this starts with C_X different than 'true' (0xf5),
			// followed by ERR_CODE as a CBOR integer
			if (!myObjects[0].equals(CBORObject.True) && myObjects[1].getType() == CBORType.Integer)
				return true;
			
		}
		else {
			// If in a response, this starts with ERR_CODE as a CBOR integer
			if (myObjects[0].getType() == CBORType.Integer)
				return true;
		}
		
		return false;
		
	}
	
    /**
     *  Determine if a message is an EDHOC error message
     * @param msg   The message to check, as a CBOR sequence
     * @param isReq   True if the message is a request, false otherwise
     * @return  True if it is an EDHOC error message, or false otherwise
     */
	public static boolean isErrorMessage(byte[] msg, boolean isReq) {
		
		CBORObject[] myObjects = null;
		
		try {
			myObjects = CBORObject.DecodeSequenceFromBytes(msg);
		} catch (CBORException e) {
			System.err.println("Error while parsing the CBOR sequence\n");
			return false;
		}
		
		if (myObjects == null)
			return false;
		
		return isErrorMessage(myObjects, isReq);
		
	}
	
    /**
     *  Process an EDHOC Message 1
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 1
     * @param isReq   True if the CoAP message is a request, or False otherwise
     * @param supportedCipherSuites   The list of cipher suites supported by this peer
     * @param supportedEADs   The list of EAD items supported by this peer
     * @param appProfile   The application profile to use
     * @param sessions   The EDHOC sessions of this peer
     * @param sideProcessor   The side processor object to use for this message
     * @return   A list of CBOR Objects including up to two elements.
     * 
     *           The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC message_1 was successfully processed; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *
     *           In case (ii), the second element is a CBOR integer, with value the CoAP response code
     *           to use for the EDHOC Error Message, if this is a CoAP response.
     */
	public static List<CBORObject> readMessage1(byte[] sequence, boolean isReq,
												List<Integer> supportedCipherSuites,
												Set<Integer> supportedEADs,
												AppProfile appProfile,
												SideProcessor sideProcessor) {
		
		if (sequence == null || supportedCipherSuites == null)
				return null;
		
		CBORObject[] ead1 = null; // Will be set if External Authorization Data is present as EAD1
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		// Serialization of the message to be sent back to the Initiator
		byte[] replyPayload = new byte[] {};
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED_ERROR; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		CBORObject cI = null; // The Connection Identifier C_I as encoded in the EDHOC message
		CBORObject suitesR = null; // The SUITE_R element to be possibly returned as SUITES_R in an EDHOC Error Message

		
		int index = -1;	
		CBORObject[] objectList = null;
		try {
			objectList = CBORObject.DecodeSequenceFromBytes(sequence);
		}
		catch (Exception e) {
		    errMsg = new String("Malformed or invalid EDHOC message_1");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}
		
		/* Consistency checks */
		
		if (error == false && objectList.length == 0) {
		    errMsg = new String("Malformed or invalid EDHOC message_1");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}
		
    	if (error == false && appProfile == null) {
			errMsg = new String("Impossible to retrieve the application profile");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
    	}
    	if (error == false) {
    	    // If the received message is a request (i.e. the CoAP client is the initiator), the first element
    	    // before the actual message_1 is the CBOR simple value 'true', i.e. the byte 0xf5, and it can be skipped
	    	if (isReq) {
	    		index++;
	    		if (!objectList[index].equals(CBORObject.True)) {
	    			errMsg = new String("The first element must be the CBOR simple value 'true'");
	    			responseCode = ResponseCode.BAD_REQUEST;
	    			error = true;
	    		}
	        }
    	}
		
    	
		// METHOD
    	index++;
    	int method = -1;
    	if (error == false) {
			if (objectList[index].getType() != CBORType.Integer) {
				errMsg = new String("METHOD must be an integer");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				// Check that the indicated authentication method is supported
		    	method = objectList[index].AsInt32();
		    	if (!appProfile.isAuthMethodSupported(method)) {
					errMsg = new String("Authentication method " + method + " is not supported");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
		    	}
			}
		}
		
		// SUITES_I
		index++;
		int indexCredI = index;
		if (error == false &&
			objectList[index].getType() != CBORType.Integer &&
			objectList[index].getType() != CBORType.Array) {
				errMsg = new String("SUITES_I must be an integer or an array");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false &&
			objectList[index].getType() == CBORType.Integer &&
			objectList[index].AsInt32() < 0) {
				errMsg = new String("SUITES_I as an integer must be greater than 0");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false &&
			objectList[index].getType() == CBORType.Array) {
				if (objectList[index].size() < 2) {
					errMsg = new String("SUITES_I as an array must have at least 2 elements");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
				}
				else {
					for (int i = 0; i < objectList[index].size(); i++) {
						if(objectList[index].get(i).getType() != CBORType.Integer) {
							errMsg = new String("SUITES_I as an array must have integers as elements");
							responseCode = ResponseCode.BAD_REQUEST;
							error = true;
							break;
						}
						if(objectList[index].get(i).AsInt32() < 0) {
							errMsg = new String("SUITES_I as an array must have integers greater than 0");
							responseCode = ResponseCode.BAD_REQUEST;
							error = true;
							break;
						}
					}
				}
		}

		// Check if the selected cipher suite is supported and that no prior cipher suite in SUITES_I is supported
		List<Integer> cipherSuitesToOffer = new ArrayList<Integer>();
		if (error == false) {
			int selectedCipherSuite;
			
			if (objectList[index].getType() == CBORType.Integer) {
				// SUITES_I is the selected cipher suite
				selectedCipherSuite = objectList[index].AsInt32();
				
				// This peer does not support the selected cipher suite
				if (!supportedCipherSuites.contains(Integer.valueOf(selectedCipherSuite))) {
					errMsg = new String("The selected cipher suite is not supported");
					errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
					
					// SUITE_R will include all the cipher suites supported by the Responder
					cipherSuitesToOffer = supportedCipherSuites;
				}
			}
			
			else if (objectList[index].getType() == CBORType.Array) {
				// The selected cipher suite is the last element of SUITES_I
				int size = objectList[index].size(); 
				selectedCipherSuite = objectList[index].get(size-1).AsInt32();
				
				int firstSharedCipherSuite = -1;
				// Find the first commonly supported cipher suite, i.e. the cipher suite both
				// supported by the Responder and specified as early as possible in SUITES_I
				for (int i = 0; i < size; i++) {
					int suite = objectList[index].get(i).AsInt32();
					if (supportedCipherSuites.contains(Integer.valueOf(suite))) {
						firstSharedCipherSuite = suite;
						break;
					}
				}
				
				if (!supportedCipherSuites.contains(Integer.valueOf(selectedCipherSuite))) {
					// The Responder does not support the selected cipher suite
					
					errMsg = new String("The selected cipher suite is not supported");
					errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
					
					if (firstSharedCipherSuite == -1) {
						// The Responder does not support any cipher suites in SUITE_I.
						// SUITE_R will include all the cipher suites supported by the Responder
						cipherSuitesToOffer = supportedCipherSuites;
					}
					else {
						// SUITES_R will include only the cipher suite supported
						// by both peers and most preferred by the Initiator.
						cipherSuitesToOffer.add(firstSharedCipherSuite);
					}
					
				}
				else if (firstSharedCipherSuite != selectedCipherSuite) {
					// The Responder supports the selected cipher suite, but it has to reply with an EDHOC Error Message
					// if it supports a cipher suite more preferred by the Initiator than the selected cipher suite
					
					errMsg = new String("A cipher suite more preferred than the selected cipher suite is also supported");
					errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
					
					// SUITES_R will include only the cipher suite supported
					// by both peers and most preferred by the Initiator.
					cipherSuitesToOffer.add(firstSharedCipherSuite);
					
				}
				
			}
			
		}
		
		// G_X
		index++;
		int indexGx = index;
		if (error == false &&
			objectList[index].getType() != CBORType.ByteString) {
				errMsg = new String("G_X must be a byte string");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		
		// C_I
		index++;
		if (error == false &&
			objectList[index].getType() != CBORType.ByteString &&
			objectList[index].getType() != CBORType.Integer) {
				errMsg = new String("C_I must be a byte string or an integer");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		
		if (error == false && decodeIdentifier(objectList[index]) == null) {
			errMsg = new String("Invalid encoding of C_I");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}

		byte[] connectionIdentifierInitiator = null;
		if (error == false) {
			cI = objectList[index];
			
			connectionIdentifierInitiator = decodeIdentifier(cI);
			if (debugPrint) {
			    Util.nicePrint("Connection Identifier of the Initiator", connectionIdentifierInitiator);
			    Util.nicePrint("C_I", cI.EncodeToBytes());
			}
		}
		
		index++;
		// EAD_1
		if (error == false && objectList.length > index) {
		    // EAD_1 is present
			ead1 = preParseEAD(objectList, index, 1, supportedEADs);
			
			if (ead1.length == 1 && ead1[0].getType() == CBORType.TextString) {
		        errMsg = new String(ead1[0].toString());
		        responseCode = ResponseCode.BAD_REQUEST;
		        ead1 = null;
		        error = true;
			}
		}
		
		// Invoke the processing of EAD items in EAD_1 (if any)
		if (error == false && ead1!= null && ead1.length != 0) {
			
	 	    CBORObject[] sideProcessorInfo = new CBORObject[4];

	 	   sideProcessorInfo[0] = CBORObject.FromObject(method);
		    
		    if (objectList[indexCredI].getType() == CBORType.Integer) {
		    	// CRED_I was a single CBOR integer, so a CBOR array including only that integer is built.
		    	// Such an integer also indicates the selected cipher suite.
		    	sideProcessorInfo[1] = CBORObject.NewArray();
		    	sideProcessorInfo[1].Add(objectList[indexCredI]);
		    }
		    else {
		    	// CRED_I was a CBOR array of integers and can be taken as is.
		    	// The last integer in the array indicates the selected cipher suite.
		    	sideProcessorInfo[1] = objectList[indexCredI];
		    }
		    
		    sideProcessorInfo[2] = objectList[indexGx];
		    sideProcessorInfo[3] = CBORObject.FromObject(connectionIdentifierInitiator);

			sideProcessor.sideProcessingMessage1(sideProcessorInfo, ead1);
			
			// A fatal error occurred
			if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_1, false).
					containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
				errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_1, false).
						get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
						get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
				int responseCodeValue = sideProcessor.getResults(Constants.EDHOC_MESSAGE_1, false).
			            get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
			            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE)).AsInt32();
				responseCode = ResponseCode.valueOf(responseCodeValue);
				error = true;
				
				// No need to keep this information any longer in the side processor object
				sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_1, Constants.SIDE_PROCESSOR_OUTER_ERROR, false);
			}
		}
		
		// If EAD_1 was present, print any available results from processing its EAD items.
		sideProcessor.showResultsFromSideProcessing(Constants.EDHOC_MESSAGE_1, false);
		
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			
			// Prepare SUITES_R
			suitesR = Util.buildSuitesR(cipherSuitesToOffer);
			
			byte[] connectionIdentifier = decodeIdentifier(cI);
			return processError(errorCode, Constants.EDHOC_MESSAGE_1, !isReq,
								connectionIdentifier, errMsg, suitesR, responseCode);
			
		}
		
		
		/* Return an indication to prepare EDHOC Message 2 */
		
		// A CBOR byte string with zero length, indicating that the EDHOC Message 2 can be prepared
		processingResult.add(CBORObject.FromObject(replyPayload));
		
		System.out.println("\nCompleted processing of EDHOC Message 1");
		return processingResult;
		
	}
	
    /**
     *  Process an EDHOC Message 2
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 2
     * @param isReq   True if the CoAP message is a request, or False otherwise
     * @param connectionIdInitiator   The already known connection identifier of the Initiator.
     * 								  It is set to null if expected in the EDHOC Message 2.
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param peerPublicKeys   The list of the long-term public keys of authorized peers
     * @param peerCredentials   The list of CRED of the long-term public keys of authorized peers
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @param ownIdCreds   The set of ID_CRED_X used for an authentication credential associated to this peer
     * @return   A list of CBOR Objects including up to two elements.
     * 
     *           The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC message_2 was successfully processed; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *           
     *           In case (ii), the second element is a CBOR integer, with value the CoAP response code
     *           to use for the EDHOC Error Message, if this is a CoAP response.
     */
	public static List<CBORObject> readMessage2(byte[] sequence, boolean isReq, byte[] connectionIdInitiator,
												HashMap<CBORObject, EdhocSession> edhocSessions,
												HashMap<CBORObject, OneKey> peerPublicKeys,
												HashMap<CBORObject, CBORObject> peerCredentials,
												Set<CBORObject> usedConnectionIds,
			                                    Set<CBORObject> ownIdCreds) {
		
		if (sequence == null || edhocSessions == null ||
		    peerPublicKeys == null || peerCredentials == null || usedConnectionIds == null)
			return null;
		
		byte[] connectionIdentifierInitiator = null; // The connection identifier of the Initiator
		byte[] connectionIdentifierResponder = null; // The connection identifier of the Responder
		
		CBORObject[] ead2 = null; // Will be set if External Authorization Data is present as EAD2
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED_ERROR; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		CBORObject cR = null; // The Connection Identifier C_R, or left to null in case of invalid message
		EdhocSession session = null; // The session used for this EDHOC execution
		
		
		int index = 0;
		CBORObject[] objectList = null;
		try {
			objectList = CBORObject.DecodeSequenceFromBytes(sequence);
		}
		catch (Exception e) {
		    errMsg = new String("Malformed or invalid EDHOC message_2");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}
		
		
		/* Consistency checks */
				
		// If EDHOC Message 2 is transported in a CoAP request, C_I is present as first element of the CBOR sequence
		if (error == false && isReq == true) {
			if (error == false && objectList[index].getType() != CBORType.ByteString &&
				objectList[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_I must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
			
			if (error == false) {
				CBORObject cI = objectList[index];
				connectionIdentifierInitiator = decodeIdentifier(cI);
				if (connectionIdentifierInitiator == null) {
				    errMsg = new String("Invalid encoding of C_I");
				    responseCode = ResponseCode.BAD_REQUEST;
				    error = true;
				}
				else {
					index++;
					if (debugPrint) {
					    Util.nicePrint("Connection Identifier of the Initiator", connectionIdentifierInitiator);
					}
				}
			}
			
		}
		
		if (error == false && isReq == false) {
			connectionIdentifierInitiator = connectionIdInitiator;
			if (debugPrint) {
			    Util.nicePrint("Connection Identifier of the Initiator", connectionIdentifierInitiator);
			}
		}
		
		if (error == false) {
				CBORObject connectionIdentifierInitiatorCbor = CBORObject.FromObject(connectionIdentifierInitiator);
				session = edhocSessions.get(connectionIdentifierInitiatorCbor);
			
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
		}
		
		// G_Y | CIPHERTEXT_2
		byte[] gY = null;
		byte[] ciphertext2 = null;
		byte[] gY_Ciphertext2 = null;
		int gYLength = 0;
		int ciphetertext2Length = 0;
		if (error == false && objectList[index].getType() != CBORType.ByteString) {
				errMsg = new String("(G_Y | CIPHERTEXT_2) must be a byte string");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false) {
			gY_Ciphertext2 = objectList[index].GetByteString();
			
			gYLength = EdhocSession.getEphermeralKeyLength(session.getSelectedCipherSuite());
			ciphetertext2Length = gY_Ciphertext2.length - gYLength;
			
			if (ciphetertext2Length <= 0) {
				errMsg = new String("(G_Y | CIPHERTEXT_2) has an inconsistent size");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
				
		}
		if (error == false) {
			
			// G_Y
			gY = new byte[gYLength];
			System.arraycopy(gY_Ciphertext2, 0, gY, 0, gYLength);
	    	if (debugPrint) {
	    		Util.nicePrint("G_Y", gY);
	    	}
			
			// Set the ephemeral public key of the Responder
			OneKey peerEphemeralKey = null;
			
			int selectedCipherSuite = session.getSelectedCipherSuite();
			
			if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_0 ||
				selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_1) {
				peerEphemeralKey = SharedSecretCalculation.buildCurve25519OneKey(null, gY);
			}
			if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_2 ||
				selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_3) {
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
			}
			
			
			// CIPHERTEXT_2
			ciphertext2 = new byte[ciphetertext2Length];
			System.arraycopy(gY_Ciphertext2, gYLength, ciphertext2, 0, ciphetertext2Length);

		}
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
		}
		
		
		/* Decrypt CIPHERTEXT_2 */
			
        // Compute TH2
		
        byte[] th2 = null;
        byte[] hashMessage1 = session.getHashMessage1(); // the hash of message_1, as plain bytes
        List<CBORObject> objectListData2 = new ArrayList<>();
        for (int i = 0; i < objectList.length - 1; i++)
        	objectListData2.add(objectList[i]);
        byte[] hashMessage1SerializedCBOR = CBORObject.FromObject(hashMessage1).EncodeToBytes();
        byte[] gYSerializedCBOR = CBORObject.FromObject(gY).EncodeToBytes();
        
        th2 = computeTH2(session, gYSerializedCBOR, hashMessage1SerializedCBOR);
        if (th2 == null) {
        	errMsg = new String("Error when computing TH2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
        }
        else if (debugPrint) {
        	Util.nicePrint("H(message_1)", hashMessage1);
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
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("G_XY", dhSecret);
    	}
        
        // Compute PRK_2e
    	String hashAlgorithm = EdhocSession.getEdhocHashAlg(session.getSelectedCipherSuite());
    	
    	prk2e = computePRK2e(th2, dhSecret, hashAlgorithm);    	
    	
    	dhSecret = null;
    	if (prk2e == null) {
        	errMsg = new String("Error when computing PRK_2e");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
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
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("KEYSTREAM_2", keystream2);
    	}
		
    	// Compute the plaintext
    	
    	if (debugPrint && ciphertext2 != null) {
    		Util.nicePrint("CIPHERTEXT_2", ciphertext2);
    	}
    	byte[] plaintext2 = Util.arrayXor(ciphertext2, keystream2);
    	if (debugPrint && plaintext2 != null) {
    		Util.nicePrint("Plaintext retrieved from CIPHERTEXT_2", plaintext2);
    	}
    	
    	error = false;
    	
    	// Parse the plaintext as a CBOR sequence
    	CBORObject[] plaintextElementList = null;
    	CBORObject idCredR = CBORObject.NewMap();
    	try {
    		plaintextElementList = CBORObject.DecodeSequenceFromBytes(plaintext2);
    	}
    	catch (Exception e) {
    	    errMsg = new String("Malformed or invalid plaintext from CIPHERTEXT_2");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	if (error == false && plaintextElementList.length < 3) {
        	errMsg = new String("Invalid format of the content encrypted as CIPHERTEXT_2");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	if (error == false) {
    	    cR = plaintextElementList[0];

    	    if (cR.getType() != CBORType.ByteString && cR.getType() != CBORType.Integer) {
    	            errMsg = new String("C_R must be a byte string or an integer");
    	            responseCode = ResponseCode.BAD_REQUEST;
    	            error = true;
    	    }
    	    if (error == false) {
    	        connectionIdentifierResponder = decodeIdentifier(cR);
    	        if (connectionIdentifierResponder == null) {
    	            errMsg = new String("Invalid encoding of C_R");
    	            responseCode = ResponseCode.BAD_REQUEST;
    	            error = true;
    	        }
    	        else {
    	            session.setPeerConnectionId(connectionIdentifierResponder);
    	            if (debugPrint) {
    	                Util.nicePrint("Connection Identifier of the Responder", connectionIdentifierResponder);
    	                Util.nicePrint("C_R", cR.EncodeToBytes());
    	            }
    	        }
    	    }
    	    if (error == false) {
    	        if (session.getApplicationProfile().getUsedForOSCORE() == true &&
    	            Arrays.equals(connectionIdentifierInitiator, connectionIdentifierResponder) == true) {
    	            errMsg = new String("C_R must be different from C_I");
    	            responseCode = ResponseCode.BAD_REQUEST;
    	            error = true;
    	        }
    	    }

    	}
    	if (error == false &&
    			 plaintextElementList[1].getType() != CBORType.ByteString &&
    			 plaintextElementList[1].getType() != CBORType.Integer &&
    			 plaintextElementList[1].getType() != CBORType.Map) {
        	errMsg = new String("Invalid format of ID_CRED_R");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	if (error == false) {
        	CBORObject rawIdCredR = plaintextElementList[1];
        	
        	// ID_CRED_R is a CBOR map with 'kid', and only 'kid' was transported
        	if (rawIdCredR.getType() == CBORType.ByteString || rawIdCredR.getType() == CBORType.Integer) {
        		byte[] kidValue = MessageProcessor.decodeIdentifier(rawIdCredR);
        		idCredR.Add(HeaderKeys.KID.AsCBOR(), kidValue);
        	}
        	else if (rawIdCredR.getType() == CBORType.Map) {
        		idCredR = rawIdCredR;
        	}
        	else {
        	    errMsg = new String("Invalid format for ID_CRED_R");
        	    responseCode = ResponseCode.BAD_REQUEST;
        	    error = true;
        	}
    	}
    	if (error == false && ownIdCreds.contains(idCredR)) {
        	errMsg = new String("The identity expressed by ID_CRED_R is equal to my own identity");
        	responseCode = ResponseCode.BAD_REQUEST;
			error = true;
    	}
    	if (error == false && plaintextElementList[2].getType() != CBORType.ByteString) {
        	errMsg = new String("Signature_or_MAC_2 must be a byte string");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	if (error == false && plaintextElementList.length > 3) {
    		// EAD_2 is present
		    ead2 = preParseEAD(plaintextElementList, 3, 2, session.getSupportedEADs());
		   
		    if (ead2.length == 1 && ead2[0].getType() == CBORType.TextString) {
		    	errMsg = new String(ead2[0].toString());
		        responseCode = ResponseCode.BAD_REQUEST;
		        ead2 = null;
		        error = true;
		    }
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    	
    	error = false;
    	
    	
    	CBORObject peerCredentialCBOR = null;
    	
    	// Invoke the retrieval and/or validation of CRED_R, and the processing of EAD items in EAD_2 (if any)
    	SideProcessor sideProcessor = session.getSideProcessor();
 	    CBORObject[] sideProcessorInfo = new CBORObject[3];
 	    sideProcessorInfo[0] = CBORObject.FromObject(gY);
 	    sideProcessorInfo[1] = CBORObject.FromObject(connectionIdentifierResponder);
 	    sideProcessorInfo[2] = CBORObject.FromObject(idCredR);
	   
	    sideProcessor.sideProcessingMessage2PreVerification(sideProcessorInfo, ead2);
	   
	    // A fatal error occurred
	    if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, false).
	    		containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
	    	errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, false).
	        	get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
	        int responseCodeValue = sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, false).
	        	get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE)).AsInt32();
	        responseCode = ResponseCode.valueOf(responseCodeValue);
	        error = true;
	         
	        // No need to keep this information any longer in the side processor object
	        sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_2, Constants.SIDE_PROCESSOR_OUTER_ERROR, false);
	   }

    	// If no fatal error occurred, the side processor object includes the authentication credential
    	// of the other peer, if a valid one was found during the side processing above.
 	   	if (error == false && sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, false).
 	   						  containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_CRED))) {
 	   		peerCredentialCBOR = sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, false).
 	   							 get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_CRED)).get(0).
 	   							 get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_CRED_VALUE));

 	    	if (peerCredentialCBOR == null) {
 	        	errMsg = new String("Unable to retrieve the peer credential");
 	        	responseCode = ResponseCode.BAD_REQUEST;
 	        	error = true;
 	    	}
	    }
	     	   	
        // No need to keep this information any longer in the side processor object
        sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_2, Constants.SIDE_PROCESSOR_OUTER_CRED, false);
        
        // If EAD_2 was present, print any available results from processing its EAD items.
        sideProcessor.showResultsFromSideProcessing(Constants.EDHOC_MESSAGE_2, false);
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    
    	
    	OneKey peerKey = peerPublicKeys.get(idCredR);
    	session.setPeerLongTermPublicKey(peerKey);
    	
    	
    	// Compute PRK_3e2m
    	prk3e2m = computePRK3e2m(session, prk2e);
    	if (prk3e2m == null) {
        	errMsg = new String("Error when computing PRK_3e2m");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
	    		Util.nicePrint("PRK_3e2m", prk3e2m);
    	}
    	session.setPRK3e2m(prk3e2m);
    	
    	
    	/* Start verifying Signature_or_MAC_2 */
    	
    	byte[] peerCredential = peerCredentialCBOR.GetByteString(); // CRED_R
    	    	
    	session.setPeerIdCred(idCredR);      // Store ID_CRED_R
    	session.setPeerCred(peerCredential); // Store CRED_R
    	
    	// Compute MAC_2
    	byte[] mac2 = computeMAC2(session, prk3e2m, th2, cR, idCredR, peerCredential, ead2);
    	if (mac2 == null) {
        	errMsg = new String("Error when computing MAC_2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_2", mac2);
    	}
            	
    	// Verify Signature_or_MAC_2
    	byte[] signatureOrMac2 = plaintextElementList[2].GetByteString();
    	if (debugPrint && signatureOrMac2 != null) {
    		Util.nicePrint("Signature_or_MAC_2", signatureOrMac2);
    	}
        
    	// Prepare the External Data, as a CBOR sequence
    	byte[] externalData = computeExternalData(th2, peerCredential, ead2);
    	if (externalData == null) {
        	errMsg = new String("Error when computing External Data for MAC_2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to verify Signature_or_MAC_2", externalData);
    	}
    	
    	if (!verifySignatureOrMac2(session, signatureOrMac2, externalData, mac2)) {
        	errMsg = new String("Non valid Signature_or_MAC_2");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    	
    	/* End verifying Signature_or_MAC_2 */

    	// Invoke the processing of EAD items in EAD_2 (if any)
    	// that had to wait for a successful verification of Signature_or_MAC_2
    	if (ead2!= null && ead2.length != 0) {
    		sideProcessor.sideProcessingMessage2PostVerification(sideProcessorInfo, ead2);
    	}

    	// A fatal error occurred
    	if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, true).
    			containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
    	   errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, true).
    	         get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
    	         get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
    	   int responseCodeValue = sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, true).
    	         get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
    	         get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE)).AsInt32();
    	   responseCode = ResponseCode.valueOf(responseCodeValue);
    	   error = true;
    	      
    	   // No need to keep this information any longer in the side processor object
    	   sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_2, Constants.SIDE_PROCESSOR_OUTER_ERROR, true);
    	}
    	
        // If EAD_2 was present, print any available results from processing its EAD items.
        sideProcessor.showResultsFromSideProcessing(Constants.EDHOC_MESSAGE_2, true);
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    	

    	// Store PLAINTEXT_2 for the later computation of TH_3
		session.setPlaintext2(plaintext2);
    	
		/* Return an indication to prepare EDHOC Message 3, possibly with the provided External Authorization Data */
		
		// A CBOR byte string with zero length, indicating that the EDHOC Message 3 can be prepared
		byte[] reply = new byte[] {};
		processingResult.add(CBORObject.FromObject(reply));
		
		System.out.println("\nCompleted processing of EDHOC Message 2");
		return processingResult;
		
	}
	
    /**
     *  Process an EDHOC Message 3
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 3
     * @param isReq   True if the CoAP message is a request, or False otherwise
     * @param connectionIdResponder   The already known connection identifier of the Responder.
     * 								  It is set to null if expected in the EDHOC Message 3.
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param peerPublicKeys   The list of the long-term public keys of authorized peers
     * @param peerCredentials   The list of CRED of the long-term public keys of authorized peers
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @return   A list of CBOR Objects including two elements.
     * 
     *           The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC message_3 was successfully processed; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *           
     *           In case (i), the second element is a CBOR byte string, specifying the Connection Identifier
     *           of the Responder in the used EDHOC session, i.e., C_R.
     *           
     *           In case (ii), the second element is a CBOR integer, with value the CoAP response code
     *           to use for the EDHOC Error Message, if this is a CoAP response.
     */
	public static List<CBORObject> readMessage3(byte[] sequence, boolean isReq, byte[] connectionIdResponder,
												HashMap<CBORObject, EdhocSession> edhocSessions,
												HashMap<CBORObject, OneKey> peerPublicKeys,
												HashMap<CBORObject, CBORObject> peerCredentials,
												Set<CBORObject> usedConnectionIds) {
		
		if (sequence == null || edhocSessions == null ||
			peerPublicKeys == null || peerCredentials == null || usedConnectionIds == null)
			return null;
		
		byte[] connectionIdentifierInitiator = null; // The Connection Identifier of the Initiator
		byte[] connectionIdentifierResponder = null; // The Connection Identifier of the Responder
		
		CBORObject[] ead3 = null; // Will be set if External Authorization Data is present as EAD3
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED_ERROR; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		EdhocSession session = null; // The session used for this EDHOC execution
		

		int index = 0;
		CBORObject[] objectList = null;
		try {
			objectList = CBORObject.DecodeSequenceFromBytes(sequence);
		}
		catch (Exception e) {
		    errMsg = new String("Malformed or invalid EDHOC message_3");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}
		
		
		/* Consistency checks */
		
		// If EDHOC Message 3 is transported in a CoAP request, C_R is present as first element of the CBOR sequence
		if (error == false && isReq == true) {
			if (error == false && objectList[index].getType() != CBORType.ByteString &&
				objectList[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_R must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
		    if (error == false) {
		        connectionIdentifierResponder = decodeIdentifier(objectList[index]);
		        if (connectionIdentifierResponder == null) {
		            errMsg = new String("Invalid encoding of C_R");
		            responseCode = ResponseCode.BAD_REQUEST;
		            error = true;
		        }
		        else {
		            index++;
					if (debugPrint) {
					    Util.nicePrint("Connection Identifier of the Responder", connectionIdentifierResponder);
					}
		        }
		    }

		}
		
		if (error == false && isReq == false) {
			connectionIdentifierResponder = connectionIdResponder;
			if (debugPrint) {
			    Util.nicePrint("Connection Identifier of the Responder", connectionIdentifierResponder);
			}
		}
			
		if (error == false) {
			CBORObject connectionIdentifierResponderCbor = CBORObject.FromObject(connectionIdentifierResponder);
			session = edhocSessions.get(connectionIdentifierResponderCbor);
			
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
		}
		
		if (session != null) {
			if (session.getPeerConnectionId() != null)
				connectionIdentifierInitiator = session.getPeerConnectionId();
		}
		
		
		// CIPHERTEXT_3
		byte[] ciphertext3 = null;
		if (error == false && objectList[index].getType() != CBORType.ByteString) {
			errMsg = new String("CIPHERTEXT_3 must be a byte string");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		else {
			ciphertext3 = objectList[index].GetByteString();
		}
		
		
		/* Send an EDHOC Error Message */
		
		if (error == true) {
			Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode);
		}
		
		
		/* Decrypt CIPHERTEXT_3 */
		
        // Compute TH3
        byte[] th2 = session.getTH2(); // TH_2 as plain bytes
        byte[] th2SerializedCBOR = CBORObject.FromObject(th2).EncodeToBytes();

        byte[] plaintext2 = session.getPlaintext2(); // PLAINTEXT_2 as serialized CBOR sequence
        
        byte[] credR = session.getCred();
        byte[] th3 = computeTH3(session, th2SerializedCBOR, plaintext2, credR);
        
        if (th3 == null) {
        	errMsg = new String("Error when computing TH3");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode);
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_3", th3);
    	}
        session.setTH3(th3);
		
		
    	// Compute K_3 and IV_3 to protect the outer COSE object
    	byte[] k3 = computeKey(Constants.EDHOC_K_3, session);
    	if (k3 == null) {
        	errMsg = new String("Error when computing K_3");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_3", k3);
    	}
    	
    	byte[] iv3 = computeIV(Constants.EDHOC_IV_3, session);
    	if (iv3 == null) {
        	errMsg = new String("Error when computing IV_3");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV_3", iv3);
    	}
    	
    	// Prepare the external_aad as including only TH3
    	byte[] externalData = th3;

    	
    	// Compute the plaintext
    	
    	if (debugPrint && ciphertext3 != null) {
    		Util.nicePrint("CIPHERTEXT_3", ciphertext3);
    	}

    	byte[] plaintext3 = decryptCiphertext3(session, externalData, ciphertext3, k3, iv3);
    	if (plaintext3 == null) {
        	errMsg = new String("Error when decrypting CIPHERTEXT_3");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("Plaintext retrieved from CIPHERTEXT_3", plaintext3);
    	}
    	
    	error = false;
    	
    	// Parse the outer plaintext as a CBOR sequence
    	CBORObject[] plaintextElementList = null;
    	CBORObject idCredI = CBORObject.NewMap();
    	try {
    		plaintextElementList = CBORObject.DecodeSequenceFromBytes(plaintext3);
    	}
    	catch (Exception e) {
    	    errMsg = new String("Malformed or invalid plaintext from CIPHERTEXT_3");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	if (error == false && plaintextElementList.length < 2) {
    	    errMsg = new String("Invalid format of the content encrypted as CIPHERTEXT_3");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	if (error == false &&
                plaintextElementList[0].getType() != CBORType.ByteString &&
                plaintextElementList[0].getType() != CBORType.Integer &&
                plaintextElementList[0].getType() != CBORType.Map) {
	        errMsg = new String("Invalid format of ID_CRED_I");
	        responseCode = ResponseCode.BAD_REQUEST;
	        error = true;
    	}
    	if (error == false) {
        	CBORObject rawIdCredI = plaintextElementList[0];
        	
        	// ID_CRED_I is a CBOR map with 'kid', and only 'kid' was transported
        	if (rawIdCredI.getType() == CBORType.ByteString || rawIdCredI.getType() == CBORType.Integer) {
        	    byte[] kidValue = MessageProcessor.decodeIdentifier(rawIdCredI);
        	    idCredI.Add(HeaderKeys.KID.AsCBOR(), kidValue);
        	}
        	else if (rawIdCredI.getType() == CBORType.Map) {
        	    idCredI = rawIdCredI;
        	}
        	else {
        	    errMsg = new String("Invalid format for ID_CRED_I");
        	    responseCode = ResponseCode.BAD_REQUEST;
        	    error = true;
        	}
    	}    	
    	if (error == false && plaintextElementList[1].getType() != CBORType.ByteString) {
    	    errMsg = new String("Signature_or_MAC_3 must be a byte string");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	if (error == false && plaintextElementList.length > 2) {
		   // EAD_3 is present
		   ead3 = preParseEAD(plaintextElementList, 2, 3, session.getSupportedEADs());
		   
		   if (ead3.length == 1 && ead3[0].getType() == CBORType.TextString) {
		         errMsg = new String(ead3[0].toString());
		         responseCode = ResponseCode.BAD_REQUEST;
			     ead3 = null;
		         error = true;
		   }
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode);
    	}
    	
    	error = false;
    	
    	CBORObject peerCredentialCBOR = null;

    	// Invoke the retrieval and/or validation of CRED_I, and the processing of EAD items in EAD_3 (if any)
    	SideProcessor sideProcessor = session.getSideProcessor();
 	    CBORObject[] sideProcessorInfo = new CBORObject[1];
 	    sideProcessorInfo[0] = CBORObject.FromObject(idCredI);
    	
 	    sideProcessor.sideProcessingMessage3PreVerification(sideProcessorInfo, ead3);

	    // A fatal error occurred
	    if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, false).
	    		containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
	    	errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, false).
	        	get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
	        int responseCodeValue = sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, false).
	        	get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE)).AsInt32();
	        responseCode = ResponseCode.valueOf(responseCodeValue);
	        error = true;

	        // No need to keep this information any longer in the side processor object
	        sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_3, Constants.SIDE_PROCESSOR_OUTER_ERROR, false);
	    }
	        	
    	// If no fatal error occurred, the side processor object includes the authentication credential
    	// of the other peer, if a valid one was found during the side processing above.
 	   	if (error == false && sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, false).
 	   						  containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_CRED))) {
 	   		peerCredentialCBOR = sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, false).
 	   							 get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_CRED)).get(0).
 	   							 get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_CRED_VALUE));

 	    	if (peerCredentialCBOR == null) {
 	        	errMsg = new String("Unable to retrieve the peer credential");
 	        	responseCode = ResponseCode.BAD_REQUEST;
 	        	error = true;
 	    	}
	    }
    	
        // No need to keep this information any longer in the side processor object
        sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_3, Constants.SIDE_PROCESSOR_OUTER_CRED, false);
        
        // If EAD_3 was present, print any available results from processing its EAD items.
        sideProcessor.showResultsFromSideProcessing(Constants.EDHOC_MESSAGE_3, false);
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator, errMsg, null, responseCode);
    	}
    	
    	
    	OneKey peerKey = peerPublicKeys.get(idCredI);
    	session.setPeerLongTermPublicKey(peerKey);
    	
    	
        // Compute PRK_4e3m
        byte[] prk4e3m = computePRK4e3m(session);
    	if (prk4e3m == null) {
    		errMsg = new String("Error when computing PRK_4e3m");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("PRK_4e3m", prk4e3m);
    	}
    	session.setPRK4e3m(prk4e3m);

    	
    	/* Start verifying Signature_or_MAC_3 */

    	byte[] peerCredential = peerCredentialCBOR.GetByteString(); // CRED_I
    	    	
    	session.setPeerIdCred(idCredI); // Store ID_CRED_I
    	
    	// Compute MAC_3
    	byte[] mac3 = computeMAC3(session, prk4e3m, th3, idCredI, peerCredential, ead3);
    	if (mac3 == null) {
    		errMsg = new String("Error when computing MAC_3");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_3", mac3);
    	}
    	
    	
    	// Verify Signature_or_MAC_3
    	
    	byte[] signatureOrMac3 = plaintextElementList[1].GetByteString();
    	if (debugPrint && signatureOrMac3 != null) {
    		Util.nicePrint("Signature_or_MAC_3", signatureOrMac3);
    	}
    	
        // Prepare the external data, as a CBOR sequence
    	externalData = computeExternalData(th3, peerCredential, ead3);
    	if (externalData == null) {
    		errMsg = new String("Error when computing the external data for MAC_3");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
    		return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
    							errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to verify Signature_or_MAC_3", externalData);
    	}
    	
    	if (!verifySignatureOrMac3(session, signatureOrMac3, externalData, mac3)) {
        	errMsg = new String("Non valid Signature_or_MAC_3");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode);
    	}
    	
    	/* End verifying Signature_or_MAC_3 */
    	
    	// Invoke the processing of EAD items in EAD_3 (if any)
    	// that had to wait for a successful verification of Signature_or_MAC_3
    	if (ead3!= null && ead3.length != 0) {
    		sideProcessor.sideProcessingMessage3PostVerification(sideProcessorInfo, ead3);
    	}

    	// A fatal error occurred
    	if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, true).
    			containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
    	   errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, true).
    	         get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
    	         get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
    	   int responseCodeValue = sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, true).
    	         get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
    	         get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE)).AsInt32();
    	   responseCode = ResponseCode.valueOf(responseCodeValue);
    	   error = true;
    	      
    	   // No need to keep this information any longer in the side processor object
    	   sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_3, Constants.SIDE_PROCESSOR_OUTER_ERROR, true);
    	}
    	
        // If EAD_3 was present, print any available results from processing its EAD items.
        sideProcessor.showResultsFromSideProcessing(Constants.EDHOC_MESSAGE_3, true);
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}
    	
    	
    	
    	
    	/* Compute TH4 */
    	
        byte[] th3SerializedCBOR = CBORObject.FromObject(th3).EncodeToBytes();
        
    	byte[] th4 = computeTH4(session, th3SerializedCBOR, plaintext3, peerCredential);
    	
        if (th4 == null) {
        	errMsg = new String("Error when computing TH_4");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
        	return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
        						errMsg, null, responseCode);
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_4", th4);
    	}
        session.setTH4(th4);

    	/* Compute PRK_out */
    	byte[] prkOut = computePRKout(session, prk4e3m);
        if (prkOut == null) {
        	System.err.println("Error when computing PRK_out");
    		errMsg = new String("Error when computing PRK_out");
    		error = true;
        }
        else if (debugPrint) {
    		Util.nicePrint("PRK_out", prkOut);
    	}
    	session.setPRKout(prkOut);

    	/* Compute PRK_exporter */
    	byte[] prkExporter = computePRKexporter(session, prkOut);
        if (prkExporter == null) {
        	System.err.println("Error when computing PRK_exporter");
    		errMsg = new String("Error when computing PRK_exporter");
    		error = true;
        }
        else if (debugPrint) {
    		Util.nicePrint("PRK_exporter", prkExporter);
    	}
    	session.setPRKexporter(prkExporter);
        
    	
    	/* Delete ephemeral keys and other temporary material */
    	
    	session.deleteTemporaryMaterial();
    	
    	
		/* Return an indication that the protocol is completed, possibly with the provided External Authorization Data */
		
		// A CBOR byte string with zero length, indicating that the protocol has successfully completed
		byte[] reply = new byte[] {};
		processingResult.add(CBORObject.FromObject(reply));

		// The Connection Identifier C_R used by the Responder
		CBORObject connectionIdentifierResponderCbor = CBORObject.FromObject(connectionIdentifierResponder);
		processingResult.add(connectionIdentifierResponderCbor);
		
		// External Authorization Data from EAD_3 (if present)
		if (ead3 != null) {
		    CBORObject eadArray = CBORObject.NewArray();
		    for (int i = 0; i < ead3.length; i++) {
		        eadArray.Add(ead3[i]);
		    }
		    processingResult.add(eadArray);
		}
		
		session.setCurrentStep(Constants.EDHOC_AFTER_M3);
		
		System.out.println("\nCompleted processing of EDHOC Message 3\n");
		return processingResult;
		
	}
	
	
    /**
     *  Process an EDHOC Message 4
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 4
     * @param isReq   True if the CoAP message is a request, or False otherwise
     * @param connectionIdInitiator   The already known connection identifier of the Initiator.
     * 								  It is set to null if expected in the EDHOC Message 4.
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @return   A list of CBOR Objects including up to two elements.
     * 
     *           The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC message_4 was successfully processed; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *
     *           In case (ii), the second element is a CBOR integer, with value the CoAP response code
     *           to use for the EDHOC Error Message, if this is a CoAP response.
     */
	public static List<CBORObject> readMessage4(byte[] sequence, boolean isReq, byte[] connectionIdInitiator,
												HashMap<CBORObject,EdhocSession> edhocSessions,
			                                    Set<CBORObject> usedConnectionIds) {
		
		if (sequence == null || edhocSessions == null || usedConnectionIds == null)
			return null;

		byte[] connectionIdentifierInitiator = null; // The connection identifier of the Initiator
		byte[] connectionIdentifierResponder = null; // The connection identifier of the Responder
		
		CBORObject[] ead4 = null; // Will be set if External Authorization Data is present as EAD4
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED_ERROR; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		EdhocSession session = null; // The session used for this EDHOC execution
		
		int index = 0;
		CBORObject[] objectList = null;
		try {
			objectList = CBORObject.DecodeSequenceFromBytes(sequence);
		}
		catch (Exception e) {
		    errMsg = new String("Malformed or invalid EDHOC message_4");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}

		
		/* Consistency checks */
		
		// If EDHOC Message 4 is transported in a CoAP request, C_I is present as first element of the CBOR sequence
		if (error == false && isReq == true) {
			if (error == false && objectList[index].getType() != CBORType.ByteString &&
				objectList[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_I must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}

			if (error == false) {
				connectionIdentifierInitiator = decodeIdentifier(objectList[index]);
				if (connectionIdentifierInitiator == null) {
				    errMsg = new String("Invalid encoding of C_I");
				    responseCode = ResponseCode.BAD_REQUEST;
				    error = true;
				}
				else {
					index++;
					if (debugPrint) {
					    Util.nicePrint("Connection Identifier of the Initiator", connectionIdentifierInitiator);
					}
				}
			}
			
		}
		
		if (error == false && isReq == false) {
			connectionIdentifierInitiator = connectionIdInitiator;
			if (debugPrint) {
			    Util.nicePrint("Connection Identifier of the Initiator", connectionIdentifierInitiator);
			}
		}
		
		if (error == false) {
			CBORObject connectionIdentifierInitiatorCbor = CBORObject.FromObject(connectionIdentifierInitiator);
			session = edhocSessions.get(connectionIdentifierInitiatorCbor);
			
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
			else if (session.getApplicationProfile().getUseMessage4() == false) {
				errMsg = new String("EDHOC Message 4 is not used for this application profile");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else if (session.getCurrentStep() != Constants.EDHOC_SENT_M3) {
				errMsg = new String("The protocol state is not waiting for an EDHOC Message 4");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
		}
		
		if (session != null && session.getPeerConnectionId() != null)
				connectionIdentifierResponder = session.getPeerConnectionId();


		// CIPHERTEXT_4
		byte[] ciphertext4 = null;
		if (error == false && objectList[index].getType() != CBORType.ByteString) {
			errMsg = new String("CIPHERTEXT_4 must be a byte string");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		else {
			ciphertext4 = objectList[index].GetByteString();
			if (ciphertext4 == null) {
				errMsg = new String("Error when retrieving CIPHERTEXT_4");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
		}
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_4, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
		}

		
		
		/* Compute the plaintext */
		
		if (debugPrint && ciphertext4 != null) {
		    Util.nicePrint("CIPHERTEXT_4", ciphertext4);
		}
		
		// Prepare the External Data as including only TH4
    	byte[] externalData = session.getTH4();

    	if (externalData == null) {
    		errMsg = new String("Error when computing the external data for CIPHERTEXT_4");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to compute CIPHERTEXT_4", externalData);
    	}
    	    	
    	
        // Compute the key material
      
    	// Compute K and IV to protect the COSE object
    	
    	byte[] k4ae = computeKey(Constants.EDHOC_K_4, session);
    	if (k4ae == null) {
    		errMsg = new String("Error when computing K");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K", k4ae);
    	}

    	byte[] iv4ae = computeIV(Constants.EDHOC_IV_4, session);
    	if (iv4ae == null) {
    		errMsg = new String("Error when computing IV");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV", iv4ae);
    	}
        
    	byte[] plaintext4 = decryptCiphertext4(session, externalData, ciphertext4, k4ae, iv4ae);
    	if (plaintext4 == null) {
    	    errMsg = new String("Error when decrypting CIPHERTEXT_4");
    	    responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    	    Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
    	    return processError(errorCode, Constants.EDHOC_MESSAGE_4, !isReq, connectionIdentifierResponder,
    	    					errMsg, null, responseCode);
    	}
    	else if (debugPrint) {
    	    Util.nicePrint("Plaintext retrieved from CIPHERTEXT_4", plaintext4);
    	}
    	
        /* End computing the plaintext */
    	
    	
    	// Parse the outer plaintext as a CBOR sequence. To be valid, this is
    	// either the empty plaintext or the External Authorization Data EAD_4 
    	error = false;
    	CBORObject[] plaintextElementList = null;
    	
    	if (plaintext4.length != 0) {
    		try {
    			plaintextElementList = CBORObject.DecodeSequenceFromBytes(plaintext4);
    		}
    		catch (Exception e) {
        		errMsg = new String("Malformed or invalid EAD_4");
        		responseCode = ResponseCode.BAD_REQUEST;
    			error = true;
    		}
    		
    		if (error == false && plaintextElementList.length > 0) {
			   // EAD_4 is present
			   ead4 = preParseEAD(plaintextElementList, 0, 4, session.getSupportedEADs());
			   
			   if (ead4.length == 1 && ead4[0].getType() == CBORType.TextString) {
			         errMsg = new String(ead4[0].toString());
			         responseCode = ResponseCode.BAD_REQUEST;
				     ead4 = null;
			         error = true;
			   }
    		}
    	}
    	    	

		SideProcessor sideProcessor = session.getSideProcessor();
		
		// Invoke the processing of EAD items in EAD_4 (if any)
		if (error == false && ead4!= null && ead4.length != 0) {

			sideProcessor.sideProcessingMessage4(ead4);
			
			// A fatal error occurred
			if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_4, false).
					containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
				errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_4, false).
						get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
						get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
				int responseCodeValue = sideProcessor.getResults(Constants.EDHOC_MESSAGE_4, false).
			            get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
			            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE)).AsInt32();
				responseCode = ResponseCode.valueOf(responseCodeValue);
				error = true;
				
				// No need to keep this information any longer in the side processor object
				sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_4, Constants.SIDE_PROCESSOR_OUTER_ERROR, false);
			}
		}
		
		// If EAD_4 was present, print any available results from processing its EAD items.
		sideProcessor.showResultsFromSideProcessing(Constants.EDHOC_MESSAGE_4, false);
    	    	
    	
    	// Return an EDHOC Error Message
    	if (error == true) {
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_4, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode);
    	}

    	session.setPRK4e3m(null);
    	session.setTH4(null);
    	
		
		/* Return an indication that message_4 is fine */
		
		// A CBOR byte string with zero length, indicating that the EDHOC Message 4 is fine
		byte[] reply = new byte[] {};
		processingResult.add(CBORObject.FromObject(reply));
		
		// External Authorization Data from EAD_4 (if present)
		if (ead4 != null) {
		    CBORObject eadArray = CBORObject.NewArray();
		    for (int i = 0; i< ead4.length; i++) {
		        eadArray.Add(ead4[i]);
		    }
		    processingResult.add(eadArray);
		}
				
    	session.setCurrentStep(Constants.EDHOC_AFTER_M4);
		
		System.out.println("\nCompleted processing of EDHOC Message 4");
		return processingResult;
		
	}
	
	
    /**
     *  Parse an EDHOC Error Message
     * @param sequence   The CBOR sequence used as payload of the EDHOC Error Message
     * @param cX   The connection identifier of the recipient; set to null if expected in the EDHOC Error Message
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @return  The elements of the EDHOC Error Message as CBOR objects, or null in case of errors
     */
	public static CBORObject[] readErrorMessage(byte[] sequence, byte[] connectionIdentifier,
												HashMap<CBORObject, EdhocSession> edhocSessions) {
		
		if (edhocSessions == null || sequence == null) {
			System.err.println("Error when processing EDHOC Error Message");
			return null;
		}
		
		int index = 0;
		EdhocSession mySession = null;
		CBORObject[] objectList = null;
		try {
			objectList = CBORObject.DecodeSequenceFromBytes(sequence);
		}
		catch (Exception e) {
			System.err.println("Malformed or invalid EDHOC Error Message");
			return null;
		}
		
		if (objectList.length == 0 || objectList.length > 3) {
			System.err.println("Error when processing EDHOC Error Message - Zero or too many elements");
			return null;
		}

		// The connection identifier of the recipient is provided by the method caller
		if (connectionIdentifier != null) {
			CBORObject connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
			mySession = edhocSessions.get(connectionIdentifierCbor);
		}
		// The connection identifier is expected as first element in the EDHOC Error Message
		else {
			if (objectList[index].getType() == CBORType.ByteString || objectList[index].getType() == CBORType.Integer) {
				byte[] retrievedConnectionIdentifier = decodeIdentifier(objectList[index]);
				if (retrievedConnectionIdentifier != null) {
					CBORObject connectionIdentifierCbor = CBORObject.FromObject(retrievedConnectionIdentifier);
					mySession = edhocSessions.get(connectionIdentifierCbor);
					index++;		
				}
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
			// This is not admitted
			System.err.println("Received EDHOC error message with ERR_CODE 0");
			return null;
		}
		else if (errorCode == Constants.ERR_CODE_UNSPECIFIED_ERROR) {
			if (objectList[index].getType() != CBORType.TextString) {
				System.err.println("Error when processing EDHOC Error Message - Invalid format of ERR_INFO");
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
							System.err.println("Error when processing EDHOC Error Message - " +
											   "Invalid format for elements of SUITES_R");
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
     * @return  The raw payload to transmit as EDHOC Message 1, or null in case of errors
     */
	public static byte[] writeMessage1(EdhocSession session) {
		
        // Prepare the list of CBOR objects to build the CBOR sequence
        List<CBORObject> objectList = new ArrayList<>();
        
        // C_X equal to the CBOR simple value 'true' (i.e., 0xf5), if EDHOC message_1 is transported in a CoAP request
        if (session.isClientInitiated() == true) {
        	objectList.add(CBORObject.True);
        }
        
        // METHOD as CBOR integer
        int method = session.getMethod();
        objectList.add(CBORObject.FromObject(method));
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("EDHOC Message 1 content:\n");
        	CBORObject obj = CBORObject.FromObject(method);
        	byte[] objBytes = obj.EncodeToBytes();
        	Util.nicePrint("METHOD", objBytes);
        }
        
        // SUITES_I as CBOR integer or CBOR array
        List<Integer> supportedCipherSuites = session.getSupportedCipherSuites();
        List<Integer> peerSupportedCipherSuites = session.getPeerSupportedCipherSuites();
        
    	int selectedSuite = -1;
    	int preferredSuite = supportedCipherSuites.get(0).intValue();
    	
    	// No SUITES_R has been received, so it is not known what cipher suites the responder supports
    	if (peerSupportedCipherSuites.size() == 0) {
    		// The selected cipher suite is the most preferred by the initiator
    		selectedSuite = preferredSuite;
    	}
    	// SUITES_R has been received, so it is known what cipher suites the responder supports
    	else {
    		// Pick the selected cipher suite as the most preferred by the Initiator from the ones supported by the Responder
    		for (Integer i : supportedCipherSuites) {
    			if (peerSupportedCipherSuites.contains(i)) {
    				selectedSuite = i.intValue();
    				break;
    			}
    		}
    	}
    	if (selectedSuite == -1) {
    		System.err.println("Impossible to agree on a mutually supported cipher suite");
    		return null;
    	}
    	
		// Set the selected cipher suite
    	session.setSelectedCipherSuite(selectedSuite);
    	
		// Set the asymmetric key pair, CRED and ID_CRED of the Initiator to use in this session
    	session.setAuthenticationCredential();
    	
    	// Set the ephemeral keys of the Initiator to use in this session
    	if (session.getEphemeralKey() == null)
    		session.setEphemeralKey();
    	
    	CBORObject suitesI;
    	if (selectedSuite == preferredSuite) {
    		// SUITES_I is only the selected suite, as a CBOR integer
    		suitesI = CBORObject.FromObject(selectedSuite);
    	}
    	else {
    		// SUITES_I is a CBOR array
    		// The elements are the Initiator's supported cipher suite in decreasing order of preference,
    		// up until and including the selected suite as last element of the array.
    		suitesI = CBORObject.NewArray();
    		for (Integer i : supportedCipherSuites) {
    			int suite = i.intValue();
    			suitesI.Add(suite);
    			if (suite == selectedSuite) {
    				break;
    			}
    		}
    	}
    	objectList.add(suitesI);
        if (debugPrint) {
        	byte[] objBytes = suitesI.EncodeToBytes();
        	Util.nicePrint("SUITES_I", objBytes);
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
        	Util.nicePrint("G_X", gX.GetByteString());
        }
		
		// C_I
        byte[] connectionIdentifierInitiator = session.getConnectionId();
        CBORObject cI = encodeIdentifier(connectionIdentifierInitiator);
		objectList.add(cI);
        if (debugPrint) {
           	Util.nicePrint("Connection Identifier of the Initiator", connectionIdentifierInitiator);
        	Util.nicePrint("C_I", cI.EncodeToBytes());
        }

        SideProcessor sideProcessor = session.getSideProcessor();
        
        // Produce possible EAD items following early instructions from the application
        sideProcessor.produceIndependentEADs(Constants.EDHOC_MESSAGE_1);
        
        // A fatal error occurred
        if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_1, false).
                containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
            
        	String errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_1, false).
                    get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
                    get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
        	
    		System.err.println(errMsg);
    		
            // No need to keep this information any longer in the side processor object
            sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_1, Constants.SIDE_PROCESSOR_OUTER_ERROR, false);
            
    		return null;
        }
        
        List<CBORObject> ead1 = session.getSideProcessor().getProducedEADs(Constants.EDHOC_MESSAGE_1);
        
        // There are EAD items to include in EAD_1
        if (ead1 != null && ead1.size() != 0) {
        	for (int i = 0; i < ead1.size(); i++) {
        		objectList.add(ead1.get(i));
        	}
        }
        if (debugPrint) {
        	System.out.println("===================================");
        }
		
        
    	/* Prepare EDHOC Message 1 */
    	
    	if (debugPrint) {
    	    byte[] sequenceBytesToPrint;
    	    byte[] sequenceBytes = Util.buildCBORSequence(objectList);
    	    
    	    // If EDHOC message_1 is transported in a CoAP request, do not print
    	    // the prepended C_X equal to the CBOR simple value 'true' (i.e., 0xf5)
    	    if (session.isClientInitiated() == true) {
    	        List<CBORObject> trimmedSequence = new ArrayList<CBORObject>();
    	        for (int i = 1; i < objectList.size(); i++) {
    	            trimmedSequence.add(objectList.get(i));
    	        }
    	        sequenceBytesToPrint = Util.buildCBORSequence(trimmedSequence);
    	    }
    	    else {
    	        sequenceBytesToPrint = sequenceBytes;
    	    }
    	    Util.nicePrint("EDHOC Message 1", sequenceBytesToPrint);
    	}
        
        return Util.buildCBORSequence(objectList);
		
	}

	
    /**
     *  Write an EDHOC Message 2
     * @param session   The EDHOC session associated to this EDHOC message
     * @return  The raw payload to transmit as EDHOC Message 2 or EDHOC Error Message; or null in case of errors
     */
	public static byte[] writeMessage2(EdhocSession session) {
		
		List<CBORObject> objectList = new ArrayList<>();
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED_ERROR; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = ResponseCode.INTERNAL_SERVER_ERROR;; // The CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 2:\n");
        }
		
        
        // C_I, if EDHOC message_2 is transported in a CoAP request
		if (!session.isClientInitiated()) {
			byte[] connectionIdentifierInitiator = session.getPeerConnectionId(); 
			CBORObject cI = encodeIdentifier(connectionIdentifierInitiator);
			objectList.add(cI);
	        if (debugPrint) {
	        	Util.nicePrint("Connection Identifier of the Initiator", connectionIdentifierInitiator);
	        	Util.nicePrint("C_I", cI.EncodeToBytes());
	        }
		}
		
    	// Set the ephemeral keys of the Responder to use in this session
    	if (session.getEphemeralKey() == null)
    		session.setEphemeralKey();
		
		// G_Y as a CBOR byte string
		int selectedSuite = session.getSelectedCipherSuite();
        CBORObject gY = null;
        if (selectedSuite == Constants.EDHOC_CIPHER_SUITE_0 || selectedSuite == Constants.EDHOC_CIPHER_SUITE_1) {
			gY = session.getEphemeralKey().PublicKey().get(KeyKeys.OKP_X);
		}
		else if (selectedSuite == Constants.EDHOC_CIPHER_SUITE_2 || selectedSuite == Constants.EDHOC_CIPHER_SUITE_3) {
			gY = session.getEphemeralKey().PublicKey().get(KeyKeys.EC2_X);
		}
    	if (debugPrint) {
    	    Util.nicePrint("G_Y", gY.GetByteString());
    	}
		
		// C_R
    	byte[] connectionIdentifierResponder = session.getConnectionId(); 
		CBORObject cR = encodeIdentifier(connectionIdentifierResponder);
    	if (debugPrint) {
    		Util.nicePrint("Connection Identifier of the Responder", connectionIdentifierResponder);
    	    Util.nicePrint("C_R", cR.EncodeToBytes());
    	}
    	
    	
        // Compute TH_2
        
        byte[] hashMessage1 = session.getHashMessage1(); // the hash of message_1, as plain bytes
        byte[] hashMessage1SerializedCBOR = CBORObject.FromObject(hashMessage1).EncodeToBytes();
        byte[] gYSerializedCBOR = gY.EncodeToBytes();
        
        byte[] th2 = computeTH2(session, gYSerializedCBOR, hashMessage1SerializedCBOR);
        if (th2 == null) {
    		System.err.println("Error when computing TH_2");
    		errMsg = new String("Error when computing TH_2");
    		error = true;
        }
        else if (debugPrint) {
        	Util.nicePrint("H(message_1)", hashMessage1);
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
    		System.err.println("Error when computing the Diffie-Hellman Secret");
    		errMsg = new String("Error when computing the Diffie-Hellman Secret");
    		error = true;
        }
        else if (debugPrint) {
    		Util.nicePrint("G_XY", dhSecret);
    	}
        
        // Compute PRK_2e
        if (error == false) {
	        String hashAlgorithm = EdhocSession.getEdhocHashAlg(session.getSelectedCipherSuite());
	    	
	    	prk2e = computePRK2e(th2, dhSecret, hashAlgorithm);
	    	
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
        }
        
        // Compute PRK_3e2m
        if (error == false) {
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
        }
    	
        // Produce possible EAD items following early instructions from the application
        if (error == false) {
            SideProcessor sideProcessor = session.getSideProcessor();
            
            sideProcessor.produceIndependentEADs(Constants.EDHOC_MESSAGE_2);
            
    	    // A fatal error occurred
    	    if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, false).
    	    		containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
    	    	errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, false).
    	        	get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
    	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
    	        int responseCodeValue = sideProcessor.getResults(Constants.EDHOC_MESSAGE_2, false).
    	        	get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
    	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE)).AsInt32();
    	        responseCode = ResponseCode.valueOf(responseCodeValue);
    	        error = true;
    	         
    	        // No need to keep this information any longer in the side processor object
    	        sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_2, Constants.SIDE_PROCESSOR_OUTER_ERROR, false);
    	    }
        }
        CBORObject ead2[] = null;
        if (error == false) {
    	    List<CBORObject> myList = session.getSideProcessor().getProducedEADs(Constants.EDHOC_MESSAGE_2);

    		// There are EAD items to include in EAD_2
    		if (myList != null && myList.size() != 0) {
    			ead2 = new CBORObject[myList.size()];
    		    for (int i = 0; i < myList.size(); i++) {
    		   	 ead2[i] = myList.get(i);
    		    }
    		}
        }
        
        
    	/* Start computing Signature_or_MAC_2 */    	
    	
        byte[] mac2 = null;

    	// Compute MAC_2
        if (error == false) {       	
	    	mac2 = computeMAC2(session, prk3e2m, th2, cR, session.getIdCred(), session.getCred(), ead2);
	    	if (mac2 == null) {
	    		System.err.println("Error when computing MAC_2");
	    		errMsg = new String("Error when computing MAC_2");
	    		error = true;
	    	}
	    	else if (debugPrint) {
	    		Util.nicePrint("MAC_2", mac2);
	    	}
        }
    	
    	// Compute Signature_or_MAC_2
    	
        // Compute the external data for the external_aad, as a CBOR sequence
        byte[] externalData = null;
        if (error == false) {
			externalData = computeExternalData(th2, session.getCred(), ead2);
			if (externalData == null) {
				System.err.println("Error when computing the external data for MAC_2");
				errMsg = new String("Error when computing the external data for MAC_2");
				error = true;
			}
        }
    	
    	byte[] signatureOrMac2 = computeSignatureOrMac2(session, mac2, externalData);
        if (error == false) {
			if (signatureOrMac2 == null) {
				System.err.println("Error when computing Signature_or_MAC_2");
				errMsg = new String("Error when computing Signature_or_MAC_2");
				error = true;
			}
			else if (debugPrint) {
				Util.nicePrint("Signature_or_MAC_2", signatureOrMac2);
			}
        }
    	
    	/* End computing Signature_or_MAC_2 */ 
    
    	
    	/* Start computing CIPHERTEXT_2 */
    
        byte[] plaintext2 = null;
    	byte[] keystream2 = null;
        if (error == false) {
	    	// Prepare the plaintext
	    	List<CBORObject> plaintextElementList = new ArrayList<>();
	    	plaintextElementList.add(cR);
	    	CBORObject plaintextElement = null;
	    	if (session.getIdCred().ContainsKey(HeaderKeys.KID.AsCBOR())) {
	    		// ID_CRED_R uses 'kid', whose value is the only thing to include in the plaintext
	    		CBORObject kid = session.getIdCred().get(HeaderKeys.KID.AsCBOR());
	    		plaintextElement = MessageProcessor.encodeIdentifier(kid.GetByteString());
	    	}
	    	else {
	    		plaintextElement = session.getIdCred();
	    	}
	    	plaintextElementList.add(plaintextElement);
	    	plaintextElementList.add(CBORObject.FromObject(signatureOrMac2));
	    	if (ead2 != null) {
	    		for (int i = 0; i < ead2.length; i++)
	    			plaintextElementList.add(ead2[i]);
	    	}
	    	plaintext2 = Util.buildCBORSequence(plaintextElementList);
	    	if (debugPrint && plaintext2 != null) {
	    		Util.nicePrint("Plaintext to compute CIPHERTEXT_2", plaintext2);
	    	}
	    	
	    	// Compute KEYSTREAM_2
	        if (error == false) {
		    	keystream2 = computeKeystream2(session, plaintext2.length);
		    	if (keystream2== null) {
		    		System.err.println("Error when computing KEYSTREAM_2");
		    		errMsg = new String("Error when computing KEYSTREAM_2");
		    		error = true;
		    	}
		    	else if (debugPrint) {
		    		Util.nicePrint("KEYSTREAM_2", keystream2);
		    	}
	        }
		}
        
    	
    	// Compute CIPHERTEXT_2
	    if (error == false) {
	        
	    	byte[] ciphertext2 = Util.arrayXor(plaintext2, keystream2);

	    	// Store PLAINTEXT_2 for the later computation of TH_3
	    	session.setPlaintext2(plaintext2);
	    	
	    	if (debugPrint && ciphertext2 != null) {
	    		Util.nicePrint("CIPHERTEXT_2", ciphertext2);
	    	}
	
	    	/* End computing CIPHERTEXT_2 */
	    	
	    	
	    	// Finish building the outer CBOR sequence
	    	
	    	// Concatenate G_Y with CIPHERTEXT_2
	    	byte[] gY_Ciphertext2 = new byte[gY.GetByteString().length + ciphertext2.length];
	    	System.arraycopy(gY.GetByteString(), 0, gY_Ciphertext2, 0, gY.GetByteString().length);
	    	System.arraycopy(ciphertext2, 0, gY_Ciphertext2, gY.GetByteString().length, ciphertext2.length);
	    	
	    	// Wrap the result in a single CBOR byte string, included in the outer CBOR sequence of EDHOC Message 2
	    	objectList.add(CBORObject.FromObject(gY_Ciphertext2));
	    	if (debugPrint) {
	    	    Util.nicePrint("G_Y | CIPHERTEXT_2", gY_Ciphertext2);
	    	}

        }

    	
		/* Prepare an EDHOC Error Message */
		
		if (error == true) {
			byte[] connectionIdentifierInitiator = session.getPeerConnectionId();
			
			List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_1,
															 !session.isClientInitiated(),
															 connectionIdentifierInitiator,
															 errMsg, null, responseCode);
			return processingResult.get(0).GetByteString();
		}
    	
    	
    	/* Prepare EDHOC Message 2 */
    	
		if (debugPrint) {
		    byte[] sequenceBytesToPrint;
		    byte[] sequenceBytes = Util.buildCBORSequence(objectList);
		    
		    // If EDHOC message_2 is transported in a CoAP request, do not print the prepended C_I
		    if (session.isClientInitiated() == false) {
		    	List<CBORObject> trimmedSequence = new ArrayList<CBORObject>();
		    	for (int i = 1; i < objectList.size(); i++) {
		    		trimmedSequence.add(objectList.get(i));
		    	}
		        sequenceBytesToPrint = Util.buildCBORSequence(trimmedSequence);
		    }
		    else {
		        sequenceBytesToPrint = sequenceBytes;
		    }
		    Util.nicePrint("EDHOC Message 2", sequenceBytesToPrint);
		}
		
        return Util.buildCBORSequence(objectList);
		
	}
	
    /**
     *  Write an EDHOC Message 3
     * @param session   The EDHOC session associated to this EDHOC message
     * @return  The raw payload to transmit as EDHOC Message 3 or EDHOC Error Message; or null in case of errors
     */
	public static byte[] writeMessage3(EdhocSession session) {
		
		List<CBORObject> objectList = new ArrayList<>();
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED_ERROR; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = ResponseCode.INTERNAL_SERVER_ERROR; // The CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 3:\n");
        }
		
        /* Start preparing data_3 */
		
        // C_R, if EDHOC message_3 is transported in a CoAP request
		if (session.isClientInitiated()) {
			byte[] connectionIdentifierResponder = session.getPeerConnectionId();
			CBORObject cR = encodeIdentifier(connectionIdentifierResponder);
			objectList.add(cR);
	        if (debugPrint) {
	        	Util.nicePrint("Connection Identifier of the Responder", connectionIdentifierResponder);
	        	Util.nicePrint("C_R", cR.EncodeToBytes());
	        }
		}
        
		
		/* End preparing data_3 */
		
		
		/* Start computing the inner COSE object */
		
        // Compute TH_3
        
        byte[] th2 = session.getTH2(); // TH_2 as plain bytes
        byte[] th2SerializedCBOR = CBORObject.FromObject(th2).EncodeToBytes();

        byte[] plaintext2 = session.getPlaintext2(); // PLAINTEXT_2 as serialized CBOR Sequence
        byte[] credR = session.getPeerCred();
        
        byte[] th3 = computeTH3(session, th2SerializedCBOR, plaintext2, credR);
        
        if (th3 == null) {
        	System.err.println("Error when computing TH_3");
    		errMsg = new String("Error when computing TH_3");
    		error = true;
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_3", th3);
    	}
        session.setTH3(th3);

        // Compute the key material
        byte[] prk4e3m = null;
        if (error == false) {
	        prk4e3m = computePRK4e3m(session);
	    	if (prk4e3m == null) {
	    		System.err.println("Error when computing PRK_4e3m");
	    		errMsg = new String("Error when computing PRK_4e3m");
	    		error = true;
	    	}
	    	else if (debugPrint) {
	    		Util.nicePrint("PRK_4e3m", prk4e3m);
	    	}
	    	session.setPRK4e3m(prk4e3m);
        }
        
        // Produce possible EAD items following early instructions from the application
        if (error == false) {
            SideProcessor sideProcessor = session.getSideProcessor();
            
            sideProcessor.produceIndependentEADs(Constants.EDHOC_MESSAGE_3);
            
            // A fatal error occurred
            if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, false).
                    containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
                errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, false).
                    get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
                    get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
                int responseCodeValue = sideProcessor.getResults(Constants.EDHOC_MESSAGE_3, false).
                    get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
                    get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE)).AsInt32();
                responseCode = ResponseCode.valueOf(responseCodeValue);
                error = true;
                    
                // No need to keep this information any longer in the side processor object
                sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_3, Constants.SIDE_PROCESSOR_OUTER_ERROR, false);
            }
        }
        CBORObject ead3[] = null;
        if (error == false) {
            List<CBORObject> myList = session.getSideProcessor().getProducedEADs(Constants.EDHOC_MESSAGE_3);

            // There are EAD items to include in EAD_3
            if (myList != null && myList.size() != 0) {
                ead3 = new CBORObject[myList.size()];
                for (int i = 0; i < myList.size(); i++) {
                    ead3[i] = myList.get(i);
                }
            }
        }
        
		
    	/* Start computing Signature_or_MAC_3 */
    	
    	// Compute MAC_3
        byte[] mac3 = null;
        
        if (error == false) {
	    	mac3 = computeMAC3(session, prk4e3m, th3, session.getIdCred(), session.getCred(), ead3);
	    	if (mac3 == null) {
	    		System.err.println("Error when computing MAC_3");
	    		errMsg = new String("Error when computing MAC_3");
	    		error = true;
	    	}
	    	else if (debugPrint) {
	    		Util.nicePrint("MAC_3", mac3);
	    	}
        }
    	
    	
    	// Compute Signature_or_MAC_3
    	
        // Compute the external data for the external_aad, as a CBOR sequence
        byte[] externalData = null;
        if (error == false) {
	    	externalData = computeExternalData(th3, session.getCred(), ead3);
	    	if (externalData == null) {
	    		System.err.println("Error when computing the external data for MAC_3");
	    		errMsg = new String("Error when computing the external data for MAC_3");
	    		error = true;
	    	}
        }
    	
        byte[] signatureOrMac3 = null;
        if (error == false) {
	    	signatureOrMac3 = computeSignatureOrMac3(session, mac3, externalData);
	    	if (signatureOrMac3 == null) {
	    		System.err.println("Error when computing Signature_or_MAC_3");
	    		errMsg = new String("Error when computing Signature_or_MAC_3");
	    		error = true;
	    	}
	    	else if (debugPrint) {
	    		Util.nicePrint("Signature_or_MAC_3", signatureOrMac3);
	    	}
        }
    	
    	/* End computing Signature_or_MAC_3 */
    	
    	
    	/* Start computing CIPHERTEXT_3 */
    	
    	// Compute K_3 and IV_3 to protect the outer COSE object

        byte[] k3 = null;
        if (error == false) {
	    	k3 = computeKey(Constants.EDHOC_K_3, session);
	    	if (k3 == null) {
	    		System.err.println("Error when computing K_3");
	    		errMsg = new String("Error when computing K_3");
	    		error = true;
	    	}
	    	else if (debugPrint) {
	    		Util.nicePrint("K_3", k3);
	    	}
        }
    	
        byte[] iv3 = null;
        if (error == false) {
	    	iv3 = computeIV(Constants.EDHOC_IV_3, session);
	    	if (iv3 == null) {
	    		System.err.println("Error when computing IV_3");
	    		errMsg = new String("Error when computing IV_3");
	    		error = true;
	    	}
	    	else if (debugPrint) {
	    		Util.nicePrint("IV_3", iv3);
	    	}
        }
    	    	
        
        if (error == false) {
	    	// Prepare the External Data as including only TH3
	    	externalData = th3;
	    	
	    	// Prepare the plaintext
	    	List<CBORObject> plaintextElementList = new ArrayList<>();
	    	CBORObject plaintextElement = null;
	    	if (session.getIdCred().ContainsKey(HeaderKeys.KID.AsCBOR())) {
	    	    // ID_CRED_I uses 'kid', whose value is the only thing to include in the plaintext
	    		CBORObject kid = session.getIdCred().get(HeaderKeys.KID.AsCBOR());
	    		plaintextElement = MessageProcessor.encodeIdentifier(kid.GetByteString());
	    	}
	    	else {
	    	    plaintextElement = session.getIdCred();
	    	}    	
	    	plaintextElementList.add(plaintextElement);
	    	plaintextElementList.add(CBORObject.FromObject(signatureOrMac3));
	    	if (ead3 != null) {
	    		for (int i = 0; i < ead3.length; i++)
	    			plaintextElementList.add(ead3[i]);
	    	}    	
	    	byte[] plaintext3 = Util.buildCBORSequence(plaintextElementList);
	    	if (debugPrint && plaintext3 != null) {
	    		Util.nicePrint("Plaintext to compute CIPHERTEXT_3", plaintext3);
	    	}
	    	
	    	
	    	// Compute CIPHERTEXT_3 and add it to the outer CBOR sequence
	    	
	    	byte[] ciphertext3 = computeCiphertext3(session, externalData, plaintext3, k3, iv3);
	    	objectList.add(CBORObject.FromObject(ciphertext3));
	    	if (debugPrint && ciphertext3 != null) {
	    		Util.nicePrint("CIPHERTEXT_3", ciphertext3);
	    	}
	    	
	    	/* End computing CIPHERTEXT_3 */
	    	
	    	
	    	/* Compute TH4 */
	    	
	        byte[] th3SerializedCBOR = CBORObject.FromObject(th3).EncodeToBytes();
	        
	        byte[] credI = session.getCred();
	        byte[] th4 = computeTH4(session, th3SerializedCBOR, plaintext3, credI);
	        
	        if (th4 == null) {
	        	System.err.println("Error when computing TH_4");
	    		errMsg = new String("Error when computing TH_4");
	    		error = true;
	        }
	        else if (debugPrint) {
	    		Util.nicePrint("TH_4", th4);
	    	}
	    	session.setTH4(th4);
		}

    	/* Compute PRK_out */
        byte[] prkOut = null;
        if (error == false) {
	    	prkOut = computePRKout(session, prk4e3m);
	        if (prkOut == null) {
	        	System.err.println("Error when computing PRK_out");
	    		errMsg = new String("Error when computing PRK_out");
	    		error = true;
	        }
	        else if (debugPrint) {
	    		Util.nicePrint("PRK_out", prkOut);
	    	}
	    	session.setPRKout(prkOut);
        }

    	/* Compute PRK_exporter */
        byte[] prkExporter = null;
        if (error == false) {
	    	prkExporter = computePRKexporter(session, prkOut);
	        if (prkExporter == null) {
	        	System.err.println("Error when computing PRK_exporter");
	    		errMsg = new String("Error when computing PRK_exporter");
	    		error = true;
	        }
	        else if (debugPrint) {
	    		Util.nicePrint("PRK_exporter", prkExporter);
	    	}
        }        
    	
        if (error == false) {
	        session.setPRKexporter(prkExporter);
	    	
	    	session.setCurrentStep(Constants.EDHOC_AFTER_M3);
	    	
	    	/* Delete ephemeral keys and other temporary material */
	    	session.deleteTemporaryMaterial();
        }
    	
    	
    	/* Prepare an EDHOC Error Message */

    	if (error == true) {
			byte[] connectionIdentifierResponder = session.getPeerConnectionId();
    	    
    	    List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_2,
    	    												 session.isClientInitiated(),
    	    												 connectionIdentifierResponder,
    	    												 errMsg, null, responseCode);
    	    return processingResult.get(0).GetByteString();
    	}
    	
    	
    	/* Prepare EDHOC Message 3 */
    	
		if (debugPrint) {
		    byte[] sequenceBytesToPrint;
		    byte[] sequenceBytes = Util.buildCBORSequence(objectList);
		    
		    // If EDHOC message_3 is transported in a CoAP request, do not print the prepended C_R
		    if (session.isClientInitiated() == true) {
		    	List<CBORObject> trimmedSequence = new ArrayList<CBORObject>();
		    	for (int i = 1; i < objectList.size(); i++) {
		    		trimmedSequence.add(objectList.get(i));
		    	}
		        sequenceBytesToPrint = Util.buildCBORSequence(trimmedSequence);
		    }
		    else {
		        sequenceBytesToPrint = sequenceBytes;
		    }
		    Util.nicePrint("EDHOC Message 3", sequenceBytesToPrint);
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
		int errorCode = Constants.ERR_CODE_UNSPECIFIED_ERROR; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = ResponseCode.INTERNAL_SERVER_ERROR; // The CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 4:\n");
        }
		
        /* Start preparing data_4 */
		
        // C_I, if EDHOC message_4 is transported in a CoAP request
		if (!session.isClientInitiated()) {
			byte[] connectionIdentifierInitiator = session.getPeerConnectionId(); 
			CBORObject cI = encodeIdentifier(connectionIdentifierInitiator);
			objectList.add(cI);
	        if (debugPrint) {
	        	Util.nicePrint("Connection Identifier of the Initiator", connectionIdentifierInitiator);
	        	Util.nicePrint("C_I", cI.EncodeToBytes());
	        }
		}
		
		
		/* End preparing data_4 */
		
		
		/* Start computing the COSE object */
		
        // Compute the external data for the external_aad
		
		// Prepare the External Data as including only TH4
    	byte[] externalData = session.getTH4();

    	if (externalData == null) {
    		System.err.println("Error when computing the external data for CIPHERTEXT_4");
    		errMsg = new String("Error when computing the external data for CIPHERTEXT_4");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to compute CIPHERTEXT_4", externalData);
    	}
    	
    	
    	// Produce possible EAD items following early instructions from the application
    	if (error == false) {
    	    SideProcessor sideProcessor = session.getSideProcessor();
    	    
    	    sideProcessor.produceIndependentEADs(Constants.EDHOC_MESSAGE_4);
    	    
    	    // A fatal error occurred
    	    if (sideProcessor.getResults(Constants.EDHOC_MESSAGE_4, false).
    	            containsKey(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR))) {
    	        errMsg = new String(sideProcessor.getResults(Constants.EDHOC_MESSAGE_4, false).
    	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
    	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION)).AsString());
    	        int responseCodeValue = sideProcessor.getResults(Constants.EDHOC_MESSAGE_4, false).
    	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_OUTER_ERROR)).get(0).
    	            get(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE)).AsInt32();
    	        responseCode = ResponseCode.valueOf(responseCodeValue);
    	        error = true;
    	            
    	        // No need to keep this information any longer in the side processor object
    	        sideProcessor.removeResultSet(Constants.EDHOC_MESSAGE_4, Constants.SIDE_PROCESSOR_OUTER_ERROR, false);
    	    }
    	}
    	CBORObject ead4[] = null;
    	if (error == false) {
    	    List<CBORObject> myList = session.getSideProcessor().getProducedEADs(Constants.EDHOC_MESSAGE_4);

    	    // There are EAD items to include in EAD_4
    	    if (myList != null && myList.size() != 0) {
    	        ead4 = new CBORObject[myList.size()];
    	        for (int i = 0; i < myList.size(); i++) {
    	            ead4[i] = myList.get(i);
    	        }
    	    }
    	}
    	
    	
        // Prepare the plaintext
    	byte[] plaintext4 = new byte[] {};
    	if (error == false) {
	    	if (ead4 != null) {
	    		List<CBORObject> plaintextElementList = new ArrayList<>();
	    	    for (int i = 0; i < ead4.length; i++) {
	    	        plaintextElementList.add(ead4[i]);
	    	    }
	    	    	plaintext4 = Util.buildCBORSequence(plaintextElementList);
	    	}
	    	if (debugPrint && error == false && plaintext4 != null) {
		        Util.nicePrint("Plaintext to compute CIPHERTEXT_4", plaintext4);
		    }
    	}
    	
    	
        // Compute the key material
      
    	// Compute K and IV to protect the COSE object
    	
    	byte[] k4 = null;
    	if (error == false) {    	
			k4 = computeKey(Constants.EDHOC_K_4, session);
			if (k4 == null) {
				System.err.println("Error when computing K_4");
				errMsg = new String("Error when computing K_4");
				error = true;
			}
			else if (debugPrint) {
				Util.nicePrint("K_4", k4);
			}
    	}

    	byte[] iv4 = null;
    	if (error == false) {
	    	iv4 = computeIV(Constants.EDHOC_IV_4, session);
	    	if (iv4 == null) {
	    		System.err.println("Error when computing IV_4");
	    		errMsg = new String("Error when computing IV_4");
	    		error = true;
	    	}
	    	else if (debugPrint) {
	    		Util.nicePrint("IV_4", iv4);
	    	}
    	}
    	
		
    	// Encrypt the COSE object and take the ciphertext as CIPHERTEXT_4
    	byte[] ciphertext4 = null;
    	if (error == false) {
	    	ciphertext4 = computeCiphertext4(session, externalData, plaintext4, k4, iv4);
	    	if (ciphertext4 == null) {
	    		System.err.println("Error when computing CIPHERTEXT_4");
	    		errMsg = new String("Error when computing CIPHERTEXT_4");
	    		error = true;
	    	}
	    	else if (debugPrint) {
	    		Util.nicePrint("CIPHERTEXT_4", ciphertext4);
	    	}
    	}
    	
        /* End computing the inner COSE object */

    	
    	/* Prepare an EDHOC Error Message */

    	if (error == true) {
    	    byte[] connectionIdentifierInitiator = session.getPeerConnectionId();
    	    
    	    List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_3,
    	    												 !session.isClientInitiated(),
    	    												 connectionIdentifierInitiator,
    	    												 errMsg, null, responseCode);
    	    return processingResult.get(0).GetByteString();
    	}
    	
    	
    	session.setPRK4e3m(null);
    	session.setTH4(null);
    	
    	/* Prepare EDHOC Message 4 */
    	
    	objectList.add(CBORObject.FromObject(ciphertext4));
    	
    	if (debugPrint) {
    	    byte[] sequenceBytesToPrint;
    	    byte[] sequenceBytes = Util.buildCBORSequence(objectList);
    	    
    	    // If EDHOC message_2 is transported in a CoAP request, do not print the prepended C_I
    	    if (session.isClientInitiated() == false) {
    	        List<CBORObject> trimmedSequence = new ArrayList<CBORObject>();
    	        for (int i = 1; i < objectList.size(); i++) {
    	            trimmedSequence.add(objectList.get(i));
    	        }
    	        sequenceBytesToPrint = Util.buildCBORSequence(trimmedSequence);
    	    }
    	    else {
    	        sequenceBytesToPrint = sequenceBytes;
    	    }
    	    Util.nicePrint("EDHOC Message 4", sequenceBytesToPrint);
    	}
    	
    	session.setCurrentStep(Constants.EDHOC_AFTER_M4);
    	
        return Util.buildCBORSequence(objectList);
		
	}

	
    /**
     *  Write an EDHOC Error Message
     * @param errorCode   The error code for the EDHOC Error Message
     * @param replyTo   The message to which this EDHOC Error Message is intended to reply to
     * @param isErrorReq   True if the EDHOC Error Message will be sent in a CoAP request, or False otherwise
     * @param connectionIdentifier   The connection identifier of the intended recipient of the EDHOC Error Message, it can be null
     * @param errMsg   The text string to include in the EDHOC Error Message
     * @param suitesR   The cipher suite(s) supported by the Responder, it can be null;
     *                  (MUST be present in response to EDHOC Message 1)
     * @return  The raw payload to transmit as EDHOC Error Message, or null in case of errors
     */
	public static byte[] writeErrorMessage(int errorCode, int replyTo, boolean isErrorReq,
			                               byte[] connectionIdentifier, String errMsg, CBORObject suitesR) {
		
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
		byte[] payload;
			
		// Possibly include C_X - This might not have been included if the incoming EDHOC message was malformed
		if (connectionIdentifier != null && isErrorReq == true) {
				CBORObject cX = encodeIdentifier(connectionIdentifier);
				objectList.add(cX);
		}

		// Include ERR_CODE
		objectList.add(CBORObject.FromObject(errorCode));
		
		// Include ERR_INFO
		if (errorCode == Constants.ERR_CODE_UNSPECIFIED_ERROR) {
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
     * @param isErrorReq   True if the EDHOC Error Message will be sent in a CoAP request, or False otherwise
     * @param connectionIdentifier   The connection identifier of the intended recipient of the EDHOC Error Message, it can be null
     * @param errMsg   The text string to include in the EDHOC Error Message
     * @param suitesR   The cipher suite(s) supported by the Responder (only in response to EDHOC Message 1), it can be null
     * @return  A list of CBOR objects, including the EDHOC Error Message and the CoAP response code to use
     */
	public static List<CBORObject> processError(int errorCode, int replyTo, boolean isErrorReq, byte[] connectionIdentifier,
			                                    String errMsg, CBORObject suitesR, ResponseCode responseCode) {
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		byte[] replyPayload = writeErrorMessage(errorCode, replyTo, isErrorReq, connectionIdentifier, errMsg, suitesR);
		
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
     * @param method   The authentication method signaled by the Initiator
     * @param keyPairs   The key pairs of the Initiator (one per supported curve)
     * @param idCreds   The identifiers of the authentication credentials of the Initiator
     * @param creds    The authentication credentials of the Initiator (one per supported curve),
     *                 as the serialization of a CBOR object
     * @param supportedCipherSuites   The list of cipher suites supported by the Initiator
     * @param peerSupportedCipherSuites   The list of cipher suites supported by the Responder, as far as the Initiator knows
     * @param supportedEADs   The set of EAD items supported by the Responder
     * @param usedConnectionIds   The set of allocated Connection Identifiers for the Initiator.
     *                            Each identifier is wrapped in a CBOR byte string.
     * @param appProfile   The application profile used for this session
     * @param trustModel   The trust model used for validating authentication credentials of other peers
     * @param db   The database of OSCORE Security Contexts
     * @return  The newly created EDHOC session
     */
	public static EdhocSession createSessionAsInitiator(int method, HashMap<Integer, HashMap<Integer, OneKey>> keyPairs,
														HashMap<Integer, HashMap<Integer, CBORObject>> idCreds,
														HashMap<Integer, HashMap<Integer, CBORObject>> creds,
			  									        List<Integer> supportedCipherSuites,
			  									        List<Integer> peerSupportedCipherSuites,
			  									        Set<Integer> supportedEADs,
			  									        HashMap<Integer, List<CBORObject>> eadProductionInput,
			  									        Set<CBORObject> usedConnectionIds,
			  									        AppProfile appProfile, int trustModel, HashMapCtxDB db) {
		
		byte[] connectionId = null;
		HashMapCtxDB oscoreDB = (appProfile.getUsedForOSCORE() == true) ? db : null;
		
		connectionId = Util.getConnectionId(usedConnectionIds, oscoreDB, null);
		// Forced for testing
		// connectionId = new byte[] {(byte) 0x1c};
		
        EdhocSession mySession = new EdhocSession(true, true, method, connectionId, keyPairs, idCreds, creds,
        										  supportedCipherSuites, peerSupportedCipherSuites, supportedEADs,
        										  appProfile, trustModel, oscoreDB);
    
		return mySession;
		
	}
	
    /**
     *  Create a new EDHOC session as a Responder
     * @param message1   The payload of the received EDHOC Message 1
     * @param keyPairs   The key pairs of the Responder (one per supported curve)
     * @param idCreds   The identifiers of the authentication credentials of the Responder
     * @param creds    The authentication credentials of the Responder (one per supported curve), as the serialization of a CBOR object
     * @param supportedCipherSuites   The list of cipher suites supported by the Responder
     * @param supportedEADs   The set of EAD items supported by the Responder
     * @param usedConnectionIds   The set of allocated Connection Identifiers for the Responder
     * @param appProfile   The application profile used for this session
     * @param trustModel   The trust model used for validating authentication credentials of other peers
     * @param db   The database of OSCORE Security Contexts
     * @return  The newly created EDHOC session
     */
	public static EdhocSession createSessionAsResponder(byte[] message1, boolean isReq,
														HashMap<Integer, HashMap<Integer, OneKey>> keyPairs,
														HashMap<Integer, HashMap<Integer, CBORObject>> idCreds,
														HashMap<Integer, HashMap<Integer, CBORObject>> creds,
			  									        List<Integer> supportedCipherSuites,
			  									        Set<Integer> supportedEADs,
			  									        Set<CBORObject> usedConnectionIds,
			  									        AppProfile appProfile, int trustModel, HashMapCtxDB db) {
		
		CBORObject[] objectListMessage1 = CBORObject.DecodeSequenceFromBytes(message1);
		int index = -1;
		
		// Retrieve elements from EDHOC Message 1
		
	    // If the received message is a request (i.e. the CoAP client is the initiator), the first element
	    // before the actual message_1 is the CBOR simple value 'true', i.e. the byte 0xf5, and it must be skipped
	    if (isReq == true) {
	        index++;
	    }
		
		// METHOD
	    index++;
		int method = objectListMessage1[index].AsInt32();
		
		// Selected cipher suites from SUITES_I
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
		// Previous checks have ensured that C_I has a valid encoding 
		CBORObject cI = objectListMessage1[index];
		byte[] connectionIdentifierInitiator = decodeIdentifier(cI);
		
		// Create a new EDHOC session

		byte[] connectionIdentifierResponder = null;
		
		HashMapCtxDB oscoreDB = (appProfile.getUsedForOSCORE() == true) ? db : null;
		
		connectionIdentifierResponder = Util.getConnectionId(usedConnectionIds, oscoreDB, connectionIdentifierInitiator);
		// Forced for testing
		// connectionIdentifierResponder = new byte[] {(byte) 0x01};
		
		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();
		EdhocSession mySession = new EdhocSession(false, isReq, method, connectionIdentifierResponder, keyPairs,
												  idCreds, creds, supportedCipherSuites, peerSupportedCipherSuites,
												  supportedEADs, appProfile, trustModel, oscoreDB);
		
		// Set the selected cipher suite
		mySession.setSelectedCipherSuite(selectedCipherSuite);
		
		// Set the asymmetric key pair, CRED and ID_CRED of the Responder to use in this session
		mySession.setAuthenticationCredential();
		
		// Set the Connection Identifier of the peer
		mySession.setPeerConnectionId(connectionIdentifierInitiator);
		
		// Set the ephemeral public key of the Initiator
		OneKey peerEphemeralKey = null;
		
		if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_0 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_1) {
			peerEphemeralKey = SharedSecretCalculation.buildCurve25519OneKey(null, gX);
		}
		if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_2 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_3) {
			peerEphemeralKey = SharedSecretCalculation.buildEcdsa256OneKey(null, gX, null);
		}
		mySession.setPeerEphemeralPublicKey(peerEphemeralKey);
				
		// Compute and store the hash of EDHOC Message 1
		// If it came as a CoAP request, the first received byte 0xf5 must be skipped
		int offset = (isReq == true) ? 1 : 0;
		byte[] hashInput = new byte[message1.length - offset];
		System.arraycopy(message1, offset, hashInput, 0, hashInput.length);
		mySession.setHashMessage1(hashInput);
		
		return mySession;
		
	}
	
	
	/**
    *  Compute one of the temporary keys
    * @param keyName   The name of the key to compute
    * @param session   The used EDHOC session
    * @return  The computed key
    */
	public static byte[] computeKey(int keyName, EdhocSession session) {
	    
	    int selectedCipherSuite = session.getSelectedCipherSuite();
	    int keyLength = EdhocSession.getKeyLengthEdhocAEAD(selectedCipherSuite);
	    if (keyLength == 0)
	        return null;
	    
	    byte[] key = null;
	    String output = null;
	    CBORObject context = null;
	    
	    try {
	        switch(keyName) {
	            case Constants.EDHOC_K_3:
	            	
	            	output = new String("K_3");
	            	byte[] th3 = session.getTH3();
	            	context = CBORObject.FromObject(th3);
	                key = session.edhocKDF(session.getPRK3e2m(), Constants.KDF_LABEL_K_3, context, keyLength);
	                
	                break;
	            case Constants.EDHOC_K_4:
	            	
	            	output = new String("K_4");
	                byte[] th4 = session.getTH4();
	            	context = CBORObject.FromObject(th4);
	                key = session.edhocKDF(session.getPRK4e3m(), Constants.KDF_LABEL_K_4, context, keyLength);
	                
	                break;
	            default:
	            	key = null;
	            	break;
	        }
	    } catch (InvalidKeyException e) {
	        System.err.println("Error when generating " + output + "\n" + e.getMessage());
	    } catch (NoSuchAlgorithmException e) {
	        System.err.println("Error when generating " + output + "\n" + e.getMessage());
	    }
	    
	    return key;
	    
	}
	
	
	/**
    *  Compute one of the temporary IVs
    * @param ivName   The name of the IV to compute
    * @param session   The used EDHOC session
    * @return  The computed IV
    */
	public static byte[] computeIV(int ivName, EdhocSession session) {
	    
	    int selectedCipherSuite = session.getSelectedCipherSuite();
	    int ivLength = EdhocSession.getIvLengthEdhocAEAD(selectedCipherSuite);
	    if (ivLength == 0)
	        return null;
	    
	    byte[] iv = null;
	    String output = null;
	    CBORObject context = null;
	    
	    try {
	        switch(ivName) {
            case Constants.EDHOC_IV_3:
            	output = new String("IV_3");
            	byte[] th3 = session.getTH3();
            	context = CBORObject.FromObject(th3);
                iv = session.edhocKDF(session.getPRK3e2m(), Constants.KDF_LABEL_IV_3, context, ivLength);
                break;
            case Constants.EDHOC_IV_4:
            	output = new String("IV_4");
                byte[] th4 = session.getTH4();
            	context = CBORObject.FromObject(th4);
                iv = session.edhocKDF(session.getPRK4e3m(), Constants.KDF_LABEL_IV_4, context, ivLength);
                break;
            default:
            	iv = null;
            	break;
	        }
	    } catch (InvalidKeyException e) {
	    	System.err.println("Error when generating " + output + "\n" + e.getMessage());
	        return null;
	    } catch (NoSuchAlgorithmException e) {
	    	System.err.println("Error when generating " + output + "\n" + e.getMessage());
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
    	
		byte[] keystream2 = null;
		
		byte[] prk2e = session.getPRK2e();
		
		CBORObject context = CBORObject.FromObject(session.getTH2());
		
    	int selectedCipherSuite = session.getSelectedCipherSuite();
    	String hashAlg = EdhocSession.getEdhocHashAlg(selectedCipherSuite);
    	int hashLength = EdhocSession.getEdhocHashAlgOutputSize(selectedCipherSuite);
		
    	if ( (!hashAlg.equals("SHA-256") && !hashAlg.equals("SHA-384") && !hashAlg.equals("SHA-512")) || (length <= 255 * hashLength) ) {
			try {
				keystream2 = session.edhocKDF(prk2e, Constants.KDF_LABEL_KEYSTREAM_2, context, length);
			} catch (InvalidKeyException e) {
				System.err.println("Error when generating KEYSTREAM_2\n" + e.getMessage());
				return null;
			} catch (NoSuchAlgorithmException e) {
				System.err.println("Error when generating KEYSTREAM_2\n" + e.getMessage());
				return null;
			}
    	}
    	else {
			byte[] part = null;
    		int regularPartSize = 255 * hashLength;
    		int lastPartSize = regularPartSize;
    		
    		int numParts = length / (regularPartSize);
    		if ((length % (regularPartSize)) != 0) {
    			lastPartSize = length % (regularPartSize);
    			numParts++;
    		}
    		
    		int offset = 0;
    		keystream2 = new byte[length];
    		for (int i = 0; i < numParts; i++) {
    			int numBytes = (i == (numParts - 1)) ? lastPartSize : regularPartSize;
    			
    			try {
    				part = session.edhocKDF(prk2e, -i, context, numBytes);
    			} catch (InvalidKeyException e) {
    				System.err.println("Error when generating KEYSTREAM_2\n" + e.getMessage());
    				return null;
    			} catch (NoSuchAlgorithmException e) {
    				System.err.println("Error when generating KEYSTREAM_2\n" + e.getMessage());
    				return null;
    			}
    			
    			System.arraycopy(part, 0, keystream2, offset, part.length);
    			offset += part.length;
    		}
    	}

 
		return keystream2;
		
	}


    /**
     *  Compute the key PRK_2e
     * @param th2   The transcript hash TH_2
     * @param dhSecret   The Diffie-Hellman secret
     * @param hashAlgorithm   The EDHOC hash algorithm of the selected cipher suite
     * @return  The computed key PRK_2e
     */
	public static byte[] computePRK2e(byte[] th2, byte[] dhSecret, String hashAlgorithm) {
	
		byte[] prk2e = null;
	    try {  	
	    	if (hashAlgorithm.equals("SHA-256") || hashAlgorithm.equals("SHA-384") || hashAlgorithm.equals("SHA-512")) {
	    		prk2e = Hkdf.extract(th2, dhSecret);
	    	}
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
            		// Use the ephemeral key of the Initiator as public key
            		publicKey = session.getPeerEphemeralPublicKey();
            		
            		// Use the long-term key of the Responder as private key
            		privateKey = session.getKeyPair();

                	// For the time being, this is not relevant, since the same
                	// key pair cannot be used for both signing and Diffie-Hellman.
            		/*
                	OneKey identityKey = session.getKeyPair();
            		
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
	            	*/
            	}
            	else if (session.isInitiator() == true) {
            		// Use the ephemeral key of the Initiator as private key
            		privateKey = session.getEphemeralKey();
            		
            		// Use the long-term key of the Responder as public key
            		publicKey = session.getPeerLongTermPublicKey();

                	// For the time being, this is not relevant, since the same
                	// key pair cannot be used for both signing and Diffie-Hellman.
            		/*
            		/*
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
	            	*/
	            	
            	}
            	
    			// Consistency check of key type and curve against the selected cipher suite
            	int selectedCipherSuite = session.getSelectedCipherSuite();
            	
            	if (Util.checkDiffieHellmanKeyAgainstCipherSuite(privateKey, selectedCipherSuite) == false) {
            		System.err.println("Error when computing the Diffie-Hellman Secret");
            		return null;
            	}
            	if (Util.checkDiffieHellmanKeyAgainstCipherSuite(publicKey, selectedCipherSuite) == false) {
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
            	
            	String hashAlgorithm = EdhocSession.getEdhocHashAlg(session.getSelectedCipherSuite());

            	// Compute SALT_3e2m
            	byte[] salt3e2m = computeSALT3e2m(session, prk2e);
            	if (salt3e2m == null) {
            		System.err.println("Error when computing SALT_3e2m");
            		return null;
            	}
            	else if (debugPrint) {
            		Util.nicePrint("SALT_3e2m", salt3e2m);
            	}
            	
            	try {
            		if (hashAlgorithm.equals("SHA-256") || hashAlgorithm.equals("SHA-384") || hashAlgorithm.equals("SHA-512")) {
            			prk3e2m = Hkdf.extract(salt3e2m, dhSecret);
            		}
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
     *  Compute the key PRK_4e3m
     * @param session   The used EDHOC session
     * @return  The computed key PRK_4e3m
     */
	public static byte[] computePRK4e3m(EdhocSession session) {
		
		byte[] prk4e3m = null;
		byte[] prk3e2m = session.getPRK3e2m();
		int authenticationMethod = session.getMethod();
		
        if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_1) {
        	// The initiator uses signatures as authentication method, then PRK_4e3m is equal to PRK_3e2m 
        	prk4e3m = new byte[prk3e2m.length];
        	System.arraycopy(prk3e2m, 0, prk4e3m, 0, prk3e2m.length);
        }
        else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_2 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_3) {
        		// The initiator does not use signatures as authentication method, then PRK_4e3m has to be computed
            	byte[] dhSecret;
            	OneKey privateKey = null;
            	OneKey publicKey = null;
            	
            	if (session.isInitiator() == false) {
            		// Use the ephemeral key of the Responder as private key
                	privateKey = session.getEphemeralKey();
                	
            		// Use the long-term key of the Initiator as public key
                	publicKey = session.getPeerLongTermPublicKey();

                	// For the time being, this is not relevant, since the same
                	// key pair cannot be used for both signing and Diffie-Hellman.
                	/*
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
	            	*/
            	}
            	else if (session.isInitiator() == true) {
            		// Use the ephemeral key of the Responder as public key
            		publicKey = session.getPeerEphemeralPublicKey();
            		
            		// Use the long-term key of the Initiator as private key
            		privateKey = session.getKeyPair();

                	// For the time being, this is not relevant, since the same
                	// key pair cannot be used for both signing and Diffie-Hellman.
            		/*
            		OneKey identityKey = session.getKeyPair();
            		
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
	            	*/
	            	
            	}
            	dhSecret = SharedSecretCalculation.generateSharedSecret(privateKey, publicKey);
            	
                if (dhSecret == null) {
            		System.err.println("Error when computing the Diffie-Hellman Secret");
            		return null;
                }
            	
            	if (debugPrint) {
            		Util.nicePrint("G_IY", dhSecret);
            	}
            	
            	String hashAlgorithm = EdhocSession.getEdhocHashAlg(session.getSelectedCipherSuite());

            	// Compute SALT_4e3m
            	byte[] salt4e3m = computeSALT4e3m(session, prk3e2m);
            	if (salt4e3m == null) {
            		System.err.println("Error when computing SALT_4e3m");
            		return null;
            	}
            	else if (debugPrint) {
            		Util.nicePrint("SALT_4e3m", salt4e3m);
            	}
            	
            	try {
            		if (hashAlgorithm.equals("SHA-256") || hashAlgorithm.equals("SHA-384") || hashAlgorithm.equals("SHA-512")) {
            			prk4e3m = Hkdf.extract(salt4e3m, dhSecret);
            		}
				} catch (InvalidKeyException e) {
					System.err.println("Error when generating PRK_4e3m\n" + e.getMessage());
					return null;
				} catch (NoSuchAlgorithmException e) {
					System.err.println("Error when generating PRK_4e3m\n" + e.getMessage());
					return null;
				}
            	finally {
            		dhSecret = null;
            	}
    	}
        
        return prk4e3m;
        
	}

    /**
     *  Compute the PRK_out
     * @param session   The used EDHOC session
     * @param prk4e3m   The key PRK_4e3m
     * @return  The computed PRK_out
     */
	public static byte[] computePRKout(EdhocSession session, byte[] prk4e3m) {
		
		byte[] prkOut = null;
		int selectedCipherSuite = session.getSelectedCipherSuite();
		int length = EdhocSession.getEdhocHashAlgOutputSize(selectedCipherSuite);
		CBORObject context = CBORObject.FromObject(session.getTH4());
		
		try {
			prkOut = session.edhocKDF(prk4e3m, Constants.KDF_LABEL_PRK_OUT, context, length);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating PRK_out\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating PRK_out\n" + e.getMessage());
			return null;
		}

		return prkOut;
		
	}

    /**
     *  Compute the PRK_exporter
     * @param session   The used EDHOC session
     * @param prkOut   The key PRK_out
     * @return  The computed PRK_exporter
     */
	public static byte[] computePRKexporter(EdhocSession session, byte[] prkOut) {
		
		byte[] prkExporter = null;
		int selectedCipherSuite = session.getSelectedCipherSuite();
		int length = EdhocSession.getEdhocHashAlgOutputSize(selectedCipherSuite);
	    CBORObject context = CBORObject.FromObject(new byte[0]);
	    
		try {
			prkExporter = session.edhocKDF(prkOut, Constants.KDF_LABEL_PRK_EXPORTER, context, length);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating PRK_exporter\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating PRK_exporter\n" + e.getMessage());
			return null;
		}

		return prkExporter;
		
	}

    /**
     *  Compute the SALT_3e2m
     * @param session   The used EDHOC session
     * @param prk2e   The key PRK_2e
     * @return  The computed SALT_3e2m
     */
	public static byte[] computeSALT3e2m(EdhocSession session, byte[] prk2e) {
		
		byte[] salt3e2m = null;
		int selectedCipherSuite = session.getSelectedCipherSuite();
		int length = EdhocSession.getEdhocHashAlgOutputSize(selectedCipherSuite);
		CBORObject context = CBORObject.FromObject(session.getTH2());
		
		try {
			salt3e2m = session.edhocKDF(prk2e, Constants.KDF_LABEL_SALT_3E2M, context, length);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating SALT_3e2m\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating SALT_3e2m\n" + e.getMessage());
			return null;
		}

		return salt3e2m;
		
	}
	
    /**
     *  Compute the SALT_4e3m
     * @param session   The used EDHOC session
     * @param prk3e2m   The key PRK_3e2m
     * @return  The computed SALT_4e3m
     */
	public static byte[] computeSALT4e3m(EdhocSession session, byte[] prk3e2m) {
		
		byte[] salt4e3m = null;
		int selectedCipherSuite = session.getSelectedCipherSuite();
		int length = EdhocSession.getEdhocHashAlgOutputSize(selectedCipherSuite);
		CBORObject context = CBORObject.FromObject(session.getTH3());
		
		try {
			salt4e3m = session.edhocKDF(prk3e2m, Constants.KDF_LABEL_SALT_4E3M, context, length);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating SALT_4e3m\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating SALT_4e3m\n" + e.getMessage());
			return null;
		}

		return salt4e3m;
		
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
        if (ead != null && ead.length != 0) {
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
     *  Compute MAC_2
     * @param session   The used EDHOC session
     * @param prk3e2m   The PRK used to compute MAC_2
     * @param th2   The transcript hash TH2
     * @param cR   The Connection Identifier C_R, encoded as a CBOR byte string or integer 
     * @param idCredR   The ID_CRED_R associated to the long-term public key of the Responder
     * @param credR   The long-term public key of the Responder, as the serialization of a CBOR object
     * @param ead2   The External Authorization Data from EDHOC Message 2, it can be null
     * @return  The computed MAC_2
     */
	public static byte[] computeMAC2(EdhocSession session, byte[] prk3e2m, byte[] th2, CBORObject cR,
			                         CBORObject idCredR, byte[] credR, CBORObject[] ead2) {
		
		// Build the CBOR sequence to use for 'context': ( C_R, ID_CRED_R, TH_2, CRED_R, ? EAD_2 )
		// The actual 'context' is a CBOR byte string with value the serialization of the CBOR sequence
        List<CBORObject> objectList = new ArrayList<>();
        objectList.add(cR);
    	objectList.add(idCredR);
    	objectList.add(CBORObject.FromObject(th2));
    	objectList.add(CBORObject.DecodeFromBytes(credR));
    	
    	if (ead2 != null && ead2.length != 0) {
	    	for (int i = 0; i < ead2.length; i++)
	    		objectList.add(ead2[i]);
    	}
    	byte[] contextSequence = Util.buildCBORSequence(objectList);
    	CBORObject context = CBORObject.FromObject(contextSequence);
    	
    	int macLength = 0;
    	int method = session.getMethod();
    	int selectedCipherSuite = session.getSelectedCipherSuite();
    	if (method == 0 || method == 2) {
    		macLength = EdhocSession.getEdhocHashAlgOutputSize(selectedCipherSuite);
    	}
    	if (method == 1 || method == 3) {
    		macLength = EdhocSession.getTagLengthEdhocAEAD(selectedCipherSuite);
    	}
    	
    	byte[] mac2 = null;
    	
    	try {
			mac2 = session.edhocKDF(prk3e2m, Constants.KDF_LABEL_MAC_2, context, macLength);
		} catch (InvalidKeyException e) {
			System.err.println("Error when computing MAC_2\n" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when computing MAC_2\n" + e.getMessage());
		}
        if (debugPrint) {
        	Util.nicePrint("context_2", contextSequence);
        }
		
		return mac2;
		
	}

    /**
     *  Compute MAC_3
     * @param session   The used EDHOC session
     * @param prk4e3m   The PRK used to compute MAC_3
     * @param idCredI   The ID_CRED_I associated to the long-term public key of the Initiator
     * @param credI   The long-term public key of the Initiator, as the serialization of a CBOR object
     * @param ead3   The External Authorization Data from EDHOC Message 3, it can be null
     * @return  The computed MAC_3
     */
	public static byte[] computeMAC3(EdhocSession session, byte[] prk4e3m, byte[] th3,
            						 CBORObject idCredI, byte[] credI, CBORObject[] ead3) {
				
		// Build the CBOR sequence for 'context': ( ID_CRED_I, TH_3, CRED_I, ? EAD_3 )
		// The actual 'context' is a CBOR byte string with value the serialization of the CBOR sequence
        List<CBORObject> objectList = new ArrayList<>();
    	objectList.add(idCredI);
    	objectList.add(CBORObject.FromObject(th3));
    	objectList.add(CBORObject.DecodeFromBytes(credI));
    	
    	if (ead3 != null && ead3.length != 0) {
	    	for (int i = 0; i < ead3.length; i++)
	    		objectList.add(ead3[i]);
    	}
    	byte[] contextSequence = Util.buildCBORSequence(objectList);
    	CBORObject context = CBORObject.FromObject(contextSequence);
    	
    	int macLength = 0;
    	int method = session.getMethod();
    	int selectedCipherSuite = session.getSelectedCipherSuite();
    	if (method == 0 || method == 1) {
    		macLength = EdhocSession.getEdhocHashAlgOutputSize(selectedCipherSuite);
    	}
    	if (method == 2 || method == 3) {
    		macLength = EdhocSession.getTagLengthEdhocAEAD(selectedCipherSuite);
    	}
    	
    	byte[] mac3 = null;
    	
    	try {
			mac3 = session.edhocKDF(prk4e3m, Constants.KDF_LABEL_MAC_3, context, macLength);
		} catch (InvalidKeyException e) {
			System.err.println("Error when computing MAC_3\n" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when computing MAC_3\n" + e.getMessage());
		}
        if (debugPrint) {
        	Util.nicePrint("context_3", contextSequence);
        }
		
		return mac3;
		
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
		
    	
    	byte[] ciphertext3 = null;
    	
    	int selectedCipherSuite = session.getSelectedCipherSuite();
    	AlgorithmID alg = EdhocSession.getEdhocAEADAlg(selectedCipherSuite);
    	
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
     *  Compute CIPHERTEXT_4
     * @param session   The used EDHOC session
     * @param externalData   The External Data for the encryption process
     * @param plaintext   The plaintext to encrypt
     * @param k4m   The encryption key
     * @param iv4m   The initialization vector
     * @return  The computed CIPHERTEXT_4
     */
	public static byte[] computeCiphertext4(EdhocSession session, byte[] externalData,
			                         		byte[] plaintext, byte[] k4m, byte[] iv4m) {
		
		
    	byte[] ciphertext4 = null;
    	
    	int selectedCipherSuite = session.getSelectedCipherSuite();
    	AlgorithmID alg = EdhocSession.getEdhocAEADAlg(selectedCipherSuite);
    	
    	// Prepare the empty content for the COSE protected header
    	CBORObject emptyMap = CBORObject.NewMap();
    	
    	try {
			ciphertext4 = Util.encrypt(emptyMap, externalData, plaintext, alg, iv4m, k4m);
		} catch (CoseException e) {
			System.err.println("Error when computing CIPHERTEXT_4\n" + e.getMessage());
			return null;
		}
		
		return ciphertext4;
		
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
		
    	byte[] plaintext = null;
    	
    	int selectedCipherSuite = session.getSelectedCipherSuite();
    	AlgorithmID alg = EdhocSession.getEdhocAEADAlg(selectedCipherSuite);
    	
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
     *  Decrypt CIPHERTEXT_4
     * @param session   The used EDHOC session
     * @param externalData   The External Data for the encryption process
     * @param plaintext   The ciphertext to decrypt
     * @param k3ae   The decryption key
     * @param iv3ae   The initialization vector
     * @return  The plaintext recovered from CIPHERTEXT_4
     */
	public static byte[] decryptCiphertext4(EdhocSession session, byte[] externalData,
			                                byte[] ciphertext, byte[] k4ae, byte[] iv4ae) {
		
    	byte[] plaintext = null;
    	
    	int selectedCipherSuite = session.getSelectedCipherSuite();
    	AlgorithmID alg = EdhocSession.getEdhocAEADAlg(selectedCipherSuite);
    	
    	// Prepare the empty content for the COSE protected header
    	CBORObject emptyMap = CBORObject.NewMap();
    	
    	try {
    		plaintext = Util.decrypt(emptyMap, externalData, ciphertext, alg, iv4ae, k4ae);
		} catch (CoseException e) {
			System.err.println("Error when decrypting CIPHERTEXT_4\n" + e.getMessage());
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
    			OneKey identityKey = session.getKeyPair();
    			int selectedCipherSuite = session.getSelectedCipherSuite();
    			
    			// Consistency check of key type and curve against the selected cipher suite
    			if (Util.checkSignatureKeyAgainstCipherSuite(identityKey, selectedCipherSuite) == false) {
    				System.err.println("Error when signing MAC_2 to produce Signature_or_MAC_2\n");
    				return null;
    			}

    			if (debugPrint) {
		    		Util.nicePrint("External Data for signing MAC_2 to produce Signature_or_MAC_2", externalData);
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
    			OneKey identityKey = session.getKeyPair();
    			int selectedCipherSuite = session.getSelectedCipherSuite();
    			
    			// Consistency check of key type and curve against the selected cipher suite
    			if (Util.checkSignatureKeyAgainstCipherSuite(identityKey, selectedCipherSuite) == false) {
    				System.err.println("Error when signing MAC_3 to produce Signature_or_MAC_3\n");
    				return null;
    			}
    			
    			if (debugPrint) {
    			    Util.nicePrint("External Data for signing MAC_3 to produce Signature_or_MAC_3", externalData);
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
    		
    		return Util.compareByteArrays(signatureOrMac2, mac2);
    	}
    	else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_2) {
    		// The responder uses signatures as authentication method, then Signature_or_MAC_2 is a signature to verify
    		
    		OneKey peerIdentityKey = session.getPeerLongTermPublicKey();
			int selectedCipherSuite = session.getSelectedCipherSuite();
			
			// Consistency check of key type and curve against the selected cipher suite
			if (Util.checkSignatureKeyAgainstCipherSuite(peerIdentityKey, selectedCipherSuite) == false) {
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
    		
    		return Util.compareByteArrays(signatureOrMac3, mac3);
    	}
    	else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_1) {
    		// The initiator uses signatures as authentication method, then Signature_or_MAC_3 is a signature to verify

    		OneKey peerIdentityKey = session.getPeerLongTermPublicKey();
			int selectedCipherSuite = session.getSelectedCipherSuite();
			
			// Consistency check of key type and curve against the selected cipher suite
			if (Util.checkSignatureKeyAgainstCipherSuite(peerIdentityKey, selectedCipherSuite) == false) {
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
     * @param gY   The G_Y ephemeral key from the EDHOC Message 2, as a serialized CBOR byte string
     * @param hashMessage1   The hash of EDHOC Message 1, as a serialized CBOR byte string
     * @return  The computed TH2
     */
	public static byte[] computeTH2(EdhocSession session, byte[] gY, byte[] hashMessage1) {
	
        byte[] th2 = null;
        
        int selectedCipherSuite = session.getSelectedCipherSuite();
        String hashAlgorithm = EdhocSession.getEdhocHashAlg(selectedCipherSuite);

        byte[] hashInput = new byte[gY.length + hashMessage1.length];
        System.arraycopy(gY, 0, hashInput, 0, gY.length);
        System.arraycopy(hashMessage1, 0, hashInput, gY.length, hashMessage1.length);
		Util.nicePrint("Input to calculate TH_2", hashInput);
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
     * @param plaintext2   The PLAINTEXT_2 from EDHOC Message 2, as a serialized CBOR sequence
     * @param credR   CRED_R as the serialization of a CBOR object
     * @return  The computed TH3
     */
	public static byte[] computeTH3(EdhocSession session, byte[] th2, byte[] plaintext2, byte[] credR) {
	
        byte[] th3 = null;
        int inputLength = th2.length + plaintext2.length + credR.length;
        
        int selectedCipherSuite = session.getSelectedCipherSuite();
        String hashAlgorithm = EdhocSession.getEdhocHashAlg(selectedCipherSuite);
        
        int offset = 0;
        byte[] hashInput = new byte[inputLength];
        System.arraycopy(th2, 0, hashInput, offset, th2.length);
        offset += th2.length;
        System.arraycopy(plaintext2, 0, hashInput, offset, plaintext2.length);
        
        offset += plaintext2.length;
        System.arraycopy(credR, 0, hashInput, offset, credR.length);
        
		Util.nicePrint("Input to calculate TH_3", hashInput);
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
     * @param plaintext3   The PLAINTEXT_3 from EDHOC Message 3, as a serialized CBOR sequence
     * @param credI   CRED_I as the serialization of a CBOR object
     * @return  The computed TH4
     */
	public static byte[] computeTH4(EdhocSession session, byte[] th3, byte[] plaintext3, byte[] credI) {
	
        byte[] th4 = null;
        int inputLength = th3.length + plaintext3.length + credI.length;
        
        int selectedCipherSuite = session.getSelectedCipherSuite();
        String hashAlgorithm = EdhocSession.getEdhocHashAlg(selectedCipherSuite);
        
        int offset = 0;
        byte[] hashInput = new byte[inputLength];
        System.arraycopy(th3, 0, hashInput, offset, th3.length);
        offset += th3.length;
        System.arraycopy(plaintext3, 0, hashInput, offset, plaintext3.length);
        
        offset += plaintext3.length;
        System.arraycopy(credI, 0, hashInput, offset, credI.length);
        
		Util.nicePrint("Input to calculate TH_4", hashInput);
        try {
        	th4 = Util.computeHash(hashInput, hashAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Invalid hash algorithm when computing TH4\n" + e.getMessage());
			return null;
			
		}
		
		return th4;
		
	}
	
    /**
     *  Encode an EDHOC connection identifier to the CBOR Object to include in an EDHOC message
     * @param identifier   The EDHOC connection identifier
     * @return  The CBOR object encoding the EDHOC connection identifier, or null in case of error
     */
	public static CBORObject encodeIdentifier(byte[] identifier) {
	
		CBORObject identifierCBOR = null;
		
		if (identifier != null && identifier.length != 1) {
			// Encode the EDHOC connection identifier as a CBOR byte string
			identifierCBOR = CBORObject.FromObject(identifier);
		}

		if (identifier != null && identifier.length == 1) {
			int byteValue = Util.bytesToInt(identifier);
					
			if ((byteValue >= 0 && byteValue <= 23) || (byteValue >= 32 && byteValue <= 55)) {
				// The EDHOC connection identifier is in the range 0x00-0x17 or in the range 0x20-0x37.
				// That is, it happens to be the serialization of a CBOR integer with numeric value -24..23
				
				// Encode the EDHOC connection identifier as a CBOR integer
				identifierCBOR = CBORObject.DecodeFromBytes(identifier);
			}
			else {
				// Encode the EDHOC connection identifier as a CBOR byte string
				identifierCBOR = CBORObject.FromObject(identifier);
			}
		}
		
		return identifierCBOR;
		
	}

    /**
     *  Decode an EDHOC connection identifier from the CBOR Object included in an EDHOC message
     * @param identifier   The CBOR object encoding the EDHOC connection identifier
     * @return  The EDHOC connection identifier, or null in case of error
     */
	public static byte[] decodeIdentifier(CBORObject identifierCbor) {
	
		byte[] identifier = null;
			
		if (identifierCbor != null && identifierCbor.getType() == CBORType.ByteString) {
			identifier = identifierCbor.GetByteString();
			
			// Consistency check
			if (identifier.length == 1) {
				int byteValue = Util.bytesToInt(identifier);
				if ((byteValue >= 0 && byteValue <= 23) || (byteValue >= 32 && byteValue <= 55))
					// This EDHOC connection identifier should have been encoded as a CBOR integer
					identifier = null;
			}			
		}
		else if (identifierCbor != null && identifierCbor.getType() == CBORType.Integer) {
			identifier = identifierCbor.EncodeToBytes();
			
			if (identifier.length != 1) {
				// This EDHOC connection identifier is not valid or was not encoded according to deterministic CBOR
				identifier = null;
			}
			
		}

		return identifier;
		
	}
	
    /**
     *  Perform early sanity checks on the EAD field of an incoming EDHOC message.
     *  Remove any EAD item that is either: i) padding; or ii) non-critical and not supported
     * @param objectList   The CBOR sequence possibly including the EAD_X field.
     *                     For EDHOC message_1, the CBOR sequence is the whole EDHOC message_1.
     *                     For EDHOC message_X, with X = (2, 3, 4), the CBOR sequence is PLAINTEXT_X.
     * @param baseIndex   With reference to 'objectList', the index of its CBOR item encoding the ead_label of the first EAD item.
     * @param msnNum      The integer X = (1, 2, 3, 4), consistent with the specifically received EDHOC message_X.
     * @param supportedEADs   The list of EAD items supported by this peer.
     * @return  In case of success, it returns the subset of the EAD field to be passed to the application for further processing.
     *          In case of error, it returns an array including one element as a CBOR text string, whose value provides a description
     *          of the error to be used in the EDHOC error message to return.
     */
	static CBORObject[] preParseEAD(CBORObject[] objectList, int baseIndex, int msgNum, Set<Integer> supportedEADs) {
		
		int length = objectList.length - baseIndex;
		CBORObject[] aux = new CBORObject[length];
		CBORObject[] ret = null;
		int count = 0;
		
		boolean error = false;
		String errMsg = new String("");
		
		// The actual goal of each step is to go through one *EAD item*.
		// At each step, the element with index 'i' must be an ead_label.
		// For EAD items that are supported or non-critical, the corresponding ead_value (if present) is
		// handled during the same step, so that the next step will consider the next EAD item, if any.
		for (int i = baseIndex; i < objectList.length; i++) {
			
			CBORObject myObject = objectList[i];
			
			if (myObject.getType() != CBORType.Integer) {
				 // Each EAD item must start with a CBOR integer encoding the ead_label
				 errMsg = new String("Malformed or invalid EAD_" + msgNum);
		         error = true;
		         break;
			}
        	if (i+1 < objectList.length &&
        		objectList[i+1].getType() != CBORType.Integer &&
        		objectList[i+1].getType() != CBORType.ByteString) {
    			 // The immediately following item in the CBOR sequence (if any) must be a CBOR integer or a CBOR byte string
				 errMsg = new String("Malformed or invalid EAD_" + msgNum);
		         error = true;
		         break;
        	}

            int eadLabel = myObject.AsInt32();
            
            if (eadLabel == Constants.EAD_LABEL_PADDING) {
            	// This is the padding EAD item and it is not passed to the application for further processing
            	
            	if (debugPrint) {
            		System.out.println("ead_label: " + eadLabel);
            	}
            	
            	if (i+1 < objectList.length && objectList[i+1].getType() == CBORType.ByteString) {
            		if (debugPrint) {
            			Util.nicePrint("ead_value", objectList[i+1].GetByteString());
            		}
            		
	            	// Skip the corresponding ead_value, if present
            		i++;
            	}
            	continue;
            }
            
            int eadLabelUnsigned = (eadLabel < 0) ? (-eadLabel) : eadLabel;
            boolean supported = supportedEADs.contains(Integer.valueOf(eadLabelUnsigned));

            if (!supported) {
	            if (eadLabel < 0) {
	            	// Since the EAD item is critical and is not supported, the protocol must be discontinued
	                errMsg = new String("Unsupported EAD_" + msgNum + " critical item with ead_label " + eadLabelUnsigned);
	                error = true;
	                break;
	            }
	            else {
	            	// Since the EAD item is non-critical and is not supported,
	            	// it is not passed to the application for further processing
	            	if (i+1 < objectList.length && objectList[i+1].getType() == CBORType.ByteString) {
	                    i++; // This will result in moving to the next EAD item, if any
	            	}
                    continue;
	            }
            }

            // This EAD item is supported, so it is kept for further processing

            // Make a hard copy of the ead_label
            byte[] serializedObjectLabel = myObject.EncodeToBytes();
            CBORObject elementLabel = CBORObject.DecodeFromBytes(serializedObjectLabel);
            aux[count] = elementLabel;
            count++;
            
            if (debugPrint) {
            	System.out.println("ead_label: " + eadLabel);
            }
            
            // Make a hard copy of the ead_value, if present
        	if (i+1 < objectList.length && objectList[i+1].getType() == CBORType.ByteString) {
                byte[] serializedObjectValue = objectList[i+1].EncodeToBytes();
                CBORObject elementValue = CBORObject.DecodeFromBytes(serializedObjectValue);
                aux[count] = elementValue;
                count++;
                
                if (debugPrint) {
                	Util.nicePrint("ead_value", objectList[i+1].GetByteString());
                }
                
                i++; // This will result in moving to the next EAD item, if any
        	}

		}
		
		if (error == true) {
			// Prepare the diagnostic error text to be returned
			ret = new CBORObject[1];
			ret[0] = CBORObject.FromObject(errMsg);
		}
		else {
			// Prepare the subset of the EAD items to provide to the application for further processing
			ret = new CBORObject[count];
			for (int i = 0; i < count; i++)
				ret[i] = aux[i];
		}
		
		return ret;
		
	}
	
}
