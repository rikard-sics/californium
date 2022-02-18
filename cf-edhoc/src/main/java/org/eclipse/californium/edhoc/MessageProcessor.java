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
import org.eclipse.californium.oscore.HashMapCtxDB;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.Utils;

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
     * @param cX   The connection identifier of this peer, it can be null and then it has to be retrieved from the message
     * @return  The type of the EDHOC message, or -1 if it not a recognized type
     */
	public static int messageType(byte[] msg, boolean isReq, Map<CBORObject, EdhocSession> edhocSessions,
			                      CBORObject cX, AppStatement appStatement) {
				
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
		
		CBORObject connectionIdentifier = null;
		
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
			
			if (cX != null) {
				connectionIdentifier = cX;
			}
			else {
				// The Connection Identifier to retrieve the EDHOC session was not provided.
				// It is present in the message as first element of the CBOR sequence.
				
			    if (elem.getType() == CBORType.ByteString || elem.getType() == CBORType.Integer)
			    	connectionIdentifier = myObjects[0];

			}
		}
		
		if (isReq == false) {
			// A response never starts with C_X
			
			if (isErrorMessage(myObjects, isReq)) {
				// Check if it is an EDHOC error message
				return Constants.EDHOC_ERROR_MESSAGE;
			}
			
			// Use the provided Connection Identifier to retrieve the EDHOC session.
		    connectionIdentifier = cX;
			
		}

	    if (connectionIdentifier != null) {
	    	
	        EdhocSession session = edhocSessions.get(connectionIdentifier);
	        
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
     * @param appStatement   The applicability statement to use
     * @param sessions   The EDHOC sessions of this peer
     * @return   A list of CBOR Objects including up to three elements.
     * 
     *           The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC Message 2 can be prepared; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *             
     *           In case (i), the second element is optionally present as a CBOR array, with elements
     *           the same elements of the external authorization data EAD1 to deliver to the application.
     *           
     *           In case (ii), the second element is a CBOR integer, with value the CoAP response code
     *           to use for the EDHOC Error Message, if this is a CoAP response. The third element is optionally
     *           present as a CBOR array, with elements the same elements of the external authorization data EAD1
     *           to deliver to the application.
     */
	public static List<CBORObject> readMessage1(byte[] sequence, boolean isReq,
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
		CBORObject cI = null; // The Connection Identifier C_I, or left to null in case of invalid message
		CBORObject suitesR = null; // The SUITE_R element to be possibly returned as SUITES_R in an EDHOC Error Message

		
		int index = -1;	
		CBORObject[] objectListRequest = null;
		try {
			objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		}
		catch (Exception e) {
		    errMsg = new String("Malformed or invalid EDHOC message_1");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}
		
		/* Consistency checks */
		
		if (error == false && objectListRequest.length == 0) {
		    errMsg = new String("Malformed or invalid EDHOC message_1");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}
		
    	if (error == false && appStatement == null) {
			errMsg = new String("Impossible to retrieve the applicability statement");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
    	}
    	else {
    	    // If the received message is a request (i.e. the CoAP client is the initiator), the first element
    	    // before the actual message_1 is the CBOR simple value 'true', i.e. the byte 0xf5, and it can be skipped
	    	if (isReq) {
	    		index++;
	    		if (!objectListRequest[index].equals(CBORObject.True)) {
	    			errMsg = new String("The first element must be the CBOR simple value 'true'");
	    			responseCode = ResponseCode.BAD_REQUEST;
	    			error = true;
	    		}
	        }
    	}
		
    	
		// METHOD
    	index++;
    	if (error == false) {
			if (objectListRequest[index].getType() != CBORType.Integer) {
				errMsg = new String("METHOD must be an integer");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
			else {
				// Check that the indicated authentication method is supported
		    	int method = objectListRequest[index].AsInt32();
		    	if (!appStatement.isAuthMethodSupported(method)) {
					errMsg = new String("Authentication method " + method + " is not supported");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
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

		// Check if the selected ciphersuite is supported and that no prior ciphersuite in SUITES_I is supported
		List<Integer> ciphersuitesToOffer = new ArrayList<Integer>();
		if (error == false) {
			int selectedCiphersuite;
			
			if (objectListRequest[index].getType() == CBORType.Integer) {
				// SUITES_I is the selected ciphersuite
				selectedCiphersuite = objectListRequest[index].AsInt32();
				
				// This peer does not support the selected ciphersuite
				if (!supportedCiphersuites.contains(Integer.valueOf(selectedCiphersuite))) {
					errMsg = new String("The selected ciphersuite is not supported");
					errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
					
					// SUITE_R will include all the ciphersuites supported by the Responder
					ciphersuitesToOffer = supportedCiphersuites;
				}
			}
			
			else if (objectListRequest[index].getType() == CBORType.Array) {
				// The selected ciphersuite is the last element of SUITES_I
				int size = objectListRequest[index].size(); 
				selectedCiphersuite = objectListRequest[index].get(size-1).AsInt32();
				
				int firstSharedCiphersuite = -1;
				// Find the first commonly supported ciphersuite, i.e. the ciphersuite both
				// supported by the Responder and specified as early as possible in SUITES_I
				for (int i = 0; i < size; i++) {
					int suite = objectListRequest[index].get(i).AsInt32();
					if (supportedCiphersuites.contains(Integer.valueOf(suite))) {
						firstSharedCiphersuite = suite;
						break;
					}
				}
				
				if (!supportedCiphersuites.contains(Integer.valueOf(selectedCiphersuite))) {
					// The Responder does not support the selected ciphersuite
					
					errMsg = new String("The selected ciphersuite is not supported");
					errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
					
					if (firstSharedCiphersuite == -1) {
						// The Responder does not support any ciphersuites in SUITE_I.
						// SUITE_R will include all the ciphersuites supported by the Responder
						ciphersuitesToOffer = supportedCiphersuites;
					}
					else {
						// SUITES_R will include only the ciphersuite supported
						// by both peers and most preferred by the Initiator.
						ciphersuitesToOffer.add(firstSharedCiphersuite);
					}
					
				}
				else if (firstSharedCiphersuite != selectedCiphersuite) {
					// The Responder supports the selected ciphersuite, but it has to reply with an EDHOC Error Message
					// if it supports a cipher suite more preferred by the Initiator than the selected cipher suite
					
					errMsg = new String("The selected ciphersuite is not supported");
					errorCode = Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE;
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
					
					// SUITES_R will include only the ciphersuite supported
					// by both peers and most preferred by the Initiator.
					ciphersuitesToOffer.add(firstSharedCiphersuite);
					
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
		if (error == false && objectListRequest[index].getType() == CBORType.Integer &&
			Util.isDeterministicCborInteger(objectListRequest[index]) == false) {
				errMsg = new String("C_I is an integer but it does not comply with deterministic CBOR encoding");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false && objectListRequest[index].getType() == CBORType.ByteString) {
			
			if (appStatement.getSupportCombinedRequest() == true ||
			    appStatement.getConversionMethodOscoreToEdhoc() == Constants.CONVERSION_ID_CORE) {
				
				byte[] buffer = objectListRequest[index].GetByteString();
				if (Util.isCborIntegerEncoding(buffer) == true) {
					errMsg = new String("C_I does not comply with the method for converting from "
							            + "OSCORE Recipient/Sender IDs to EDHOC Connection Identifiers");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
				}
				
			}
			
		}
		if (error == false) {
			cI = objectListRequest[index];
		}
		
		// EAD_1
		index++;
		if (error == false && objectListRequest.length > index) {
		    // EAD_1 is present
			int length = objectListRequest.length - index;

		    if ((length % 2) == 1) {
		        errMsg = new String("Malformed or invalid EAD_1");
		        responseCode = ResponseCode.BAD_REQUEST;
		        error = true;
		    }
		    else {
		        ead1 = new CBORObject[length];
		        
		        for (int i = index; i < objectListRequest.length; i++) {
		            if ((i % 2) == 0 && objectListRequest[i].getType() != CBORType.Integer) {
		                ead1 = null;
		                errMsg = new String("Malformed or invalid EAD_1");
		                responseCode = ResponseCode.BAD_REQUEST;
		                error = true;
		                break;
		            }
		            if ((i % 2) == 1 && objectListRequest[i].getType() != CBORType.ByteString) {
		                ead1 = null;
		                errMsg = new String("Malformed or invalid EAD_1");
		                responseCode = ResponseCode.BAD_REQUEST;
		                error = true;
		                break;
		            }
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
			suitesR = Util.buildSuitesR(ciphersuitesToOffer);
			
			return processError(errorCode, Constants.EDHOC_MESSAGE_1, !isReq, cI, errMsg, suitesR, responseCode, ead1);
			
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
		
		System.out.println("\nCompleted processing of EDHOC Message 1");
		return processingResult;
		
	}
	
    /**
     *  Process an EDHOC Message 2
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 2
     * @param isReq   True if the CoAP message is a request, or False otherwise
     * @param cI   The connection identifier of the Initiator; set to null if expected in the EDHOC Message 2
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param peerPublicKeys   The list of the long-term public keys of authorized peers
     * @param peerCredentials   The list of CRED of the long-term public keys of authorized peers
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @param ownIdCreds   The set of ID_CRED_X used for an authentication credential associated to this peer
     * @return   A list of CBOR Objects including up to three elements.
     * 
     *           The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC Message 3 can be prepared; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *             
     *           In case (i), the second element is optionally present as a CBOR array, with elements
     *           the same elements of the external authorization data EAD2 to deliver to the application.
     *           
     *           In case (ii), the second element is a CBOR integer, with value the CoAP response code
     *           to use for the EDHOC Error Message, if this is a CoAP response. The third element is optionally
     *           present as a CBOR array, with elements the same elements of the external authorization data EAD2
     *           to deliver to the application.
     */
	public static List<CBORObject> readMessage2(byte[] sequence, boolean isReq, CBORObject cI, Map<CBORObject,
			                                    EdhocSession> edhocSessions, Map<CBORObject, OneKey> peerPublicKeys,
			                                    Map<CBORObject, CBORObject> peerCredentials, Set<CBORObject> usedConnectionIds,
			                                    Set<CBORObject> ownIdCreds) {
		
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
		CBORObject cR = null; // The Connection Identifier C_R, or left to null in case of invalid message
		EdhocSession session = null; // The session used for this EDHOC execution
		
		
		int index = 0;
		CBORObject[] objectListRequest = null;
		try {
			objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		}
		catch (Exception e) {
		    errMsg = new String("Malformed or invalid EDHOC message_2");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}
		
		
		/* Consistency checks */
		
		if (error == false && cI == null && objectListRequest.length != 3) {
			errMsg = new String("C_I must be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		if (error == false && cI != null && objectListRequest.length != 2) {
			errMsg = new String("C_I must not be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		// If EDHOC Message 2 is transported in a CoAP request, C_I is present as first element of the CBOR sequence
		if (error == false && isReq == true) {
			if (error == false && objectListRequest[index].getType() != CBORType.ByteString &&
				objectListRequest[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_I must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
			if (error == false && objectListRequest[index].getType() == CBORType.Integer &&
				    Util.isDeterministicCborInteger(objectListRequest[index]) == false) {
				        errMsg = new String("C_I is an integer but it does not comply with deterministic CBOR encoding");
				        responseCode = ResponseCode.BAD_REQUEST;
				        error = true;
			}
			if (error == false) {
				connectionIdentifier = objectListRequest[index];
				index++;
			}
		}
		
		if (error == false && isReq == false && cI != null) {
				connectionIdentifier = cI; 
		}
		
		if (error == false) {
			if (connectionIdentifier != null)
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
		}
		
		// G_Y | CIPHERTEXT_2
		byte[] gY = null;
		byte[] ciphertext2 = null;
		byte[] gY_Ciphertext2 = null;
		int gYLength = 0;
		int ciphetertext2Length = 0;
		if (error == false && objectListRequest[index].getType() != CBORType.ByteString) {
				errMsg = new String("(G_Y | CIPHERTEXT_2) must be a byte string");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false) {
			gY_Ciphertext2 = objectListRequest[index].GetByteString();
			
			gYLength = EdhocSession.getEphermeralKeyLength(session.getSelectedCiphersuite());
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
			
			int selectedCipherSuite = session.getSelectedCiphersuite();
			
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
			session.setCiphertext2(ciphertext2);
			
			
			// Move to the next element of the CBOR sequence, i.e., C_R 
			index++;
			
		}
		

		// C_R		
		if (error == false) {
			cR = objectListRequest[index];
			
			if (cR.getType() != CBORType.ByteString && cR.getType() != CBORType.Integer) {
					errMsg = new String("C_R must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
			if (error == false && cR.getType() == CBORType.Integer &&
				Util.isDeterministicCborInteger(cR) == false) {
			        errMsg = new String("C_R is an integer but it does not comply with deterministic CBOR encoding");
			        responseCode = ResponseCode.BAD_REQUEST;
			        error = true;
			}
			if (error == false && session.getApplicabilityStatement().getUsedForOSCORE() == true) {
				byte[] recipientId = EdhocSession.edhocToOscoreId(session.getConnectionId());
				byte[] senderId = EdhocSession.edhocToOscoreId(cR);
				if (Arrays.equals(recipientId, senderId)) {
			        errMsg = new String("C_I and C_R cannot be equivalent and yield the same OSCORE Sender/Recipient ID");
			        responseCode = ResponseCode.BAD_REQUEST;
			        error = true;
				}
			}
			if (error == false && objectListRequest[index].getType() == CBORType.ByteString) {
				
				if (session.getApplicabilityStatement().getSupportCombinedRequest() == true ||
					session.getApplicabilityStatement().getConversionMethodOscoreToEdhoc() == Constants.CONVERSION_ID_CORE) {
					
					byte[] buffer = objectListRequest[index].GetByteString();
					if (Util.isCborIntegerEncoding(buffer) == true) {
						errMsg = new String("C_R does not comply with the method for converting from "
								            + "OSCORE Recipient/Sender IDs to EDHOC Connection Identifiers");
						responseCode = ResponseCode.BAD_REQUEST;
						error = true;
					}
					
				}
				
			}
			if (error == false) {
				session.setPeerConnectionId(cR);
			}
		}
		
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
		}
		
		
		/* Decrypt CIPHERTEXT_2 */
			
        // Compute TH2
		
        byte[] th2 = null;
        byte[] hashMessage1 = session.getHashMessage1(); // the hash of message_1, as plain bytes
        List<CBORObject> objectListData2 = new ArrayList<>();
        for (int i = 0; i < objectListRequest.length - 1; i++)
        	objectListData2.add(objectListRequest[i]);
        byte[] hashMessage1SerializedCBOR = CBORObject.FromObject(hashMessage1).EncodeToBytes();
        byte[] gYSerializedCBOR = CBORObject.FromObject(gY).EncodeToBytes();
        byte[] cRSerializedCBOR = cR.EncodeToBytes();
        
        th2 = computeTH2(session, hashMessage1SerializedCBOR, gYSerializedCBOR, cRSerializedCBOR);
        if (th2 == null) {
        	errMsg = new String("Error when computing TH2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
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
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("G_XY", dhSecret);
    	}
        
        // Compute PRK_2e
    	String hashAlgorithm = EdhocSession.getEdhocHashAlg(session.getSelectedCiphersuite());
    	prk2e = computePRK2e(dhSecret, hashAlgorithm);
    	dhSecret = null;
    	if (prk2e == null) {
        	errMsg = new String("Error when computing PRK_2e");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
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
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
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
    	
    	error = false;
    	
    	// Parse the outer plaintext as a CBOR sequence
    	int baseIndex = 0;
    	CBORObject[] plaintextElementList = null;
    	try {
    		plaintextElementList = CBORObject.DecodeSequenceFromBytes(outerPlaintext);
    	}
    	catch (Exception e) {
    	    errMsg = new String("Malformed or invalid plaintext from CIPHERTEXT_2");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
	    
    	if (error == false && plaintextElementList.length == 0) {
        	errMsg = new String("Malformed or invalid plaintext from CIPHERTEXT_2");
        	responseCode = ResponseCode.BAD_REQUEST;
    		error = true;
    	}
    	else if (error == false) {
        	// Discard possible padding prepended to the plaintext
	    	while (plaintextElementList[baseIndex] == CBORObject.True)
	    		baseIndex++;
    	}
    	else if (error == false && plaintextElementList.length - baseIndex < 2) {
        	errMsg = new String("Invalid format of the content encrypted as CIPHERTEXT_2");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	else if (error == false &&
    			 plaintextElementList[baseIndex].getType() != CBORType.ByteString &&
    			 plaintextElementList[baseIndex].getType() != CBORType.Integer &&
    			 plaintextElementList[baseIndex].getType() != CBORType.Map) {
        	errMsg = new String("Invalid format of ID_CRED_R");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}
    	else if (error == false && plaintextElementList[baseIndex + 1].getType() != CBORType.ByteString) {
        	errMsg = new String("Signature_or_MAC_2 must be a byte string");
        	responseCode = ResponseCode.BAD_REQUEST;
        	error = true;
    	}	
    	else if (error == false && plaintextElementList.length - baseIndex > 2) {
    		// EAD_2 is present
    		int length = plaintextElementList.length - baseIndex - 2;
    		
    		if ((length % 2) == 1) {
	        	errMsg = new String("Malformed or invalid EAD_2");
	        	responseCode = ResponseCode.BAD_REQUEST;
	        	error = true;
    		}
    		else {
    	        ead2 = new CBORObject[length];
    	        
    	        for (int i = baseIndex + 2; i < plaintextElementList.length; i++) {
        	        if ((i % 2) == 0 && plaintextElementList[i].getType() != CBORType.Integer) {
        	        	ead2 = null;
        	        	errMsg = new String("Malformed or invalid EAD_2");
        	        	responseCode = ResponseCode.BAD_REQUEST;
        	        	error = true;
        	        	break;
        	        }
        	        if ((i % 2) == 1 && plaintextElementList[i].getType() != CBORType.ByteString) {
        	        	ead2 = null;
        	        	errMsg = new String("Malformed or invalid EAD_2");
        	        	responseCode = ResponseCode.BAD_REQUEST;
        	        	error = true;
        	        	break;
        	        }
    	            // Make a hard copy
    	            byte[] serializedObject = plaintextElementList[i].EncodeToBytes();
    	            CBORObject element = CBORObject.DecodeFromBytes(serializedObject);
    	            ead2[i] = element;
    	        }
    		}
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
    	}
    	
    	
    	// Verify that the identity of the Responder is an allowed identity
    	CBORObject idCredR = CBORObject.NewMap();
    	CBORObject rawIdCredR = plaintextElementList[0];
    	error = false;
    	
    	// ID_CRED_R is a CBOR map with 'kid', and only 'kid' was transported
    	if (rawIdCredR.getType() == CBORType.Integer || rawIdCredR.getType() == CBORType.ByteString) {
    		idCredR.Add(HeaderKeys.KID.AsCBOR(), rawIdCredR);
    	}
    	else if (rawIdCredR.getType() == CBORType.Map) {
    		idCredR = rawIdCredR;
    	}
    	else {
    	    errMsg = new String("Invalid format for ID_CRED_R");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	if (error == false && !peerPublicKeys.containsKey(idCredR)) {
        	errMsg = new String("The identity expressed by ID_CRED_R is not recognized");
        	responseCode = ResponseCode.BAD_REQUEST;
			error = true;
    	}
    	if (error == false && ownIdCreds.contains(idCredR)) {
        	errMsg = new String("The identity expressed by ID_CRED_R is equal to my own identity");
        	responseCode = ResponseCode.BAD_REQUEST;
			error = true;
    	}
    	
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
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
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
    	}
    	else if (debugPrint) {
	    		Util.nicePrint("PRK_3e2m", prk3e2m);
    	}
    	session.setPRK3e2m(prk3e2m);
    	
    	
    	/* Start verifying Signature_or_MAC_2 */
    	
    	CBORObject peerCredentialCBOR = peerCredentials.get(idCredR);
    	if (peerCredentialCBOR == null) {
        	errMsg = new String("Unable to retrieve the peer credential");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
    	}
    	byte[] peerCredential = peerCredentialCBOR.GetByteString();
    	
    	// Compute MAC_2
    	byte[] mac2 = computeMAC2(session, prk3e2m, th2, idCredR, peerCredential, ead2);
    	if (mac2 == null) {
        	errMsg = new String("Error when computing MAC_2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_2", mac2);
    	}
            	
    	// Verify Signature_or_MAC_2
    	byte[] signatureOrMac2 = plaintextElementList[1].GetByteString();
    	if (debugPrint && signatureOrMac2 != null) {
    		Util.nicePrint("Signature_or_MAC_2", signatureOrMac2);
    	}
        
    	// Prepare the External Data, as a CBOR sequence
    	byte[] externalData = computeExternalData(th2, peerCredential, ead2);
    	if (externalData == null) {
        	errMsg = new String("Error when computing External Data for MAC_2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to verify Signature_or_MAC_2", externalData);
    	}
    	
    	if (!verifySignatureOrMac2(session, signatureOrMac2, externalData, mac2)) {
        	errMsg = new String("Non valid Signature_or_MAC_2");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, cR, errMsg, null, responseCode, ead2);
    	}
    	
    	/* End verifying Signature_or_MAC_2 */
		
    	
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
		
		System.out.println("\nCompleted processing of EDHOC Message 2");
		return processingResult;
		
	}
	
    /**
     *  Process an EDHOC Message 3
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 3
     * @param isReq   True if the CoAP message is a request, or False otherwise
     * @param cR   The connection identifier of the Responder; set to null if expected in the EDHOC Message 3
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param peerPublicKeys   The list of the long-term public keys of authorized peers
     * @param peerCredentials   The list of CRED of the long-term public keys of authorized peers
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @return   A list of CBOR Objects including up to three elements.
     * 
     *           The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC message_3 was successfully processed; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *           
     *           In case (i), the second element is a CBOR byte string, specifying the Connection Identifier
     *           of the Responder in the used EDHOC session, i.e. C_R.
     *           
     *           In case (ii), the second element is a CBOR integer, with value the CoAP response code
     *           to use for the EDHOC Error Message, if this is a CoAP response.
     *           
     *           The third element is optionally present in both cases (i) and (ii). If present, it is a CBOR array,
     *           with elements the same elements of the external authorization data EAD1 to deliver to the application.
     */
	public static List<CBORObject> readMessage3(byte[] sequence, boolean isReq, CBORObject cR, Map<CBORObject,
            								EdhocSession> edhocSessions, Map<CBORObject, OneKey> peerPublicKeys,
            								Map<CBORObject, CBORObject> peerCredentials, Set<CBORObject> usedConnectionIds) {
		
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
		CBORObject cI = null; // The Connection Identifier C_I, or left to null in case of invalid message
		EdhocSession session = null; // The session used for this EDHOC execution
		

		int index = 0;
		CBORObject[] objectListRequest = null;
		try {
			objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		}
		catch (Exception e) {
		    errMsg = new String("Malformed or invalid EDHOC message_3");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}
		
		
		/* Consistency checks */
		
		if (error == false && cR == null && objectListRequest.length != 2) {
			errMsg = new String("C_R must be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		if (error == false && cR != null && objectListRequest.length != 1) {
			errMsg = new String("C_R must not be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		// If EDHOC Message 3 is transported in a CoAP request, C_R is present as first element of the CBOR sequence
		if (error == false && isReq == true) {
			if (error == false && objectListRequest[index].getType() != CBORType.ByteString &&
				objectListRequest[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_R must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
			if (error == false && objectListRequest[index].getType() == CBORType.Integer &&
				    Util.isDeterministicCborInteger(objectListRequest[index]) == false) {
				        errMsg = new String("C_R is an integer but it does not comply with deterministic CBOR encoding");
				        responseCode = ResponseCode.BAD_REQUEST;
				        error = true;
			}
			else {
				connectionIdentifier = objectListRequest[index];
				index++;
			}
		}
		
		if (error == false && isReq == false && cR != null) {
			connectionIdentifier = cR;
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
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
		}
		
		
		/* Decrypt CIPHERTEXT_3 */
		
        // Compute TH3
        byte[] th2 = session.getTH2(); // TH_2 as plain bytes
        byte[] th2SerializedCBOR = CBORObject.FromObject(th2).EncodeToBytes();
        byte[] ciphertext2 = session.getCiphertext2(); // CIPHERTEXT_2 as plain bytes
        byte[] ciphertext2SerializedCBOR = CBORObject.FromObject(ciphertext2).EncodeToBytes();
        
        byte[] th3 = computeTH3(session, th2SerializedCBOR, ciphertext2SerializedCBOR);
        if (th3 == null) {
        	errMsg = new String("Error when computing TH3");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
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
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_3ae", k3ae);
    	}
    	
    	byte[] iv3ae = computeIV(Constants.EDHOC_IV_3AE, session);
    	if (iv3ae == null) {
        	errMsg = new String("Error when computing IV_3ae");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
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
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("Plaintext retrieved from CIPHERTEXT_3", outerPlaintext);
    	}
    	
    	error = false;
    	
    	// Parse the outer plaintext as a CBOR sequence
    	int baseIndex = 0;
    	CBORObject[] plaintextElementList = null;
    	try {
    		plaintextElementList = CBORObject.DecodeSequenceFromBytes(outerPlaintext);
    	}
    	catch (Exception e) {
    	    errMsg = new String("Malformed or invalid plaintext from CIPHERTEXT_3");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	
    	if (error == false && plaintextElementList.length == 0) {
    	    errMsg = new String("Malformed or invalid plaintext from CIPHERTEXT_3");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	else if (error == false) {
    	    // Discard possible padding prepended to the plaintext
    	    while (plaintextElementList[baseIndex] == CBORObject.True)
    	        baseIndex++;
    	}
    	else if (error == false && plaintextElementList.length - baseIndex < 2) {
    	    errMsg = new String("Invalid format of the content encrypted as CIPHERTEXT_3");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	else if (error == false &&
                plaintextElementList[baseIndex].getType() != CBORType.ByteString &&
                plaintextElementList[baseIndex].getType() != CBORType.Integer &&
                plaintextElementList[baseIndex].getType() != CBORType.Map) {
        errMsg = new String("Invalid format of ID_CRED_I");
        responseCode = ResponseCode.BAD_REQUEST;
        error = true;
    	}
    	else if (error == false && plaintextElementList[baseIndex + 1].getType() != CBORType.ByteString) {
    	    errMsg = new String("Signature_or_MAC_3 must be a byte string");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	else if (error == false && plaintextElementList.length - baseIndex > 2) {
    	    // EAD_3 is present
    	    int length = plaintextElementList.length - baseIndex - 2;
    	    
    	    if ((length % 2) == 1) {
    	        errMsg = new String("Malformed or invalid EAD_3");
    	        responseCode = ResponseCode.BAD_REQUEST;
    	        error = true;
    	    }
    	    else {
    	        ead3 = new CBORObject[length];
    	        
    	        for (int i = baseIndex + 2; i < plaintextElementList.length; i++) {
    	            if ((i % 2) == 0 && plaintextElementList[i].getType() != CBORType.Integer) {
    	                ead3 = null;
    	                errMsg = new String("Malformed or invalid EAD_3");
    	                responseCode = ResponseCode.BAD_REQUEST;
    	                error = true;
    	                break;
    	            }
    	            if ((i % 2) == 1 && plaintextElementList[i].getType() != CBORType.ByteString) {
    	                ead3 = null;
    	                errMsg = new String("Malformed or invalid EAD_3");
    	                responseCode = ResponseCode.BAD_REQUEST;
    	                error = true;
    	                break;
    	            }
    	            // Make a hard copy
    	            byte[] serializedObject = plaintextElementList[i].EncodeToBytes();
    	            CBORObject element = CBORObject.DecodeFromBytes(serializedObject);
    	            ead3[i] = element;
    	        }
    	    }
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
    	}
    	
    	// Verify that the identity of the Initiator is an allowed identity
    	CBORObject idCredI = CBORObject.NewMap();
    	CBORObject rawIdCredI = plaintextElementList[0];
    	error = false;
    	
    	// ID_CRED_I is a CBOR map with 'kid', and only 'kid' was transported
    	if (rawIdCredI.getType() == CBORType.Integer || rawIdCredI.getType() == CBORType.ByteString) {
    	    idCredI.Add(HeaderKeys.KID.AsCBOR(), rawIdCredI);
    	}
    	else if (rawIdCredI.getType() == CBORType.Map) {
    	    idCredI = rawIdCredI;
    	}
    	else {
    	    errMsg = new String("Invalid format for ID_CRED_I");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	if (error == false && !peerPublicKeys.containsKey(idCredI)) {
    	    errMsg = new String("The identity expressed by ID_CRED_I is not recognized");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
    	}
    	
    	session.setPeerIdCred(idCredI);
    	OneKey peerKey = peerPublicKeys.get(idCredI);
    	session.setPeerLongTermPublicKey(peerKey);

    	CBORObject peerCredentialCBOR = peerCredentials.get(idCredI);
    	if (peerCredentialCBOR == null) {
        	errMsg = new String("Unable to retrieve the peer credential");
        	responseCode = ResponseCode.BAD_REQUEST;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
    		return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
    	}
    	byte[] peerCredential = peerCredentialCBOR.GetByteString();
    	
        // Compute the key material
        byte[] prk4x3m = computePRK4x3m(session);
    	if (prk4x3m == null) {
    		errMsg = new String("Error when computing PRK_4x3m");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("PRK_4x3m", prk4x3m);
    	}
    	session.setPRK4x3m(prk4x3m);

    	
    	/* Start verifying Signature_or_MAC_3 */

    	// Compute MAC_3
    	byte[] mac3 = computeMAC3(session, prk4x3m, th3, idCredI, peerCredential, ead3);
    	if (mac3 == null) {
    		errMsg = new String("Error when computing MAC_3");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_3", mac3);
    	}
    	
    	
    	// Verify Signature_or_MAC_3
    	
    	byte[] signatureOrMac3 = plaintextElementList[1].GetByteString();
    	if (debugPrint && signatureOrMac3 != null) {
    		Util.nicePrint("Signature_or_MAC_3", signatureOrMac3);
    	}
    	
        // Compute the external data, as a CBOR sequence
    	externalData = computeExternalData(th3, peerCredential, ead3);
    	if (externalData == null) {
    		errMsg = new String("Error when computing the external data for MAC_3");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
    		return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to verify Signature_or_MAC_3", externalData);
    	}
    	
    	if (!verifySignatureOrMac3(session, signatureOrMac3, externalData, mac3)) {
        	errMsg = new String("Non valid Signature_or_MAC_3");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
    	}
    	
    	/* End verifying Signature_or_MAC_3 */
    	
    	
    	/* Compute TH4 */
    	
        byte[] th3SerializedCBOR = CBORObject.FromObject(th3).EncodeToBytes();
        byte[] ciphertext3SerializedCBOR = CBORObject.FromObject(ciphertext3).EncodeToBytes();
    	byte[] th4 = computeTH4(session, th3SerializedCBOR, ciphertext3SerializedCBOR);
        if (th4 == null) {
        	errMsg = new String("Error when computing TH_4");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
        	return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, cI, errMsg, null, responseCode, ead3);
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
		
		System.out.println("\nCompleted processing of EDHOC Message 3\n");
		return processingResult;
		
	}
	
	
    /**
     *  Process an EDHOC Message 4
     * @param sequence   The CBOR sequence used as payload of the EDHOC Message 4
     * @param isReq   True if the CoAP message is a request, or False otherwise
     * @param cI   The connection identifier of the Initiator; set to null if expected in the EDHOC Message 4
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @return   A list of CBOR Objects including up to three elements.
     * 
     *           The first element is a CBOR byte string, with value either:
     *              i) a zero length byte string, indicating that the EDHOC Message 4 was correct; or
     *             ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *             
     *           In case (i), the second element is optionally present as a CBOR array, with elements
     *           the same elements of the external authorization data EAD4 to deliver to the application.
     *           
     *           In case (ii), the second element is a CBOR integer, with value the CoAP response code
     *           to use for the EDHOC Error Message, if this is a CoAP response. The third element is optionally
     *           present as a CBOR array, with elements the same elements of the external authorization data EAD4
     *           to deliver to the application.
     */
	public static List<CBORObject> readMessage4(byte[] sequence, boolean isReq, CBORObject cI,
			                                    Map<CBORObject,EdhocSession> edhocSessions,
			                                    Set<CBORObject> usedConnectionIds) {
		
		if (sequence == null || edhocSessions == null || usedConnectionIds == null)
			return null;
		
		CBORObject connectionIdentifier = null; // The Connection Identifier C_I
		
		CBORObject[] ead4 = null; // Will be set if External Authorization Data is present as EAD4
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = null; // Will be set to the CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		CBORObject cR = null; // The Connection Identifier C_R, or left to null in case of invalid message
		EdhocSession session = null; // The session used for this EDHOC execution
		
		int index = 0;
		CBORObject[] objectListRequest = null;
		try {
			objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		}
		catch (Exception e) {
		    errMsg = new String("Malformed or invalid EDHOC message_4");
		    responseCode = ResponseCode.BAD_REQUEST;
		    error = true;
		}

		
		/* Consistency checks */

		if (error == false && cI == null && objectListRequest.length != 2) {
			errMsg = new String("C_I must be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		if (error == false && cI != null && objectListRequest.length != 1) {
			errMsg = new String("C_I must not be specified");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		// If EDHOC Message 4 is transported in a CoAP request, C_I is present as first element of the CBOR sequence
		if (error == false && isReq == true) {
			if (error == false && objectListRequest[index].getType() != CBORType.ByteString &&
				objectListRequest[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_I must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
			if (error == false && objectListRequest[index].getType() == CBORType.Integer &&
				    Util.isDeterministicCborInteger(objectListRequest[index]) == false) {
				        errMsg = new String("C_I is an integer but it does not comply with deterministic CBOR encoding");
				        responseCode = ResponseCode.BAD_REQUEST;
				        error = true;
			}
			else {
				connectionIdentifier = objectListRequest[index];
				index++;
			}
		}
		
		if (error == false && isReq == false && cI != null) {
			connectionIdentifier = cI;
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
		}
		
		if (session != null && session.getPeerConnectionId() != null)
				cR = session.getPeerConnectionId();


		// CIPHERTEXT_4
		byte[] ciphertext4 = null;
		if (error == false && objectListRequest[index].getType() != CBORType.ByteString) {
			errMsg = new String("CIPHERTEXT_4 must be a byte string");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		else {
			ciphertext4 = objectListRequest[index].GetByteString();
			if (ciphertext4 == null) {
				errMsg = new String("Error when retrieving CIPHERTEXT_4");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
			}
		}
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_4, !isReq, cR, errMsg, null, responseCode, null);
		}

		
		
		/* Compute the plaintext */
		
		if (debugPrint && ciphertext4 != null) {
		    Util.nicePrint("CIPHERTEXT_4", ciphertext4);
		}
		
        // Compute the external data for the external_aad
		
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
    	
    	byte[] k4ae = computeKey(Constants.EDHOC_K_4AE, session);
    	if (k4ae == null) {
    		errMsg = new String("Error when computing K");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K", k4ae);
    	}

    	byte[] iv4ae = computeIV(Constants.EDHOC_IV_4AE, session);
    	if (iv4ae == null) {
    		errMsg = new String("Error when computing IV");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("IV", iv4ae);
    	}
        
    	byte[] outerPlaintext = decryptCiphertext4(session, externalData, ciphertext4, k4ae, iv4ae);
    	if (outerPlaintext == null) {
    	    errMsg = new String("Error when decrypting CIPHERTEXT_4");
    	    responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    	    Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
    	    return processError(errorCode, Constants.EDHOC_MESSAGE_4, !isReq, cI, errMsg, null, responseCode, null);
    	}
    	else if (debugPrint) {
    	    Util.nicePrint("Plaintext retrieved from CIPHERTEXT_4", outerPlaintext);
    	}
    	
        /* End computing the plaintext */
    	
    	
    	// Parse the outer plaintext as a CBOR sequence. To be valid, this is either the empty plaintext,
    	// or the External Authorization Data EAD_4 possibly prepended by padding 
    	error = false;
    	int baseIndex = 0;
    	CBORObject[] plaintextElementList = null;
    	
    	if (outerPlaintext.length != 0) {
    		try {
    			plaintextElementList = CBORObject.DecodeSequenceFromBytes(outerPlaintext);
    		}
    		catch (Exception e) {
        		errMsg = new String("Malformed or invalid EAD_4");
        		responseCode = ResponseCode.BAD_REQUEST;
    			error = true;
    		}
    		
        	if (error == false) {
        	    // Discard possible padding prepended to the plaintext
        	    while (plaintextElementList[baseIndex] == CBORObject.True)
        	        baseIndex++;
        	}
        	if (error == false && plaintextElementList.length - baseIndex > 0) {
        	    // EAD_4 is present
        	    int length = plaintextElementList.length - baseIndex;
        	    
        	    if ((length % 2) == 1) {
        	        errMsg = new String("Malformed or invalid EAD_4");
        	        responseCode = ResponseCode.BAD_REQUEST;
        	        error = true;
        	    }
        	    else {
        	        ead4 = new CBORObject[length];
        	        
        	        for (int i = baseIndex; i < plaintextElementList.length; i++) {
        	            if ((i % 2) == 0 && plaintextElementList[i].getType() != CBORType.Integer) {
        	                ead4 = null;
        	                errMsg = new String("Malformed or invalid EAD_4");
        	                responseCode = ResponseCode.BAD_REQUEST;
        	                error = true;
        	                break;
        	            }
        	            if ((i % 2) == 1 && plaintextElementList[i].getType() != CBORType.ByteString) {
        	                ead4 = null;
        	                errMsg = new String("Malformed or invalid EAD_4");
        	                responseCode = ResponseCode.BAD_REQUEST;
        	                error = true;
        	                break;
        	            }
        	            // Make a hard copy
        	            byte[] serializedObject = plaintextElementList[i].EncodeToBytes();
        	            CBORObject element = CBORObject.DecodeFromBytes(serializedObject);
        	            ead4[i] = element;
        	        }
        	    }
        	}
    		
    	}
    	
    	// Return an EDHOC Error Message
    	if (error == true) {
        	Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_4, !isReq, cR, errMsg, null, responseCode, ead4);
    	}
    	
		
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
     * @param sequence   The CBOR sequence used as paylod of the EDHOC Error Message
     * @param cX   The connection identifier of the recipient; set to null if expected in the EDHOC Error Message
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @return  The elements of the EDHOC Error Message as CBOR objects, or null in case of errors
     */
	public static CBORObject[] readErrorMessage(byte[] sequence, CBORObject cX,
			                                    Map<CBORObject, EdhocSession> edhocSessions) {
		
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
		
		// C_X is provided by the method caller
		if (cX != null) {
			mySession = edhocSessions.get(cX);
		}
		
		// The connection identifier is expected as first element in the EDHOC Error Message
		else {
			
			if (objectList[index].getType() == CBORType.ByteString || objectList[index].getType() == CBORType.Integer) {
				mySession = edhocSessions.get(objectList[index]);
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
							System.err.println("Error when processing EDHOC Error Message - "
									         + "Invalid format for elements of SUITES_R");
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
        List<Integer> supportedCiphersuites = session.getSupportedCipherSuites();
        List<Integer> peerSupportedCiphersuites = session.getPeerSupportedCipherSuites();
        
    	int selectedSuite = -1;
    	int preferredSuite = supportedCiphersuites.get(0).intValue();
    	
    	// No SUITES_R has been received, so it is not known what ciphersuites the responder supports
    	if (peerSupportedCiphersuites == null) {
    		// The selected ciphersuite is the most preferred by the initiator
    		selectedSuite = preferredSuite;
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
    		for (Integer i : supportedCiphersuites) {
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
		
		// C_I
        CBORObject cI = session.getConnectionId();
		objectList.add(cI);
        if (debugPrint) {
        	Util.nicePrint("C_I", cI.EncodeToBytes());
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
		ResponseCode responseCode = ResponseCode.INTERNAL_SERVER_ERROR;; // The CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 2:\n");
        }
		
        
        // C_I, if EDHOC message_2 is transported in a CoAP request
		if (!session.isClientInitiated()) {
			CBORObject cI = session.getPeerConnectionId();
			objectList.add(cI);
	        if (debugPrint) {
	        	Util.nicePrint("C_I", cI.EncodeToBytes());
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
    	if (debugPrint) {
    	    Util.nicePrint("G_Y", gY.EncodeToBytes());
    	}
		
		// C_R
		CBORObject cR = session.getConnectionId();
    	if (debugPrint) {
    	    Util.nicePrint("C_R", cR.EncodeToBytes());
    	}
    	
    	
        // Compute TH_2
        
        byte[] hashMessage1 = session.getHashMessage1(); // the hash of message_1, as plain bytes
        byte[] hashMessage1SerializedCBOR = CBORObject.FromObject(hashMessage1).EncodeToBytes();
        byte[] gYSerializedCBOR = gY.EncodeToBytes();
        byte[] cRSerializedCBOR = cR.EncodeToBytes();
        
        byte[] th2 = computeTH2(session, hashMessage1SerializedCBOR, gYSerializedCBOR, cRSerializedCBOR);
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
        String hashAlgorithm = EdhocSession.getEdhocHashAlg(session.getSelectedCiphersuite());
    	prk2e = computePRK2e(dhSecret, hashAlgorithm);
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
    	
        
    	/* Start computing Signature_or_MAC_2 */    	
    	
    	// Compute MAC_2
    	byte[] mac2 = computeMAC2(session, prk3e2m, th2, session.getIdCred(), session.getCred(), ead2);
    	if (mac2 == null) {
    		System.err.println("Error when computing MAC_2");
    		errMsg = new String("Error when computing MAC_2");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_2", mac2);
    	}
    	
    	
    	// Compute Signature_or_MAC_2
    	
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
    	
    	byte[] signatureOrMac2 = computeSignatureOrMac2(session, mac2, externalData);
    	if (signatureOrMac2 == null) {
    		System.err.println("Error when computing Signature_or_MAC_2");
    		errMsg = new String("Error when computing Signature_or_MAC_2");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("Signature_or_MAC_2", signatureOrMac2);
    	}
    	
    	/* End computing Signature_or_MAC_2 */ 
    
    	
    	/* Start computing CIPHERTEXT_2 */
    
    	// Prepare the plaintext
    	List<CBORObject> plaintextElementList = new ArrayList<>();
    	CBORObject plaintextElement = null;
    	if (session.getIdCred().ContainsKey(HeaderKeys.KID.AsCBOR())) {
    		// ID_CRED_R uses 'kid', whose value is the only thing to include in the plaintext
    		plaintextElement = session.getIdCred().get(HeaderKeys.KID.AsCBOR());
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
    	byte[] plaintext = Util.buildCBORSequence(plaintextElementList);
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

    	
    	// Compute CIPHERTEXT_2
    	byte[] ciphertext2 = Util.arrayXor(plaintext, keystream2);
    	session.setCiphertext2(ciphertext2);
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
    	
    	// The outer CBOR sequence finishes with the connection identifier C_R
    	objectList.add(cR);

    	
    	
		/* Prepare an EDHOC Error Message */
		
		if (error == true) {
			
			// Prepare C_I
			CBORObject cI = CBORObject.FromObject(session.getPeerConnectionId());
			
			List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_1,
															 !session.isClientInitiated(),
															 cI, errMsg, null, responseCode, null);
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
		ResponseCode responseCode = ResponseCode.INTERNAL_SERVER_ERROR; // The CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 3:\n");
        }
		
        /* Start preparing data_3 */
		
        // C_R, if EDHOC message_3 is transported in a CoAP request
		if (session.isClientInitiated()) {
			CBORObject cR = session.getPeerConnectionId();
			objectList.add(cR);
	        if (debugPrint) {
	        	Util.nicePrint("C_R", cR.EncodeToBytes());
	        }
		}
        
		/* End preparing data_3 */
		
		
		/* Start computing the inner COSE object */
		
        // Compute TH_3
        
        byte[] th2 = session.getTH2(); // TH_2 as plain bytes
        byte[] th2SerializedCBOR = CBORObject.FromObject(th2).EncodeToBytes();
        byte[] ciphertext2 = session.getCiphertext2(); // CIPHERTEXT_2 as plain bytes
        byte[] ciphertext2SerializedCBOR = CBORObject.FromObject(ciphertext2).EncodeToBytes();

        byte[] th3 = computeTH3(session, th2SerializedCBOR, ciphertext2SerializedCBOR);
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
        
		
    	/* Start computing Signature_or_MAC_3 */
    	
    	// Compute MAC_3
    	byte[] mac3 = computeMAC3(session, prk4x3m, th3, session.getIdCred(), session.getCred(), ead3);
    	if (mac3 == null) {
    		System.err.println("Error when computing MAC_3");
    		errMsg = new String("Error when computing MAC_3");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("MAC_3", mac3);
    	}
    	
    	
    	// Compute Signature_or_MAC_3
    	
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
    	
    	byte[] signatureOrMac3 = computeSignatureOrMac3(session, mac3, externalData);
    	if (signatureOrMac3 == null) {
    		System.err.println("Error when computing Signature_or_MAC_3");
    		errMsg = new String("Error when computing Signature_or_MAC_3");
    		error = true;
    	}
    	else if (debugPrint) {
    		Util.nicePrint("Signature_or_MAC_3", signatureOrMac3);
    	}
    	
    	/* End computing Signature_or_MAC_3 */
    	
    	
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
    	    	
    	// Prepare the External Data as including only TH3
    	externalData = th3;
    	
    	// Prepare the plaintext
    	List<CBORObject> plaintextElementList = new ArrayList<>();
    	CBORObject plaintextElement = null;
    	if (session.getIdCred().ContainsKey(HeaderKeys.KID.AsCBOR())) {
    	    // ID_CRED_I uses 'kid', whose value is the only thing to include in the plaintext
    	    plaintextElement = session.getIdCred().get(HeaderKeys.KID.AsCBOR());
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
    	byte[] plaintext = Util.buildCBORSequence(plaintextElementList);
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
    	    
    	    // Prepare C_R
    	    CBORObject cR = CBORObject.FromObject(session.getPeerConnectionId());
    	    
    	    List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_2,
    	    												 session.isClientInitiated(),
    	    												 cR, errMsg, null, responseCode, null);
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
     * @param ead4   A CBOR array including the elements of the External Authorization Data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 4 or EDHOC Error Message; or null in case of errors
     */
	public static byte[] writeMessage4(EdhocSession session, CBORObject[] ead4) {
		
		List<CBORObject> objectList = new ArrayList<>();
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		int errorCode = Constants.ERR_CODE_UNSPECIFIED; // The error code to use for the EDHOC Error Message
		ResponseCode responseCode = ResponseCode.INTERNAL_SERVER_ERROR; // The CoAP response code to use for the EDHOC Error Message
		String errMsg = null; // The text string to be possibly returned as DIAG_MSG in an EDHOC Error Message
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 4:\n");
        }
		
        /* Start preparing data_4 */
		
        // C_I, if EDHOC message_4 is transported in a CoAP request
		if (!session.isClientInitiated()) {
			CBORObject cI = session.getPeerConnectionId();
			objectList.add(cI);
	        if (debugPrint) {
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
    	    	
    	
        // Prepare the plaintext
    	byte[] plaintext = new byte[] {};
    	if (error == false) {
	    	if (ead4 != null) {
	    		List<CBORObject> plaintextElementList = new ArrayList<>();
	    	    for (int i = 0; i < ead4.length; i++) {
	    	        plaintextElementList.add(ead4[i]);
	    	    }
	    	    	plaintext = Util.buildCBORSequence(plaintextElementList);
	    	}
	    	if (debugPrint && error == false && plaintext != null) {
		        Util.nicePrint("Plaintext to compute CIPHERTEXT_4", plaintext);
		    }
    	}
    	
    	
        // Compute the key material
      
    	// Compute K and IV to protect the COSE object
    	
    	byte[] k4ae = null;
    	if (error == false) {    	
			k4ae = computeKey(Constants.EDHOC_K_4AE, session);
			if (k4ae == null) {
				System.err.println("Error when computing K_4ae");
				errMsg = new String("Error when computing K_4ae");
				error = true;
			}
			else if (debugPrint) {
				Util.nicePrint("K_4ae", k4ae);
			}
    	}

    	byte[] iv4ae = null;
    	if (error == false) {
	    	iv4ae = computeIV(Constants.EDHOC_IV_4AE, session);
	    	if (iv4ae == null) {
	    		System.err.println("Error when computing IV_4ae");
	    		errMsg = new String("Error when computing IV_4ae");
	    		error = true;
	    	}
	    	else if (debugPrint) {
	    		Util.nicePrint("IV_4ae", iv4ae);
	    	}
    	}
    	
		
    	// Encrypt the COSE object and take the ciphertext as CIPHERTEXT_4
    	byte[] ciphertext4 = null;
    	if (error == false) {
	    	ciphertext4 = computeCiphertext4(session, externalData, plaintext, k4ae, iv4ae);
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
    	    
    	    // Prepare C_I
    	    CBORObject cI = CBORObject.FromObject(session.getPeerConnectionId());
    	    
    	    List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_3,
    	    												 !session.isClientInitiated(),
    	    												 cI, errMsg, null, responseCode, null);
    	    return processingResult.get(0).GetByteString();
    	    
    	}
    	
    	
    	/* Prepare EDHOC Message 4 */
    	
    	objectList.add(CBORObject.FromObject(ciphertext4));
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
     * @param isErrorReq   True if the EDHOC Error Message will be sent in a CoAP request, or False otherwise
     * @param cX   The connection identifier of the intended recipient of the EDHOC Error Message, it can be null
     * @param errMsg   The text string to include in the EDHOC Error Message
     * @param suitesR   The cipher suite(s) supported by the Responder, it can be null;
     *                  (MUST be present in response to EDHOC Message 1)
     * @return  The raw payload to transmit as EDHOC Error Message, or null in case of errors
     */
	public static byte[] writeErrorMessage(int errorCode, int replyTo, boolean isErrorReq,
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
		byte[] payload;
			
		// Possibly include C_X - This might not have been included if the incoming EDHOC message was malformed
		if (cX != null && isErrorReq == true) {
				objectList.add(cX);
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
     * @param isErrorReq   True if the EDHOC Error Message will be sent in a CoAP request, or False otherwise
     * @param cX   The connection identifier of the intended recipient of the EDHOC Error Message, it can be null
     * @param errMsg   The text string to include in the EDHOC Error Message
     * @param suitesR   The cipher suite(s) supported by the Responder (only in response to EDHOC Message 1), it can be null
     * @param ead   The external authorization data from the latest incoming message, it can be null
     * @return  A list of CBOR objects, including the EDHOC Error Message and the CoAP response code to use
     */
	public static List<CBORObject> processError(int errorCode, int replyTo, boolean isErrorReq, CBORObject cX,
			                                    String errMsg, CBORObject suitesR, ResponseCode responseCode,
			                                    CBORObject[] ead) {
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		byte[] replyPayload = writeErrorMessage(errorCode, replyTo, isErrorReq, cX, errMsg, suitesR);
		
		// EDHOC Error Message, as a CBOR byte string
		processingResult.add(CBORObject.FromObject(replyPayload));
		
		// CoAP response code as a CBOR integer
		processingResult.add(CBORObject.FromObject(responseCode.value));
		
		if (errMsg != null) {
			System.err.println(errMsg);
		}
		
		// External Authorization Data (if present)
		if (ead != null) {
		    CBORObject eadArray = CBORObject.NewArray();
		    for (int i = 0; i < ead.length; i++) {
		        eadArray.Add(ead[i]);
		    }
		    processingResult.add(eadArray);
		}
		
		return processingResult;
		
	}
	
	
    /**
     *  Create a new EDHOC session as an Initiator
     * @param method   The authentication method signaled by the Initiator
     * @param keyPair   The identity key of the Initiator
     * @param idCredI   ID_CRED_I for the identity key of the Initiator
     * @param credI   CRED_I for the identity key of the Initiator, as the serialization of a CBOR object
     * @param supportedCipherSuites   The list of ciphersuites supported by the Initiator
     * @param usedConnectionIds   The set of allocated Connection Identifiers for the Initiator
     * @param appStatement   The applicability statement used for this session
     * @param epd   The processor of External Authentication Data used for this session
     * @param db   The database of OSCORE Security Contexts
     * @return  The newly created EDHOC session
     */
	public static EdhocSession createSessionAsInitiator(int method, OneKey keyPair,
												        CBORObject idCredI, byte[] credI,
			  									        List<Integer> supportedCiphersuites,
			  									        Set<CBORObject> usedConnectionIds,
			  									        AppStatement appStatement,
			  									        EDP edp, HashMapCtxDB db) {
		
		CBORObject connectionId = null;
		HashMapCtxDB oscoreDB = (appStatement.getUsedForOSCORE() == true) ? db : null;
		
		connectionId = Util.getConnectionId(usedConnectionIds, oscoreDB, null);
		// Forced for testing
		// connectionId = CBORObject.FromObject(new byte[] {(byte) 0x1c});
		
		usedConnectionIds.add(connectionId);
        EdhocSession mySession = new EdhocSession(true, true, method, connectionId, keyPair,
        										  idCredI, credI, supportedCiphersuites, appStatement, edp, oscoreDB);
		
		return mySession;
		
	}
	
    /**
     *  Create a new EDHOC session as a Responder
     * @param message1   The payload of the received EDHOC Message 1
     * @param keyPair   The identity key of the Responder
     * @param idCredR   ID_CRED_R for the identity key of the Responder
     * @param credR   CRED_R for the identity key of the Responder, as the serialization of a CBOR object
     * @param supportedCipherSuites   The list of ciphersuites supported by the Responder
     * @param usedConnectionIds   The set of allocated Connection Identifiers for the Responder
     * @param appStatement   The applicability statement used for this session
     * @param epd   The processor of External Authentication Data used for this session
     * @param db   The database of OSCORE Security Contexts
     * @return  The newly created EDHOC session
     */
	public static EdhocSession createSessionAsResponder(byte[] message1, boolean isReq, OneKey keyPair,
			                                            CBORObject idCredR, byte[] credR,
			  									        List<Integer> supportedCiphersuites,
			  									        Set<CBORObject> usedConnectionIds,
			  									        AppStatement appStatement,
			  									        EDP edp, HashMapCtxDB db) {
		
		CBORObject[] objectListMessage1 = CBORObject.DecodeSequenceFromBytes(message1);
		int index = -1;
		
		// Retrieve elements from EDHOC Message 1
		
	    // If the received message is a request (i.e. the CoAP client is the initiator), the first element
	    // before the actual message_1 is the CBOR simple value 'true', i.e. the byte 0xf5, and it can be skipped
	    if (isReq == true) {
	        index++;
	    }
		
		// METHOD
	    index++;
		int method = objectListMessage1[index].AsInt32();
		
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
		CBORObject cI = objectListMessage1[index];
		
		
		// Create a new EDHOC session
		
		CBORObject connectionId = null;
		HashMapCtxDB oscoreDB = (appStatement.getUsedForOSCORE() == true) ? db : null;
		
		connectionId = Util.getConnectionId(usedConnectionIds, oscoreDB, cI);
		// Forced for testing
		// connectionId = CBORObject.FromObject(new byte[] {(byte) 0x1d});
		
		usedConnectionIds.add(connectionId);
		EdhocSession mySession = new EdhocSession(false, isReq, method, connectionId, keyPair,
												  idCredR, credR, supportedCiphersuites, appStatement, edp, oscoreDB);
		
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
	    
	    int selectedCiphersuite = session.getSelectedCiphersuite();
	    int keyLength = EdhocSession.getKeyLengthEdhocAEAD(selectedCiphersuite);
	    if (keyLength == 0)
	        return null;
	    
	    byte[] key = new byte[keyLength];
	    String label = null;
	    CBORObject context = CBORObject.FromObject(new byte[0]);
	    
	    try {
	        switch(keyName) {
	            case Constants.EDHOC_K_3AE:
	            	label = new String("K_3");
	                key = session.edhocKDF(session.getPRK3e2m(), session.getTH3(), label, context, keyLength);
	                break;
	            case Constants.EDHOC_K_4AE:
	            	label = new String("EDHOC_K_4");
	                key = session.edhocExporter(label, context, keyLength);
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
    * @return  The computed IV
    */
	public static byte[] computeIV(int ivName, EdhocSession session) {
	    
	    int selectedCiphersuite = session.getSelectedCiphersuite();
	    int ivLength = EdhocSession.getIvLengthEdhocAEAD(selectedCiphersuite);
	    if (ivLength == 0)
	        return null;
	    
	    byte[] iv = new byte[ivLength];
	    String label = null;
	    CBORObject context = CBORObject.FromObject(new byte[0]);
	    
	    try {
	        switch(ivName) {
            case Constants.EDHOC_IV_3AE:
            	label = new String("IV_3");
                iv = session.edhocKDF(session.getPRK3e2m(), session.getTH3(), label, context, ivLength);
                break;
            case Constants.EDHOC_IV_4AE:
            	label = new String("EDHOC_IV_4");
                iv = session.edhocExporter(label, context, ivLength);
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
		CBORObject context = CBORObject.FromObject(new byte[0]);
		try {
			keystream2 = session.edhocKDF(session.getPRK2e(), session.getTH2(), "KEYSTREAM_2", context, length);
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
     * @param hashAlgorithm   The EDHOC hash algorithm of the selected cipher suite
     * @return  The computed key PRK_2e
     */
	public static byte[] computePRK2e(byte[] dhSecret, String hashAlgorithm) {
	
		byte[] prk2e = null;
	    try {  	
	    	if (hashAlgorithm.equals("SHA-256") || hashAlgorithm.equals("SHA-384") || hashAlgorithm.equals("SHA-512")) {
	    		prk2e = Hkdf.extract(new byte[] {}, dhSecret);
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
            	
            	String hashAlgorithm = EdhocSession.getEdhocHashAlg(session.getSelectedCiphersuite());
            	try {
            		if (hashAlgorithm.equals("SHA-256") || hashAlgorithm.equals("SHA-384") || hashAlgorithm.equals("SHA-512")) {
            			prk3e2m = Hkdf.extract(prk2e, dhSecret);
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
            	
            	String hashAlgorithm = EdhocSession.getEdhocHashAlg(session.getSelectedCiphersuite());
            	try {
            		if (hashAlgorithm.equals("SHA-256") || hashAlgorithm.equals("SHA-384") || hashAlgorithm.equals("SHA-512")) {
            			prk4x3m = Hkdf.extract(prk3e2m, dhSecret);
            		}
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
     * @param prk3e2m   The PRK used to compute MAC_2
     * @param th2   The transcript hash TH2
     * @param idCredR   The ID_CRED_R associated to the long-term public key of the Responder
     * @param credR   The long-term public key of the Responder, as the serialization of a CBOR object
     * @param ead2   The External Authorization Data from EDHOC Message 2, it can be null
     * @return  The computed MAC_2
     */
	public static byte[] computeMAC2(EdhocSession session, byte[] prk3e2m, byte[] th2,
			                         CBORObject idCredR, byte[] credR, CBORObject[] ead2) {
		
		// Build the CBOR sequence to use for 'context': ( ID_CRED_R, CRED_R, ? EAD_2 )
		// The actual 'context' is a CBOR byte string with value the serialization of the CBOR sequence
        List<CBORObject> objectList = new ArrayList<>();
    	objectList.add(idCredR);
    	objectList.add(CBORObject.DecodeFromBytes(credR));
    	
    	if (ead2 != null) {
	    	for (int i = 0; i < ead2.length; i++)
	    		objectList.add(ead2[i]);
    	}
    	byte[] contextSequence = Util.buildCBORSequence(objectList);
    	CBORObject context = CBORObject.FromObject(contextSequence);
    	
    	int macLength = 0;
    	int method = session.getMethod();
    	int selectedCipherSuite = session.getSelectedCiphersuite();
    	if (method == 0 || method == 2) {
    		macLength = EdhocSession.getEdhocHashAlgOutputSize(selectedCipherSuite);
    	}
    	if (method == 1 || method == 3) {
    		macLength = EdhocSession.getTagLengthEdhocAEAD(selectedCipherSuite);
    	}
    	
    	byte[] mac2 = new byte[macLength];
    	try {
			mac2 = session.edhocKDF(prk3e2m, th2, "MAC_2", context, macLength);
		} catch (InvalidKeyException e) {
			System.err.println("Error when computing MAC_2\n" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when computing MAC_2\n" + e.getMessage());
		}
		
		return mac2;
		
	}

	
    /**
     *  Compute MAC_3
     * @param session   The used EDHOC session
     * @param prk4x3m   The PRK used to compute MAC_3
     * @param th3   The transcript hash TH3
     * @param idCredI   The ID_CRED_I associated to the long-term public key of the Initiator
     * @param credI   The long-term public key of the Initiator, as the serialization of a CBOR object
     * @param ead3   The External Authorization Data from EDHOC Message 3, it can be null
     * @return  The computed MAC_3
     */
	public static byte[] computeMAC3(EdhocSession session, byte[] prk4x3m, byte[] th3,
            						 CBORObject idCredI, byte[] credI, CBORObject[] ead3) {
				
		// Build the CBOR sequence for 'context': ( ID_CRED_I, CRED_I, ? EAD_3 )
		// The actual 'context' is a CBOR byte string with value the serialization of the CBOR sequence
        List<CBORObject> objectList = new ArrayList<>();
    	objectList.add(idCredI);
    	objectList.add(CBORObject.DecodeFromBytes(credI));
    	
    	if (ead3 != null) {
	    	for (int i = 0; i < ead3.length; i++)
	    		objectList.add(ead3[i]);
    	}
    	byte[] contextSequence = Util.buildCBORSequence(objectList);
    	CBORObject context = CBORObject.FromObject(contextSequence);
    	
    	int macLength = 0;
    	int method = session.getMethod();
    	int selectedCipherSuite = session.getSelectedCiphersuite();
    	if (method == 0 || method == 1) {
    		macLength = EdhocSession.getEdhocHashAlgOutputSize(selectedCipherSuite);
    	}
    	if (method == 2 || method == 3) {
    		macLength = EdhocSession.getTagLengthEdhocAEAD(selectedCipherSuite);
    	}
    	
    	byte[] mac3 = new byte[macLength];
    	try {
			mac3 = session.edhocKDF(prk4x3m, th3, "MAC_3", context, macLength);
		} catch (InvalidKeyException e) {
			System.err.println("Error when computing MAC_3\n" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when computing MAC_3\n" + e.getMessage());
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
    	
    	int selectedCiphersuite = session.getSelectedCiphersuite();
    	AlgorithmID alg = EdhocSession.getEdhocAEADAlg(selectedCiphersuite);
    	
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
    	
    	int selectedCiphersuite = session.getSelectedCiphersuite();
    	AlgorithmID alg = EdhocSession.getEdhocAEADAlg(selectedCiphersuite);
    	
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
    	
    	int selectedCiphersuite = session.getSelectedCiphersuite();
    	AlgorithmID alg = EdhocSession.getEdhocAEADAlg(selectedCiphersuite);
    	
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
    	
    	int selectedCiphersuite = session.getSelectedCiphersuite();
    	AlgorithmID alg = EdhocSession.getEdhocAEADAlg(selectedCiphersuite);
    	
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
     * @param message1   The hash of EDHOC Message 1, as a serialized CBOR byte string
     * @param gY   The G_Y ephemeral key from the EDHOC Message 2, as a serialized CBOR byte string
     * @param cR   The C_R connection identifier from the EDHOC Message 2, as a serialized CBOR Object
     * @return  The computed TH2
     */
	public static byte[] computeTH2(EdhocSession session, byte[] hashMessage1, byte[] gY, byte[] cR) {
	
        byte[] th2 = null;
        
        int selectedCiphersuite = session.getSelectedCiphersuite();
        String hashAlgorithm = EdhocSession.getEdhocHashAlg(selectedCiphersuite);
        
        int offset = 0;
        byte[] hashInput = new byte[hashMessage1.length + gY.length + cR.length];
        System.arraycopy(hashMessage1, 0, hashInput, 0, hashMessage1.length);
        offset += hashMessage1.length;
        System.arraycopy(gY, 0, hashInput, offset, gY.length);
        offset += gY.length;
        System.arraycopy(cR, 0, hashInput, offset, cR.length);
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
     * @return  The computed TH3
     */
	public static byte[] computeTH3(EdhocSession session, byte[] th2, byte[] ciphertext2) {
	
        byte[] th3 = null;
        int inputLength = th2.length + ciphertext2.length;
        
        int selectedCiphersuite = session.getSelectedCiphersuite();
        String hashAlgorithm = EdhocSession.getEdhocHashAlg(selectedCiphersuite);
        
        int offset = 0;
        byte[] hashInput = new byte[inputLength];
        System.arraycopy(th2, 0, hashInput, offset, th2.length);
        offset += th2.length;
        System.arraycopy(ciphertext2, 0, hashInput, offset, ciphertext2.length);
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
        
        int selectedCiphersuite = session.getSelectedCiphersuite();
        String hashAlgorithm = EdhocSession.getEdhocHashAlg(selectedCiphersuite);
        
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