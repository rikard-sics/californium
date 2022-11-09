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
												List<Integer> supportedCipherSuites,
												Set<Integer> supportedEADs,
												AppProfile appProfile) {
		
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
		
    	if (error == false && appProfile == null) {
			errMsg = new String("Impossible to retrieve the application profile");
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
		    	if (!appProfile.isAuthMethodSupported(method)) {
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

		// Check if the selected cipher suite is supported and that no prior cipher suite in SUITES_I is supported
		List<Integer> cipherSuitesToOffer = new ArrayList<Integer>();
		if (error == false) {
			int selectedCipherSuite;
			
			if (objectListRequest[index].getType() == CBORType.Integer) {
				// SUITES_I is the selected cipher suite
				selectedCipherSuite = objectListRequest[index].AsInt32();
				
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
			
			else if (objectListRequest[index].getType() == CBORType.Array) {
				// The selected cipher suite is the last element of SUITES_I
				int size = objectListRequest[index].size(); 
				selectedCipherSuite = objectListRequest[index].get(size-1).AsInt32();
				
				int firstSharedCipherSuite = -1;
				// Find the first commonly supported cipher suite, i.e. the cipher suite both
				// supported by the Responder and specified as early as possible in SUITES_I
				for (int i = 0; i < size; i++) {
					int suite = objectListRequest[index].get(i).AsInt32();
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
					
					errMsg = new String("The selected cipher suite is not supported");
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
		
		if (error == false && decodeIdentifier(objectListRequest[index]) == null) {
			errMsg = new String("Invalid encoding of C_I");
			responseCode = ResponseCode.BAD_REQUEST;
			error = true;
		}
		
		if (error == false) {
			cI = objectListRequest[index];
			
			byte[] connectionIdentifierInitiator = decodeIdentifier(cI);
			if (debugPrint) {
			    Util.nicePrint("Connection Identifier of the Initiator", connectionIdentifierInitiator);
			    Util.nicePrint("C_I", cI.EncodeToBytes());
			}
		}
		
		// PAD_1
		index++;
		if (error == false) {
		   // Skip possible padding
		   while (objectListRequest.length > index && objectListRequest[index] == CBORObject.True)
		         index++;
		}
		
		// EAD_1
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
		        
		        int eadIndex = 0;
		        
		        for (int i = index; i < objectListRequest.length; i++) {
		        	
		        	// The first element of each pair is an ead_label, and must be a CBOR integer with value different than 0
		            if ((eadIndex % 2) == 0) {
		            	if (objectListRequest[i].getType() != CBORType.Integer || objectListRequest[i].AsInt32() == 0) {
			                ead1 = null;
			                errMsg = new String("Malformed or invalid EAD_1");
			                responseCode = ResponseCode.BAD_REQUEST;
			                error = true;
			                break;
		            	}
		            	int eadLabel = objectListRequest[i].AsInt32();
		            	if (eadLabel < 0 && !supportedEADs.contains(Integer.valueOf(eadLabel))) {
	            			// Since the EAD item is critical and is not supported, discontinue the protocol
			                ead1 = null;
			                errMsg = new String("Unsupported EAD_1 critical item with ead_label " + eadLabel);
			                responseCode = ResponseCode.BAD_REQUEST;
			                error = true;
			                break;
		            	}
		            	
		            	// The ead_label is fine; move on to the ead_value
		            	eadIndex++;
		            	continue;
		            }
		            
		            // The second element of each pair is an ead_value, and must be a CBOR byte string
		            if ((eadIndex % 2) == 1) {
		            	if (objectListRequest[i].getType() != CBORType.ByteString) {
			                ead1 = null;
			                errMsg = new String("Malformed or invalid EAD_1");
			                responseCode = ResponseCode.BAD_REQUEST;
			                error = true;
			                break;
		            	}
		            	// Skip this EAD item as not supported and not critical
		            	if (!supportedEADs.contains(Integer.valueOf(eadIndex-1))) {
		            		eadIndex++;
		            		continue;
		            	}
		            	
		            	// This EAD item is supported, so it is kept for further processing
		            	
			            // Make a hard copy of ead_label
			            byte[] serializedObjectLabel = objectListRequest[i-1].EncodeToBytes();
			            CBORObject elementLabel = CBORObject.DecodeFromBytes(serializedObjectLabel);
			            ead1[eadIndex-1] = elementLabel;
			            
			            // Make a hard copy of ead_value
			            byte[] serializedObjectValue = objectListRequest[i].EncodeToBytes();
			            CBORObject elementValue = CBORObject.DecodeFromBytes(serializedObjectValue);
			            ead1[eadIndex] = elementValue;
		            	
			            eadIndex++;
		            }
		        }
		    }
			
		}
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			
			// Prepare SUITES_R
			suitesR = Util.buildSuitesR(cipherSuitesToOffer);
			
			byte[] connectionIdentifier = decodeIdentifier(cI);
			return processError(errorCode, Constants.EDHOC_MESSAGE_1, !isReq,
								connectionIdentifier, errMsg, suitesR, responseCode, ead1);
			
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
     * @param connectionIdInitiator   The already known connection identifier of the Initiator.
     * 								  It is set to null if expected in the EDHOC Message 2.
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
				
		// If EDHOC Message 2 is transported in a CoAP request, C_I is present as first element of the CBOR sequence
		if (error == false && isReq == true) {
			if (error == false && objectListRequest[index].getType() != CBORType.ByteString &&
				objectListRequest[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_I must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
			
			if (error == false) {
				CBORObject cI = objectListRequest[index];
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
					    Util.nicePrint("C_I", cI.EncodeToBytes());
					}
				}
			}
			
		}
		
		if (error == false && isReq == false) {
			connectionIdentifierInitiator = connectionIdInitiator;
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
		if (error == false && objectListRequest[index].getType() != CBORType.ByteString) {
				errMsg = new String("(G_Y | CIPHERTEXT_2) must be a byte string");
				responseCode = ResponseCode.BAD_REQUEST;
				error = true;
		}
		if (error == false) {
			gY_Ciphertext2 = objectListRequest[index].GetByteString();
			
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
		
		
		/* Return an EDHOC Error Message */
		
		if (error == true) {
			Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
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
        
        th2 = computeTH2(session, gYSerializedCBOR, cRSerializedCBOR, hashMessage1SerializedCBOR);
        if (th2 == null) {
        	errMsg = new String("Error when computing TH2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
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
								errMsg, null, responseCode, ead2);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("G_XY", dhSecret);
    	}
        
        // Compute PRK_2e
    	String hashAlgorithm = EdhocSession.getEdhocHashAlg(session.getSelectedCipherSuite());
    	
    	// prk2e = computePRK2e(dhSecret, hashAlgorithm);
    	prk2e = computePRK2e(th2, dhSecret, hashAlgorithm);    	
    	
    	dhSecret = null;
    	if (prk2e == null) {
        	errMsg = new String("Error when computing PRK_2e");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
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
								errMsg, null, responseCode, ead2);
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
    	int baseIndex = 0;
    	CBORObject[] plaintextElementList = null;
    	try {
    		plaintextElementList = CBORObject.DecodeSequenceFromBytes(plaintext2);
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
    	        
    	        int eadIndex = 0;
    	        
		        for (int i = index; i < objectListRequest.length; i++) {
		        	
		        	// The first element of each pair is an ead_label, and must be a CBOR integer with value different than 0
		            if ((eadIndex % 2) == 0) {
		            	if (objectListRequest[i].getType() != CBORType.Integer || objectListRequest[i].AsInt32() == 0) {
			                ead2 = null;
			                errMsg = new String("Malformed or invalid EAD_2");
			                responseCode = ResponseCode.BAD_REQUEST;
			                error = true;
			                break;
		            	}
		            	int eadLabel = objectListRequest[i].AsInt32();
		            	if (eadLabel < 0 && !session.getSupportedEADs().contains(Integer.valueOf(eadLabel))) {
	            			// Since the EAD item is critical and is not supported, discontinue the protocol
			                ead2 = null;
			                errMsg = new String("Unsupported EAD_2 critical item with ead_label " + eadLabel);
			                responseCode = ResponseCode.BAD_REQUEST;
			                error = true;
			                break;
		            	}
		            	
		            	// The ead_label is fine; move on to the ead_value
		            	eadIndex++;
		            	continue;
		            }
		            
		            // The second element of each pair is an ead_value, and must be a CBOR byte string
		            if ((eadIndex % 2) == 1) {
		            	if (objectListRequest[i].getType() != CBORType.ByteString) {
			                ead2 = null;
			                errMsg = new String("Malformed or invalid EAD_2");
			                responseCode = ResponseCode.BAD_REQUEST;
			                error = true;
			                break;
		            	}
		            	// Skip this EAD item as not supported and not critical
		            	if (!session.getSupportedEADs().contains(Integer.valueOf(eadIndex-1))) {
		            		eadIndex++;
		            		continue;
		            	}
		            	
		            	// This EAD item is supported, so it is kept for further processing
		            	
			            // Make a hard copy of ead_label
			            byte[] serializedObjectLabel = objectListRequest[i-1].EncodeToBytes();
			            CBORObject elementLabel = CBORObject.DecodeFromBytes(serializedObjectLabel);
			            ead2[eadIndex-1] = elementLabel;
			            
			            // Make a hard copy of ead_value
			            byte[] serializedObjectValue = objectListRequest[i].EncodeToBytes();
			            CBORObject elementValue = CBORObject.DecodeFromBytes(serializedObjectValue);
			            ead2[eadIndex] = elementValue;
		            	
			            eadIndex++;
		            }
		        }
    		}
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
    	}
    	
    	
    	// Verify that the identity of the Responder is an allowed identity
    	CBORObject idCredR = CBORObject.NewMap();
    	CBORObject rawIdCredR = plaintextElementList[0];
    	error = false;
    	
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
    		Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
    	}
    	
    	session.setPeerIdCred(idCredR);
    	OneKey peerKey = peerPublicKeys.get(idCredR);
    	session.setPeerLongTermPublicKey(peerKey);
    	
    	
    	// Compute PRK_3e2m
    	prk3e2m = computePRK3e2m(session, prk2e);
    	if (prk3e2m == null) {
        	errMsg = new String("Error when computing PRK_3e2m");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
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
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
    	}
    	byte[] peerCredential = peerCredentialCBOR.GetByteString(); // CRED_R
    	
    	session.setPeerCred(peerCredential); // Store CRED_R
    	
    	// Compute MAC_2
    	byte[] mac2 = computeMAC2(session, prk3e2m, th2, idCredR, peerCredential, ead2);
    	if (mac2 == null) {
        	errMsg = new String("Error when computing MAC_2");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
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
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to verify Signature_or_MAC_2", externalData);
    	}
    	
    	if (!verifySignatureOrMac2(session, signatureOrMac2, externalData, mac2)) {
        	errMsg = new String("Non valid Signature_or_MAC_2");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_2, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead2);
    	}
    	
    	/* End verifying Signature_or_MAC_2 */

    	// Store PLAINTEXT_2 for the later computation of TH_3
		session.setPlaintext2(plaintext2);
    	
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
     * @param connectionIdResponder   The already known connection identifier of the Responder.
     * 								  It is set to null if expected in the EDHOC Message 3.
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
		
		// If EDHOC Message 3 is transported in a CoAP request, C_R is present as first element of the CBOR sequence
		if (error == false && isReq == true) {
			if (error == false && objectListRequest[index].getType() != CBORType.ByteString &&
				objectListRequest[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_R must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}
		    if (error == false) {
		        connectionIdentifierResponder = decodeIdentifier(objectListRequest[index]);
		        if (connectionIdentifierResponder == null) {
		            errMsg = new String("Invalid encoding of C_R");
		            responseCode = ResponseCode.BAD_REQUEST;
		            error = true;
		        }
		        else
		            index++;
		    }

		}
		
		if (error == false && isReq == false) {
			connectionIdentifierResponder = connectionIdResponder;
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
			Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode, ead3);
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
								errMsg, null, responseCode, ead3);
        }
        else if (debugPrint) {
    		Util.nicePrint("TH_3", th3);
    	}
        session.setTH3(th3);
		
		
    	// Compute K_3 and IV_3 to protect the outer COSE object
    	byte[] k3 = computeKey(Constants.EDHOC_K_3, session);
    	if (k3 == null) {
        	errMsg = new String("Error when computing TH3");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode, ead3);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("K_3", k3);
    	}
    	
    	byte[] iv3 = computeIV(Constants.EDHOC_IV_3, session);
    	if (iv3 == null) {
        	errMsg = new String("Error when computing IV_3ae");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode, ead3);
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
								errMsg, null, responseCode, ead3);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("Plaintext retrieved from CIPHERTEXT_3", plaintext3);
    	}
    	
    	error = false;
    	
    	// Parse the outer plaintext as a CBOR sequence
    	int baseIndex = 0;
    	CBORObject[] plaintextElementList = null;
    	try {
    		plaintextElementList = CBORObject.DecodeSequenceFromBytes(plaintext3);
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
    	        
    	        int eadIndex = 0;
    	        
		        for (int i = index; i < objectListRequest.length; i++) {
		        	
		        	// The first element of each pair is an ead_label, and must be a CBOR integer with value different than 0
		            if ((eadIndex % 2) == 0) {
		            	if (objectListRequest[i].getType() != CBORType.Integer || objectListRequest[i].AsInt32() == 0) {
			                ead3 = null;
			                errMsg = new String("Malformed or invalid EAD_3");
			                responseCode = ResponseCode.BAD_REQUEST;
			                error = true;
			                break;
		            	}
		            	int eadLabel = objectListRequest[i].AsInt32();
		            	if (eadLabel < 0 && !session.getSupportedEADs().contains(Integer.valueOf(eadLabel))) {
	            			// Since the EAD item is critical and is not supported, discontinue the protocol
			                ead3 = null;
			                errMsg = new String("Unsupported EAD_3 critical item with ead_label " + eadLabel);
			                responseCode = ResponseCode.BAD_REQUEST;
			                error = true;
			                break;
		            	}
		            	
		            	// The ead_label is fine; move on to the ead_value
		            	eadIndex++;
		            	continue;
		            }
		            
		            // The second element of each pair is an ead_value, and must be a CBOR byte string
		            if ((eadIndex % 2) == 1) {
		            	if (objectListRequest[i].getType() != CBORType.ByteString) {
			                ead3 = null;
			                errMsg = new String("Malformed or invalid EAD_3");
			                responseCode = ResponseCode.BAD_REQUEST;
			                error = true;
			                break;
		            	}
		            	// Skip this EAD item as not supported and not critical
		            	if (!session.getSupportedEADs().contains(Integer.valueOf(eadIndex-1))) {
		            		eadIndex++;
		            		continue;
		            	}
		            	
		            	// This EAD item is supported, so it is kept for further processing
		            	
			            // Make a hard copy of ead_label
			            byte[] serializedObjectLabel = objectListRequest[i-1].EncodeToBytes();
			            CBORObject elementLabel = CBORObject.DecodeFromBytes(serializedObjectLabel);
			            ead3[eadIndex-1] = elementLabel;
			            
			            // Make a hard copy of ead_value
			            byte[] serializedObjectValue = objectListRequest[i].EncodeToBytes();
			            CBORObject elementValue = CBORObject.DecodeFromBytes(serializedObjectValue);
			            ead3[eadIndex] = elementValue;
		            	
			            eadIndex++;
		            }
		        }
    	    }
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode, ead3);
    	}
    	
    	// Verify that the identity of the Initiator is an allowed identity
    	CBORObject idCredI = CBORObject.NewMap();
    	CBORObject rawIdCredI = plaintextElementList[0];
    	error = false;
    	
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
    	if (error == false && !peerPublicKeys.containsKey(idCredI)) {
    	    errMsg = new String("The identity expressed by ID_CRED_I is not recognized");
    	    responseCode = ResponseCode.BAD_REQUEST;
    	    error = true;
    	}
    	
    	if (error == true) {
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator, errMsg, null, responseCode, ead3);
    	}
    	
    	session.setPeerIdCred(idCredI);
    	OneKey peerKey = peerPublicKeys.get(idCredI);
    	session.setPeerLongTermPublicKey(peerKey);

    	CBORObject peerCredentialCBOR = peerCredentials.get(idCredI);
    	if (peerCredentialCBOR == null) {
        	errMsg = new String("Unable to retrieve the peer credential");
        	responseCode = ResponseCode.BAD_REQUEST;
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
    		return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
    							errMsg, null, responseCode, ead3);
    	}
    	byte[] peerCredential = peerCredentialCBOR.GetByteString(); // CRED_I
    	
        // Compute the key material
        byte[] prk4e3m = computePRK4e3m(session);
    	if (prk4e3m == null) {
    		errMsg = new String("Error when computing PRK_4e3m");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode, ead3);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("PRK_4e3m", prk4e3m);
    	}
    	session.setPRK4e3m(prk4e3m);

    	
    	/* Start verifying Signature_or_MAC_3 */

    	// Compute MAC_3
    	byte[] mac3 = computeMAC3(session, prk4e3m, th3, idCredI, peerCredential, ead3);
    	if (mac3 == null) {
    		errMsg = new String("Error when computing MAC_3");
    		responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode, ead3);
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
    		Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
    		return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
    							errMsg, null, responseCode, ead3);
    	}
    	else if (debugPrint) {
    		Util.nicePrint("External Data to verify Signature_or_MAC_3", externalData);
    	}
    	
    	if (!verifySignatureOrMac3(session, signatureOrMac3, externalData, mac3)) {
        	errMsg = new String("Non valid Signature_or_MAC_3");
        	responseCode = ResponseCode.BAD_REQUEST;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
								errMsg, null, responseCode, ead3);
    	}
    	
    	/* End verifying Signature_or_MAC_3 */
    	
    	
    	/* Compute TH4 */
    	
        byte[] th3SerializedCBOR = CBORObject.FromObject(th3).EncodeToBytes();
        
    	byte[] th4 = computeTH4(session, th3SerializedCBOR, plaintext3, peerCredential);
    	
        if (th4 == null) {
        	errMsg = new String("Error when computing TH_4");
        	responseCode = ResponseCode.INTERNAL_SERVER_ERROR;
        	Util.purgeSession(session, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
        	return processError(errorCode, Constants.EDHOC_MESSAGE_3, !isReq, connectionIdentifierInitiator,
        						errMsg, null, responseCode, ead3);
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
		
		// If EDHOC Message 4 is transported in a CoAP request, C_I is present as first element of the CBOR sequence
		if (error == false && isReq == true) {
			if (error == false && objectListRequest[index].getType() != CBORType.ByteString &&
				objectListRequest[index].getType() != CBORType.Integer)  {
					errMsg = new String("C_I must be a byte string or an integer");
					responseCode = ResponseCode.BAD_REQUEST;
					error = true;
			}

			if (error == false) {
				connectionIdentifierInitiator = decodeIdentifier(objectListRequest[index]);
				if (connectionIdentifierInitiator == null) {
				    errMsg = new String("Invalid encoding of C_I");
				    responseCode = ResponseCode.BAD_REQUEST;
				    error = true;
				}
				else
					index++;
			}
			
		}
		
		if (error == false && isReq == false) {
			connectionIdentifierInitiator = connectionIdInitiator;
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
			Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_4, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, null);
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
    	    					errMsg, null, responseCode, null);
    	}
    	else if (debugPrint) {
    	    Util.nicePrint("Plaintext retrieved from CIPHERTEXT_4", plaintext4);
    	}
    	
        /* End computing the plaintext */
    	
    	
    	// Parse the outer plaintext as a CBOR sequence. To be valid, this is either the empty plaintext,
    	// or padding, or padding followed by the External Authorization Data EAD_4 possibly 
    	error = false;
    	int baseIndex = 0;
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
        	        
        	        int eadIndex = 0;
        	        
    		        for (int i = index; i < objectListRequest.length; i++) {
    		        	
    		        	// The first element of each pair is an ead_label, and must be a CBOR integer with value different than 0
    		            if ((eadIndex % 2) == 0) {
    		            	if (objectListRequest[i].getType() != CBORType.Integer || objectListRequest[i].AsInt32() == 0) {
    			                ead4 = null;
    			                errMsg = new String("Malformed or invalid EAD_4");
    			                responseCode = ResponseCode.BAD_REQUEST;
    			                error = true;
    			                break;
    		            	}
    		            	int eadLabel = objectListRequest[i].AsInt32();
    		            	if (eadLabel < 0 && !session.getSupportedEADs().contains(Integer.valueOf(eadLabel))) {
    	            			// Since the EAD item is critical and is not supported, discontinue the protocol
    			                ead4 = null;
    			                errMsg = new String("Unsupported EAD_4 critical item with ead_label " + eadLabel);
    			                responseCode = ResponseCode.BAD_REQUEST;
    			                error = true;
    			                break;
    		            	}
    		            	
    		            	// The ead_label is fine; move on to the ead_value
    		            	eadIndex++;
    		            	continue;
    		            }
    		            
    		            // The second element of each pair is an ead_value, and must be a CBOR byte string
    		            if ((eadIndex % 2) == 1) {
    		            	if (objectListRequest[i].getType() != CBORType.ByteString) {
    			                ead4 = null;
    			                errMsg = new String("Malformed or invalid EAD_4");
    			                responseCode = ResponseCode.BAD_REQUEST;
    			                error = true;
    			                break;
    		            	}
    		            	// Skip this EAD item as not supported and not critical
    		            	if (!session.getSupportedEADs().contains(Integer.valueOf(eadIndex-1))) {
    		            		eadIndex++;
    		            		continue;
    		            	}
    		            	
    		            	// This EAD item is supported, so it is kept for further processing
    		            	
    			            // Make a hard copy of ead_label
    			            byte[] serializedObjectLabel = objectListRequest[i-1].EncodeToBytes();
    			            CBORObject elementLabel = CBORObject.DecodeFromBytes(serializedObjectLabel);
    			            ead4[eadIndex-1] = elementLabel;
    			            
    			            // Make a hard copy of ead_value
    			            byte[] serializedObjectValue = objectListRequest[i].EncodeToBytes();
    			            CBORObject elementValue = CBORObject.DecodeFromBytes(serializedObjectValue);
    			            ead4[eadIndex] = elementValue;
    		            	
    			            eadIndex++;
    		            }
    		        }
        	    }
        	}
    		
    	}
    	
    	// Return an EDHOC Error Message
    	if (error == true) {
        	Util.purgeSession(session, connectionIdentifierInitiator, edhocSessions, usedConnectionIds);
			return processError(errorCode, Constants.EDHOC_MESSAGE_4, !isReq, connectionIdentifierResponder,
								errMsg, null, responseCode, ead4);
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
     * @param sequence   The CBOR sequence used as paylod of the EDHOC Error Message
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
					CBORObject connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
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
			// Do nothing
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
        List<Integer> supportedCipherSuites = session.getSupportedCipherSuites();
        List<Integer> peerSupportedCipherSuites = session.getPeerSupportedCipherSuites();
        
    	int selectedSuite = -1;
    	int preferredSuite = supportedCipherSuites.get(0).intValue();
    	
    	// No SUITES_R has been received, so it is not known what cipher suites the responder supports
    	if (peerSupportedCipherSuites == null) {
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
        
        // EAD_1, if provided
        if (ead1 != null) {
        	for (int i = 0; i < ead1.length; i++)
        		objectList.add(ead1[i]);
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
     * @param ead2   A CBOR array including the elements of the External Authorization Data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 2 or EDHOC Error Message; or null in case of errors
     */
	public static byte[] writeMessage2(EdhocSession session, CBORObject[] ead2) {
		
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
        byte[] cRSerializedCBOR = cR.EncodeToBytes();
        
        byte[] th2 = computeTH2(session, gYSerializedCBOR, cRSerializedCBOR, hashMessage1SerializedCBOR);
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
    	
        
    	/* Start computing Signature_or_MAC_2 */    	
    	
        byte[] mac2 = null;
        byte[] externalData = null;
        
    	// Compute MAC_2
        if (error == false) {
	    	mac2 = computeMAC2(session, prk3e2m, th2, session.getIdCred(), session.getCred(), ead2);
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
	    	
	    	// The outer CBOR sequence finishes with the connection identifier C_R
	    	objectList.add(cR);
        }

    	
		/* Prepare an EDHOC Error Message */
		
		if (error == true) {
			byte[] connectionIdentifierInitiator = session.getPeerConnectionId();
			
			List<CBORObject> processingResult = processError(errorCode, Constants.EDHOC_MESSAGE_1,
															 !session.isClientInitiated(),
															 connectionIdentifierInitiator,
															 errMsg, null, responseCode, null);
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
     * @param ead3   A CBOR array including the elements of the External Authorization Data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 3 or EDHOC Error Message; or null in case of errors
     */
	public static byte[] writeMessage3(EdhocSession session, CBORObject[] ead3) {
		
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
    	    												 errMsg, null, responseCode, null);
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
     * @param ead4   A CBOR array including the elements of the External Authorization Data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 4 or EDHOC Error Message; or null in case of errors
     */
	public static byte[] writeMessage4(EdhocSession session, CBORObject[] ead4) {
		
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
    	    												 errMsg, null, responseCode, null);
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
     * @param ead   The external authorization data from the latest incoming message, it can be null
     * @return  A list of CBOR objects, including the EDHOC Error Message and the CoAP response code to use
     */
	public static List<CBORObject> processError(int errorCode, int replyTo, boolean isErrorReq, byte[] connectionIdentifier,
			                                    String errMsg, CBORObject suitesR, ResponseCode responseCode,
			                                    CBORObject[] ead) {
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		byte[] replyPayload = writeErrorMessage(errorCode, replyTo, isErrorReq, connectionIdentifier, errMsg, suitesR);
		
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
     * @param keyPairs   The key pairs of the Initiator (one per supported curve)
     * @param idCreds   The identifiers of the authentication credentials of the Initiator
     * @param creds    The authentication credentials of the Initiator (one per supported curve),
     *                 as the serialization of a CBOR object
     * @param supportedCipherSuites   The list of cipher suites supported by the Initiator
     * @param supportedEADs   The set of EAD items supported by the Responder
     * @param usedConnectionIds   The set of allocated Connection Identifiers for the Initiator.
     *                            Each identifier is wrapped in a CBOR byte string.
     * @param appProfile   The application profile used for this session
     * @param epd   The processor of External Authentication Data used for this session
     * @param db   The database of OSCORE Security Contexts
     * @return  The newly created EDHOC session
     */
	public static EdhocSession createSessionAsInitiator(int method, HashMap<Integer, HashMap<Integer, OneKey>> keyPairs,
														HashMap<Integer, HashMap<Integer, CBORObject>> idCreds,
														HashMap<Integer, HashMap<Integer, CBORObject>> creds,
			  									        List<Integer> supportedCipherSuites,
			  									        Set<Integer> supportedEADs,
			  									        Set<CBORObject> usedConnectionIds,
			  									        AppProfile appProfile, EDP edp, HashMapCtxDB db) {
		
		byte[] connectionId = null;
		HashMapCtxDB oscoreDB = (appProfile.getUsedForOSCORE() == true) ? db : null;
		
		connectionId = Util.getConnectionId(usedConnectionIds, oscoreDB, null);
		// Forced for testing
		// connectionId = new byte[] {(byte) 0x1c};
		
        EdhocSession mySession = new EdhocSession(true, true, method, connectionId, keyPairs, idCreds, creds,
        										  supportedCipherSuites, supportedEADs, appProfile, edp, oscoreDB);
		
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
     * @param epd   The processor of External Authentication Data used for this session
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
			  									        AppProfile appProfile, EDP edp, HashMapCtxDB db) {
		
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
		
		EdhocSession mySession = new EdhocSession(false, isReq, method, connectionIdentifierResponder, keyPairs, idCreds, creds,
												  supportedCipherSuites, supportedEADs, appProfile, edp, oscoreDB);
		
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
		
		// Build the CBOR sequence to use for 'context': ( ID_CRED_R, TH_2, CRED_R, ? EAD_2 )
		// The actual 'context' is a CBOR byte string with value the serialization of the CBOR sequence
        List<CBORObject> objectList = new ArrayList<>();
    	objectList.add(idCredR);
    	objectList.add(CBORObject.FromObject(th2));
    	objectList.add(CBORObject.DecodeFromBytes(credR));
    	
    	if (ead2 != null) {
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
    	
    	if (ead3 != null) {
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
    		return Arrays.equals(signatureOrMac2, mac2);
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
    		return Arrays.equals(signatureOrMac3, mac3);
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
     * @param cR   The C_R connection identifier from the EDHOC Message 2, as a serialized CBOR Object
     * @param hashMessage1   The hash of EDHOC Message 1, as a serialized CBOR byte string
     * @return  The computed TH2
     */
	public static byte[] computeTH2(EdhocSession session, byte[] gY, byte[] cR, byte[] hashMessage1) {
	
        byte[] th2 = null;
        
        int selectedCipherSuite = session.getSelectedCipherSuite();
        String hashAlgorithm = EdhocSession.getEdhocHashAlg(selectedCipherSuite);

        int offset = 0;
        byte[] hashInput = new byte[gY.length + cR.length + hashMessage1.length];
        System.arraycopy(gY, 0, hashInput, offset, gY.length);
        offset += gY.length;
        System.arraycopy(cR, 0, hashInput, offset, cR.length);
        offset += cR.length;
        System.arraycopy(hashMessage1, 0, hashInput, offset, hashMessage1.length);
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
	
}