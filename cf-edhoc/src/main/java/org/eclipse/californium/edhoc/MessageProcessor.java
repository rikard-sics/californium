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
import java.util.Set;

import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.Utils;
import sun.security.rsa.RSAUtil.KeyType;

public class MessageProcessor {
	
	private static final boolean debugPrint = true;
	
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
     * @param ltk   The long term identity key
     * @param usedConnectionIds   The collection of Connection Identifiers used by this peer
     * @param supportedCipherSuites   The list of cipher suites supported by this peer 
     * @param edhocSessions   The EDHOC sessions of this peer 
     *                        The map label is C_X, i.e. the connection identifier
     *                        offered to the other peer in the session, as a bstr_identifier
     * @return   A list of CBOR Objects including up to two elements.
     *           The first element is always present. It it is a CBOR byte string, with value either:
     *           i) a zero length byte string, indicating that the EDHOC Message 2 can be prepared; or
     *           ii) a non-zero length byte string as the EDHOC Error Message to be sent.
     *           The second element is optional. If present, it is a CBOR byte string, with value
     *           the application data AD1 to deliver to the application.
     */
	public static List<CBORObject> readMessage1(byte[] sequence,
												OneKey ltk,
												List<Set<Integer>> usedConnectionIds,
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

			// The EDHOC Error Message, as a CBOR sequence
			responsePayload = Util.buildCBORSequence(objectListResponse);
			processingResult.add(CBORObject.FromObject(responsePayload));
			
			// Application Data from AD_1 (if present), as a CBOR byte string
			if (hasApplicationData == true) {
				processingResult.add(objectListRequest[4]);
			}
			
			System.out.println("Completed preparation of EDHOC Error Message");
			return processingResult;
			
		}
		
		
		/* Return an indication to prepare EDHOC Message 2, possibly with the provided Application Data */
		
		// A CBOR byte string wihth zero length, indicating that the EDHOC Message 2 can be prepared
		processingResult.add(CBORObject.FromObject(responsePayload));
		
		// Application Data from AD_1 (if present), as a CBOR byte string
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
		
        // Prepare the list of CBOR objects to build the CBOR sequence
        List<CBORObject> objectList = new ArrayList<>();
        
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
    		// Pick the selected ciphersuited as the most preferred by the initiator from the ones supported by the responder
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
        
        // AD_1 as a CBOR byte string (if provided)
        if (ad1 != null) {
        	objectList.add(CBORObject.FromObject(ad1));
        }
        if (debugPrint) {
        	System.out.println("===================================");
        }
		
        return Util.buildCBORSequence(objectList);
		
	}
	
	
    /**
     *  Prepare an EDHOC Message 2
     * @param session   The EDHOC session associated to this EDHOC message
     * @param ad2   The auxiliary data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 2, or null in case of errors
     */
	public static byte[] writeMessage2(EdhocSession session, byte[] ad2) {
		
		
		
		return null;
		
	}
	
}