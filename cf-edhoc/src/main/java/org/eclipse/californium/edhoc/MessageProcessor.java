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
import java.util.List;
import java.util.Map;
import java.util.Set;

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
		boolean hasApplicationData = false; // Will be set to True if Application Data is present as AD1
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>(); // List of CBOR Objects to return as result
		
		// Serialization of the response to be sent back to the client
		byte[] responsePayload = new byte[] {};
		
		boolean error = false; // Will be set to True if an EDHOC Error Message has to be returned
		String errMsg = null; // The text string to be possibly returned as ERR_MSG in an EDHOC Error Message
		int correlation = -1; // The correlation method indicated by METHOD_CORR, or left to -1 in case on invalid message
		CBORObject cI = null; // The Connection Identifier C_I, or left to null in case of invalid message
		CBORObject suitesR = null; // The SUITE_R element to be possibly returned as SUITES_R in an EDHOC Error Message
		

		CBORObject[] objectListRequest = CBORObject.DecodeSequenceFromBytes(sequence);
		
		/* Consistency checks */
		
		// METHOD_CORR
		if (objectListRequest[0].getType() != CBORType.Integer) {
			errMsg = new String("METHOD_CORR must be an integer");
			error = true;
		}
		else {
			correlation = objectListRequest[0].AsInt32() % 4; 
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
		else {
			cI = objectListRequest[3];
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
			
			responsePayload = writeErrorMessage(Constants.EDHOC_MESSAGE_1, correlation, cI, errMsg, suitesR);
			processingResult.add(CBORObject.FromObject(responsePayload));
			
			// Application Data from AD_1 (if present), as a CBOR byte string
			if (hasApplicationData == true) {
				processingResult.add(objectListRequest[4]);
			}
			
			return processingResult;
			
		}
		
		
		/* Return an indication to prepare EDHOC Message 2, possibly with the provided Application Data */
		
		// A CBOR byte string with zero length, indicating that the EDHOC Message 2 can be prepared
		processingResult.add(CBORObject.FromObject(responsePayload));
		
		// Application Data from AD_1 (if present), as a CBOR byte string
		if (hasApplicationData == true) {
			processingResult.add(objectListRequest[4]);
		}
		
		System.out.println("Completed processing of EDHOC Message 1");
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
     * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param cX   The connection identifier of the recipient; set to null if expected in the EDHOC Error Message
     * @param sequence   The CBOR sequence used as paylod of the EDHOC Error Message
     * @return  The elements of the EDHOC Error Message as CBOR objects, or null in case of errors
     */
	public static CBORObject[] readErrorMessage(Map<CBORObject, EdhocSession> edhocSessions, CBORObject cX, byte[] sequence) {
		
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
			mySession = edhocSessions.get(cX);
		}
		
		// The connection identifier is expected as first element in the EDHOC Error Message
		else {
			
			if (objectList[index].getType() == CBORType.ByteString) {
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
		int correlation = mySession.getCorrelation();
		
		if (initiator == true) {
			if (correlation != Constants.EDHOC_CORR_METHOD_0 && correlation != Constants.EDHOC_CORR_METHOD_2) {
				System.err.println("Error when processing EDHOC Error Message - Inconsistent correlation method");
				return null;
			}
		}
		else if (initiator == false) {
			if (correlation != Constants.EDHOC_CORR_METHOD_0 && correlation != Constants.EDHOC_CORR_METHOD_1) {
				System.err.println("Error when processing EDHOC Error Message - Inconsistent correlation method");
				return null;
			}
		}
		
		if (objectList[index].getType() != CBORType.TextString) {
			System.err.println("Error when processing EDHOC Error Message - Invalid format of ERR_MSG");
			return null;
		}
		
		index++;
		
		if (initiator == true && mySession.getCurrentStep() == Constants.EDHOC_AFTER_M1) {
			
			if (objectList.length == index){
				System.err.println("Error when processing EDHOC Error Message - SUITES_R expected but not included");
				return null;
			}
			
			if (objectList.length > (index + 1)){
				System.err.println("Error when processing EDHOC Error Message - Unexpected parameters following SUITES_R");
				return null;
			}
			
			if (objectList[index].getType() != CBORType.Array &&  objectList[index].getType() != CBORType.Integer) {
				System.err.println("Error when processing EDHOC Error Message - Invalid format for SUITES_R");
				return null;
			}
			
			if (objectList[index].getType() != CBORType.Array) {
				for (int i = 0; i < objectList[index].size(); i++) {
					if (objectList[index].get(i).getType() != CBORType.Integer) {
						System.err.println("Error when processing EDHOC Error Message - Invalid format for elements of SUITES_R");
						return null;
					}
				}
			}
			
		}
		else if (objectList.length != index){
			System.err.println("Error when processing EDHOC Error Message - SUITES_R included while not pertinent");
			return null;
		}
		
		return objectList;
		
	}
	
    /**
     *  Write an EDHOC Message 1
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
        
        // AD_1 as a CBOR byte string (if provided)
        if (ad1 != null) {
        	objectList.add(CBORObject.FromObject(ad1));
        }
        if (debugPrint) {
        	System.out.println("===================================");
        }
		
        // Mark the session as used - Possible reusage will trigger the generation of new ephemeral keys
        session.setAsUsed();
        
        return Util.buildCBORSequence(objectList);
		
	}

	
    /**
     *  Write an EDHOC Message 2
     * @param session   The EDHOC session associated to this EDHOC message
     * @param ad2   The auxiliary data, it can be null
     * @return  The raw payload to transmit as EDHOC Message 2, or null in case of errors
     */
	public static byte[] writeMessage2(EdhocSession session, byte[] ad2) {
		
		List<CBORObject> objectList = new ArrayList<>();
		
        if (debugPrint) {
        	System.out.println("===================================");
        	System.out.println("Start processing EDHOC Message 2:\n");
        }
		
        /* Start preparing data_2 */
        
		// C_I as a bstr_identifier
		int correlationMethod = session.getCorrelation();
		if (correlationMethod == Constants.EDHOC_CORR_METHOD_0 || correlationMethod == Constants.EDHOC_CORR_METHOD_2) {
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
        
        byte[] th2 = null;
        byte[] message1 = session.getMessage1(); // message_1 as a CBOR sequence
        byte[] data2 = Util.buildCBORSequence(objectList); // data_2 as a CBOR sequence
        byte[] hashInput = new byte[message1.length + data2.length];
        System.arraycopy(message1, 0, hashInput, 0, message1.length);
        System.arraycopy(data2, 0, hashInput, message1.length, data2.length);
        try {
			th2 = Util.computeHash(hashInput, "SHA-256");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Invalid hash algorithm when computing TH2\n" + e.getMessage());
			return null;
			
		}
        session.setTH2(th2);
    	if (debugPrint) {
    		Util.nicePrint("TH_2", th2);
    	}
        
        
        // Compute the external data for the external_aad, as a CBOR sequence
        
        List<CBORObject> externalDataList = new ArrayList<>();
        
        // TH2 is the first element of the CBOR Sequence
        byte[] th2SerializedCBOR = CBORObject.FromObject(th2).EncodeToBytes();
        externalDataList.add(CBORObject.FromObject(th2SerializedCBOR));
        
        // CRED_R is the second element of the CBOR Sequence
        OneKey identityKey = session.getLongTermKey();
        
        
        // TODO REMOVE
        //byte[] credISerializedCBOR = Util.buildCredRawPublicKey(identityKey, "");
        
        
        byte[] credISerializedCBOR = session.getCred();
        externalDataList.add(CBORObject.FromObject(credISerializedCBOR));
        
        // AD_2 is the third element of the CBOR Sequence (if provided)
        if (ad2 != null) {
            byte[] ad2SerializedCBOR = CBORObject.FromObject(ad2).EncodeToBytes();
            externalDataList.add(CBORObject.FromObject(ad2SerializedCBOR)); 
        }
      
        byte[] externalData = Util.concatenateByteArrays(externalDataList);
    	if (debugPrint) {
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
    	if (debugPrint) {
    		Util.nicePrint("G_XY", dhSecret);
    	}
        
        // Compute PRK_2e
        try {
			prk2e = Hkdf.extract(new byte[] {}, dhSecret);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating PRK_2e\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating PRK_2e\n" + e.getMessage());
			return null;
		}
        session.setPRK2e(prk2e);
    	if (debugPrint) {
    		Util.nicePrint("PRK_2e", prk2e);
    	}
        
        
        // Compute PRK_3e2m
        int authenticationMethod = session.getMethod();
        if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_2) {
        	// The responded uses signatures as authentication method, then PRK_3e2m is equal to PRK_2e 
        	prk3e2m = new byte[prk2e.length];
        	System.arraycopy(prk2e, 0, prk3e2m, 0, prk2e.length);
        	session.setPRK3e2m(prk3e2m);
        }
        else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_1 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_3) {
        		// The responder does not use signatures as authentication method, then PRK_3e2m has to be computed
            	byte[] dhSecret2;
            	OneKey ownKey = identityKey;
            	OneKey peerKey = session.getPeerEphemeralPublicKey();
            	if (identityKey.get(KeyKeys.OKP_Curve) == KeyKeys.OKP_Ed25519) {
                	// Convert the identity key from Edward to Montgomery form
                	try {
						ownKey = SharedSecretCalculation.convertEd25519ToCurve25519(identityKey);
					} catch (CoseException e) {
						System.err.println("Error when converting the Responder identity key" + 
								           "from Edward to Montgomery format\n" + e.getMessage());
						return null;
					}
            	}

        		dhSecret2 = SharedSecretCalculation.generateSharedSecret(ownKey, peerKey);
            	if (debugPrint) {
            		Util.nicePrint("G_RX", dhSecret2);
            	}
            	try {
					prk3e2m = Hkdf.extract(prk2e, dhSecret2);
				} catch (InvalidKeyException e) {
					System.err.println("Error when generating PRK_3e2m\n" + e.getMessage());
					return null;
				} catch (NoSuchAlgorithmException e) {
					System.err.println("Error when generating PRK_3e2m\n" + e.getMessage());
					return null;
				}
            	session.setPRK3e2m(prk3e2m);
    	}
    	if (debugPrint) {
    		Util.nicePrint("PRK_3e2m", prk3e2m);
    	}
        
        
    	// Compute K_2m and IV_2m to protect the inner COSE object
        
    	int keyLength = 0;
    	int ivLength = 0;
    	switch (selectedSuite) {
		case Constants.EDHOC_CIPHER_SUITE_0:
		case Constants.EDHOC_CIPHER_SUITE_1:
		case Constants.EDHOC_CIPHER_SUITE_2:
		case Constants.EDHOC_CIPHER_SUITE_3:
			keyLength = 16;
			ivLength = 13;
    	}
    	byte[] k2m = new byte[keyLength];
    	byte[] iv2m = new byte[ivLength];
    	try {
			k2m = session.edhocKDF(prk3e2m, th2, "K_2m", keyLength);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating K_2m\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating K_2m\n" + e.getMessage());
			return null;
		}
    	if (debugPrint) {
    		Util.nicePrint("K_2m", k2m);
    	}
    	try {
			iv2m = session.edhocKDF(prk3e2m, th2, "IV_2m", ivLength);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating K_2m\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating K_2m\n" + e.getMessage());
			return null;
		}
    	if (debugPrint) {
    		Util.nicePrint("IV_2m", iv2m);
    	}
    	
    	
    	// Encrypt the inner COSE object and take the ciphertext as MAC_2
    	
    	AlgorithmID alg = null;
    	byte[] mac2 = null;
    	switch (selectedSuite) {
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
			mac2 = Util.encrypt(session.getIdCred(), externalData, plaintext, alg, iv2m, k2m);
		} catch (CoseException e) {
			System.err.println("Error when computing MAC_2\n" + e.getMessage());
			return null;
		}
    	if (debugPrint) {
    		Util.nicePrint("MAC_2", mac2);
    	}
    	
    	
    	// Compute Signature_or_MAC_2
    	
    	byte[] signatureOrMac2 = null;
    	
    	if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_1 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_3) {
    		// The responded does not use signatures as authentication method, then Signature_or_MAC_2 is equal to MAC_2
    		signatureOrMac2 = new byte[mac2.length];
    		System.arraycopy(mac2, 0, signatureOrMac2, 0, mac2.length);
    	}
    	else if (authenticationMethod == Constants.EDHOC_AUTH_METHOD_0 || authenticationMethod == Constants.EDHOC_AUTH_METHOD_2) {
    		// The responded uses signatures as authentication method, then Signature_or_MAC_2 has to be computed
    		try {
				signatureOrMac2 = Util.computeSignature(session.getIdCred(), externalData, mac2, identityKey);
			} catch (CoseException e) {
				System.err.println("Error when signing MAC_2 to produce Signature_or_MAC_2\n" + e.getMessage());
				return null;
			}
    	}
    	if (debugPrint) {
    		Util.nicePrint("Signature_or_MAC_2", signatureOrMac2);
    	}
    	
        /* End computing the inner COSE object */
    
    	
    	// The following is as per v -02:   https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#section-4.5
    	// It's unclear how the initiator side should process EDHOC Message 2 when receiving it
    	
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
    	if (ad2 != null) {
        	plaintextElementList.add(CBORObject.FromObject(ad2));
    	}
    	plaintext = Util.buildCBORSequence(plaintextElementList);
    	if (debugPrint) {
    		Util.nicePrint("Plaintext to compute CIPHERTEXT_2", plaintext);
    	}
    	
    	
    	// Compute K_2e
    	
    	byte[] k2e = new byte[plaintext.length];
    	try {
			k2e = session.edhocKDF(prk2e, th2, "K_2e", plaintext.length);
		} catch (InvalidKeyException e) {
			System.err.println("Error when generating K_2e\n" + e.getMessage());
			return null;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating K_2e\n" + e.getMessage());
			return null;
		}
    	if (debugPrint) {
    		Util.nicePrint("K_2e", k2e);
    	}

    	
    	// Compute CIPHERTEXT_2 and add it to the outer CBOR sequence
    	
    	byte[] ciphertext2 = Util.arrayXor(plaintext, k2e);
    	objectList.add(CBORObject.FromObject(ciphertext2));
    	if (debugPrint) {
    		Util.nicePrint("CIPHERTEXT_2", ciphertext2);
    	}
    	        
    	/* End computing CIPHERTEXT_2 */
    	
    	if (debugPrint) {
    		Util.nicePrint("EDHOC Message 2", Util.buildCBORSequence(objectList));
    	}
        return Util.buildCBORSequence(objectList);
		
	}
	
    /**
     *  Write an EDHOC Error Message
     * @param replyTo   The message to which this EDHOC Error Message is intended to reply to
     * @param corr   The used correlation method
     * @param cX   The connection identifier of the recipient, it can be null
     * @param errMsg   The text string to include in the EDHOC Error Message
     * @param suitesR   The cipher suite(s) supported by the Responder (only in response to EDHOC Message 1), it can be null
     * @return  The raw payload to transmit as EDHOC Error Message, or null in case of errors
     */
	public static byte[] writeErrorMessage(int replyTo, int corr, CBORObject cX, String errMsg, CBORObject suitesR) {
		
		if (replyTo != Constants.EDHOC_MESSAGE_1 && replyTo != Constants.EDHOC_MESSAGE_2 &&
			replyTo != Constants.EDHOC_MESSAGE_3) {
				   return null;
		}
				
		if (errMsg == null)
			return null;

		if (suitesR.getType() != CBORType.Integer && suitesR.getType() != CBORType.Array)
			return null;
		
		List<CBORObject> objectList = new ArrayList<CBORObject>();
		boolean includeIdentifier = false;
		byte[] payload;
			
		// Possibly include C_X - This might not have been included if the incoming EDHOC message was malformed
		if (cX != null) {
			
			if (replyTo == Constants.EDHOC_MESSAGE_1 || replyTo == Constants.EDHOC_MESSAGE_3) {
				if (corr == Constants.EDHOC_CORR_METHOD_0 || corr == Constants.EDHOC_CORR_METHOD_2) {
					includeIdentifier = true;
				}
			}
			else if (replyTo != Constants.EDHOC_MESSAGE_2) {
				if (corr == Constants.EDHOC_CORR_METHOD_0 || corr == Constants.EDHOC_CORR_METHOD_1) {
					includeIdentifier = true;
				}
			}
		
			if (includeIdentifier == true) {
				
				objectList.add(CBORObject.FromObject(cX));
				
			}
			
		}

		
		// Include ERR_MSG
		objectList.add(CBORObject.FromObject(errMsg));
		

		// Possibly include SUITES_R - This implies that EDHOC Message 1 was good enough and yielding a suite negotiation
		if (replyTo == Constants.EDHOC_MESSAGE_1) {
			
			if (suitesR != null) {
				objectList.add(suitesR);
			}
			
		}
		
		
		// Encode the EDHOC Error Message, as a CBOR sequence
		payload = Util.buildCBORSequence(objectList);
		
		System.out.println("Completed preparation of EDHOC Error Message");
		return payload;
		
	}
	
    /**
     *  Create a new EDHOC session as an Initiator
     * @param authenticationMethod   The authentication method signaled by the Initiator
     * @param correlationMethod   The correlation method signaled by the Initiator
     * @param keyPair   The identity key of the Initiator
     * @param idCredI   ID_CRED_I for the identity key of the Initiator
     * @param credI   CRED_I for the identity key of the Initiator
     * @param subjectName   The subject name for the identity key of the Initiator
     * @param supportedCipherSuites   The list of ciphersuites supported by the Initiator
     * @param usedConnectionIds   The list of allocated Connection Identifiers for the Initiator
     * @return  The newly created EDHOC session
     */
	public static EdhocSession createSessionAsInitiator(int authenticationMethod, int correlationMethod,
												  OneKey keyPair, CBORObject idCredI, byte[] credI, String subjectName,
			  									  List<Integer> supportedCiphersuites, List<Set<Integer>> usedConnectionIds) {
		
		int methodCorr = (4 * authenticationMethod) + correlationMethod;
		byte[] connectionId = Util.getConnectionId(usedConnectionIds, null);
        EdhocSession mySession = new EdhocSession(true, methodCorr, connectionId, keyPair,
        										  idCredI, credI, supportedCiphersuites);
		
		return mySession;
		
	}
	
    /**
     *  Create a new EDHOC session as a Responder
     * @param message1   The payload of the received EDHOC Message 1
     * @param keyPair   The identity key of the Responder
     * @param idCredR   ID_CRED_R for the identity key of the Responder
     * @param supportedCipherSuites   The list of ciphersuites supported by the Responder
     * @param usedConnectionIds   The list of allocated Connection Identifiers for the Responder
     * @return  The newly created EDHOC session
     */
	public static EdhocSession createSessionAsResponder(byte[] message1, OneKey keyPair, CBORObject idCredR, byte[] credR,
			  									  List<Integer> supportedCiphersuites, List<Set<Integer>> usedConnectionIds) {
		
		CBORObject[] objectListMessage1 = CBORObject.DecodeSequenceFromBytes(message1);
		
		// Retrieve elements from EDHOC Message 1
		
		// METHOD_CORR
		int methodCorr = objectListMessage1[0].AsInt32();
		
		// Selected ciphersuites from SUITES_I
		int selectedCipherSuite = -1;
		if (objectListMessage1[1].getType() == CBORType.Integer)
			selectedCipherSuite = objectListMessage1[1].AsInt32();
		else if (objectListMessage1[1].getType() == CBORType.Array)
			selectedCipherSuite = objectListMessage1[1].get(0).AsInt32();
		
		// G_X
		byte[] gX = objectListMessage1[2].GetByteString();
		
		// C_I
		byte[] cI = Util.decodeFromBstrIdentifier(objectListMessage1[3]).GetByteString();
		
		// Create a new EDHOC session
		byte[] connectionId = Util.getConnectionId(usedConnectionIds, null);
		EdhocSession mySession = new EdhocSession(false, methodCorr, connectionId, keyPair,
												  idCredR, credR, supportedCiphersuites);
		
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
			// TODO Need a way to build a public-key-only OneKey object starting only from the received 'X' parameter
		}
		mySession.setPeerEphemeralPublicKey(peerEphemeralKey);
		
		// Store the EDHOC Message 1
		mySession.setMessage1(message1);
		
		return mySession;
		
	}
	
}