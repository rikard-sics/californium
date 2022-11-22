package org.eclipse.californium.edhoc;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/*
 * During the EDHOC execution, the side processor object temporarily
 * takes over the processing of incoming messages in order to:
 *     i) validate authentication credential of other peers; and
 *    ii) process EAD items, which can play a role in the previous point.
 * 
 * Due to early pre-parsing of the EAD field, the side processor object
 * can receive only EAD items that this peers supports
 */

public class SideProcessor {
	
	// The trust model used to validate authentication credentials of other peers
    private int trustModel;
    
	// Authentication credentials of other peers
	// 
	// The map label is a CBOR Map used as ID_CRED_X
	// The map value is a CBOR Byte String, with value the serialization of CRED_X
	private HashMap<CBORObject, CBORObject> peerCredentials = new HashMap<CBORObject, CBORObject>();
	
	// The EDHOC session this side process object is tied to
	private EdhocSession session;


	// EAD labels of existing EAD items that can be specified in EAD_1
	private static Set<Integer> existingEAD1 = new HashSet<>();
	
	// EAD labels of existing EAD items that can be specified in EAD_2 and have to be processed before message verification
	private static Set<Integer> existingEAD2Pre = new HashSet<>();
	
	// EAD labels of existing EAD items that can be specified in EAD_2 and have to be processed after message verification
	private static Set<Integer> existingEAD2Post = new HashSet<>();
	
	// EAD labels of existing EAD items that can be specified in EAD_3 and have to be processed before message verification
	private static Set<Integer> existingEAD3Pre = new HashSet<>();
	
	// EAD labels of existing EAD items that can be specified in EAD_3 and have to be processed after message verification
	private static Set<Integer> existingEAD3Post = new HashSet<>();

	// EAD labels of existing EAD items that can be specified in EAD_4
	private static Set<Integer> existingEAD4 = new HashSet<>();
	
	// The following maps are used to collect the results from the side processing of each incoming EDHOC message
	//
	// The label of the outer map uniquely determines the namespace of labels and corresponding values for the inner map.
	//
	// The label of the outer map is equal to the ead_label of the EAD item the results refer to,
	// with the following exceptions:
	//
	// - The outer map includes an entry with label 0, with information about the authentication credential of the other peer to use.
	// - The outer map includes an entry with label -1, in case the overall side processing fails.
	//
	private HashMap<Integer, HashMap<Integer, CBORObject>> resultFromMessage1 = new HashMap<Integer, HashMap<Integer, CBORObject>>();
	private HashMap<Integer, HashMap<Integer, CBORObject>> resultFromMessage2 = new HashMap<Integer, HashMap<Integer, CBORObject>>();
	private HashMap<Integer, HashMap<Integer, CBORObject>> resultFromMessage3 = new HashMap<Integer, HashMap<Integer, CBORObject>>();
	private HashMap<Integer, HashMap<Integer, CBORObject>> resultFromMessage4 = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
	public SideProcessor(int trustModel, HashMap<CBORObject, CBORObject> peerCredentials, EdhocSession session) {

		this.trustModel = trustModel;
		this.peerCredentials = peerCredentials;
		
		this.session = session; // On the Responder, this starts as null and is set later on before starting to prepare message_2
		if (session != null)
			session.setSideProcessor(this);
		
		populateSetsOfExistingEAD();
	}
			
	public HashMap<Integer, HashMap<Integer, CBORObject>> getResults(int messageNumber) {
		HashMap<Integer, HashMap<Integer, CBORObject>> myMap = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		switch(messageNumber) {
			case Constants.EDHOC_MESSAGE_1:
				myMap = resultFromMessage1;
				break;
			case Constants.EDHOC_MESSAGE_2:
				myMap = resultFromMessage2;
				break;
			case Constants.EDHOC_MESSAGE_3:
				myMap = resultFromMessage3;
				break;
			case Constants.EDHOC_MESSAGE_4:
				myMap = resultFromMessage4;
				break;
		}
		return myMap;
	}
	
	public void removeEntryFromResultMap(int messageNumber, int keyValue) {
		HashMap<Integer, HashMap<Integer, CBORObject>> myMap = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		switch(messageNumber) {
			case Constants.EDHOC_MESSAGE_1:
				myMap = resultFromMessage1;
				break;
			case Constants.EDHOC_MESSAGE_2:
				myMap = resultFromMessage2;
				break;
			case Constants.EDHOC_MESSAGE_3:
				myMap = resultFromMessage3;
				break;
			case Constants.EDHOC_MESSAGE_4:
				myMap = resultFromMessage4;
				break;
		}
		if (myMap.size() == 0)
			return;
		myMap.remove(Integer.valueOf(keyValue));
	}
	
	public void setEdhocSession(EdhocSession session) {
		if (session != null) {
			this.session = session;
		}
		
		if (this.session != null) {
			this.session.setSideProcessor(this);
			
			if (session == null) {
				this.session = null;
			}
		}
	}
	
	// elements1 includes useful pieces information for processing EAD_1
	//
	// ead1 includes the actual EAD items from EAD_1
	public void sideProcessingMessage1(CBORObject[] elements1, CBORObject[] ead1) {
		// Go through the EAD items, if any		
	}

	// elements2 includes useful pieces information for processing EAD_2, in this order:
	// 0) A CBOR byte string, with value G_Y
	// 1) A CBOR byte string, with value C_R (in its original, binary format)
	// 2) A CBOR map, as ID_CRED_R 
	//
	// ead2 includes the actual EAD items from EAD_2
	public void sideProcessingMessage2PreVerification(CBORObject[] elements2, CBORObject[] ead2) {
				
		CBORObject gY = elements2[0];
		CBORObject connectionIdentifierResponder = elements2[1];
		CBORObject idCredR = elements2[2];
		
		CBORObject peerCredentialCBOR = findValidPeerCredential(idCredR, ead2);
		
		if (peerCredentialCBOR == null) {
			addErrorEntry("Unable to retrieve a valid peer credential from ID_CRED_R", ResponseCode.BAD_REQUEST.value);
			return;
    	}
		else {
			HashMap<Integer, CBORObject> myMap = new HashMap<Integer, CBORObject>();
			myMap.put(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_CRED_VALUE), peerCredentialCBOR);
			resultFromMessage2.put(Constants.SIDE_PROCESSOR_OUTER_CRED, myMap);
		}
		
		// Go through the EAD items, if any
	}

	// elements2 includes useful pieces information for processing EAD_2, in this order:
	// 0) A CBOR byte string, with value G_Y
	// 1) A CBOR byte string, with value C_R (in its original, binary format)
	// 2) A CBOR map, as ID_CRED_R 
	//
	// ead2 includes the actual EAD items from EAD_2
	public void sideProcessingMessage2PostVerification(CBORObject[] elements2, CBORObject[] ead2) {
		CBORObject gY = elements2[0];
		CBORObject connectionIdentifierResponder = elements2[1];
		CBORObject idCredR = elements2[2];
		
		// Go through the EAD items, if any		
	}

	// elements3 includes useful pieces information for processing EAD_3
	//
	// ead3 includes the actual EAD items from EAD_3
	public void sideProcessingMessage3PreVerification(CBORObject[] elements3, CBORObject[] ead3) {
		// Go through the EAD items, if any		
	}

	// elements3 includes useful pieces information for processing EAD_3
	//
	// ead3 includes the actual EAD items from EAD_3
	public void sideProcessingMessage3PostVerification(CBORObject[] elements3, CBORObject[] ead3) {
		// Go through the EAD items, if any		
	}
	
	// elements4 includes useful pieces information for processing EAD_4
	//
	// ead4 includes the actual EAD items from EAD_4
	public void sideProcessingMessage4(CBORObject[] ead4) {
		// Go through the EAD items, if any		
	}
	
	public void showResultsFromProcessingEAD(int messageNumber) {
		HashMap<Integer, HashMap<Integer, CBORObject>> myMap = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		switch(messageNumber) {
			case Constants.EDHOC_MESSAGE_1:
				myMap = resultFromMessage1;
				break;
			case Constants.EDHOC_MESSAGE_2:
				myMap = resultFromMessage2;
				break;
			case Constants.EDHOC_MESSAGE_3:
				myMap = resultFromMessage3;
				break;
			case Constants.EDHOC_MESSAGE_4:
				myMap = resultFromMessage4;
				break;
		}
		if (myMap.size() == 0)
			return;
		
		for (Integer i : myMap.keySet()) {
			System.out.println("Processing result for the EAD item with ead_label: " + i.intValue());
			
			for (Integer j : myMap.get(i).keySet()) {
				CBORObject obj = myMap.get(i).get(j);
				System.out.print("Result element #" + j.intValue() + ": " + obj.toString());				
			}
			System.out.println("\n");
		}
		
	}
	
	private CBORObject findValidPeerCredential(CBORObject idCredX, CBORObject[] ead) {
		CBORObject peerCredentialCBOR = null;
		
		if (trustModel == Constants.TRUST_MODEL_STRICT) {
			if (!peerCredentials.containsKey(idCredX)) {
				return null;
			}
		}
		
    	peerCredentialCBOR = peerCredentials.get(idCredX);    	
    			
		return peerCredentialCBOR;
	}
	
	private void addErrorEntry(String errorMessage, int responseCode) {
		HashMap<Integer, CBORObject> errorMap = new HashMap<Integer, CBORObject>();
		
		errorMap.put(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION),
				 CBORObject.FromObject(errorMessage));
		errorMap.put(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE),
			 CBORObject.FromObject(responseCode));
		resultFromMessage2.put(Constants.SIDE_PROCESSOR_OUTER_ERROR, errorMap);
	}
	
	public void populateSetsOfExistingEAD() {
		// Fill the corresponding sets as EAD items as they are defined and registered
	}
	
}