package org.eclipse.californium.edhoc;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

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
	// The label of the outer map is equal to the ead_label of the EAD item the results refer to.
	// In case the overall side processing fails, the outer map includes an entry with label 0.
	//
	// The label of the outer map uniquely determines the namespace of labels and corresponding values for the inner map.
	private HashMap<Integer, HashMap<Integer, CBORObject>> resultFromMessage1 = new HashMap<Integer, HashMap<Integer, CBORObject>>();
	private HashMap<Integer, HashMap<Integer, CBORObject>> resultFromMessage2 = new HashMap<Integer, HashMap<Integer, CBORObject>>();
	private HashMap<Integer, HashMap<Integer, CBORObject>> resultFromMessage3 = new HashMap<Integer, HashMap<Integer, CBORObject>>();
	private HashMap<Integer, HashMap<Integer, CBORObject>> resultFromMessage4 = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		
	public SideProcessor(int trustModel, HashMap<CBORObject, CBORObject> peerCredentials, EdhocSession session) {

		this.trustModel = trustModel;
		this.peerCredentials = peerCredentials;
		this.session = session;
		
		populateSetsOfExistingEAD();
	}
			
	public HashMap<Integer, HashMap<Integer, CBORObject>> getResultFromMessage1() {
		return resultFromMessage1;
	}
	
	public HashMap<Integer, HashMap<Integer, CBORObject>> getResultFromMessage2() {
		return resultFromMessage2;
	}
	
	public HashMap<Integer, HashMap<Integer, CBORObject>> getResultFromMessage3() {
		return resultFromMessage3;
	}
	
	public HashMap<Integer, HashMap<Integer, CBORObject>> getResultFromMessage4() {
		return resultFromMessage4;
	}
	
	public void setEdhocSession(EdhocSession session) {
		this.session = session;
	}
	
	public void sideProcessingMessage1(CBORObject[] elements1, CBORObject[] ead1) {
		// Go through the EAD items, if any		
	}

	public void sideProcessingMessage2PreVerification(CBORObject[] elements2, CBORObject[] ead2) {
		// Go through the EAD items, if any		
	}

	public void sideProcessingMessage2PostVerification(CBORObject[] elements2, CBORObject[] ead2) {
		// Go through the EAD items, if any		
	}
	
	public void sideProcessingMessage3PreVerification(CBORObject[] elements3, CBORObject[] ead3) {
		// Go through the EAD items, if any		
	}

	public void sideProcessingMessage3PostVerification(CBORObject[] elements3, CBORObject[] ead3) {
		// Go through the EAD items, if any		
	}
	
	public void sideProcessingMessage4(CBORObject[] ead4) {
		// Go through the EAD items, if any		
	}
	
	public void populateSetsOfExistingEAD() {
		// Fill the corresponding sets as EAD items as they are defined and registered
	}
	
}