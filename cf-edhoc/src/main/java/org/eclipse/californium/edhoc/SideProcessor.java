package org.eclipse.californium.edhoc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
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
	
	// The following data structures are used to collect the results from the side processing of each incoming EDHOC message.
	// For message_2 and message_3, each of those refer to two different data structures, in order to separately collect the
	// results of the processing occurred before and after message verification.
	//
	// The value of the outer map is a list of maps. Each element of the list includes the results from one processing process. 
	// The key of the outer map uniquely determines the namespace of keys and corresponding values for the inner maps organized into a list.
	//
	// The key of the outer map is equal to the ead_label of the EAD item the results refer to, with the following exceptions:
	//
	// - The outer map includes an entry with label  0, with information about the authentication credential of the other peer to use.
	// - The outer map includes an entry with label -1, in case the overall side processing fails.
	//
	private HashMap<Integer, List<HashMap<Integer, CBORObject>>> resMessage1     = new HashMap<Integer, List<HashMap<Integer, CBORObject>>>();
	private HashMap<Integer, List<HashMap<Integer, CBORObject>>> resMessage2Pre  = new HashMap<Integer, List<HashMap<Integer, CBORObject>>>();
	private HashMap<Integer, List<HashMap<Integer, CBORObject>>> resMessage2Post = new HashMap<Integer, List<HashMap<Integer, CBORObject>>>();
	private HashMap<Integer, List<HashMap<Integer, CBORObject>>> resMessage3Pre  = new HashMap<Integer, List<HashMap<Integer, CBORObject>>>();
	private HashMap<Integer, List<HashMap<Integer, CBORObject>>> resMessage3Post = new HashMap<Integer, List<HashMap<Integer, CBORObject>>>();
	private HashMap<Integer, List<HashMap<Integer, CBORObject>>> resMessage4     = new HashMap<Integer, List<HashMap<Integer, CBORObject>>>();
		
	public SideProcessor(int trustModel, HashMap<CBORObject, CBORObject> peerCredentials, EdhocSession session) {

		this.trustModel = trustModel;
		this.peerCredentials = peerCredentials;
		
		this.session = session; // On the Responder, this starts as null and is set later on before starting to prepare message_2
		if (session != null)
			session.setSideProcessor(this);

	}
			
	public HashMap<Integer, List<HashMap<Integer, CBORObject>>> getResults(int messageNumber, boolean postValidation) {
		return whichResults(messageNumber, postValidation);
	}
	
	private void addResult(int messageNumber, boolean postValidation, int resultLabel, HashMap<Integer, CBORObject> resultContent) {
		HashMap<Integer, List<HashMap<Integer, CBORObject>>> myResults = whichResults(messageNumber, postValidation);
		
		if (!myResults.containsKey(Integer.valueOf(resultLabel))) {
			List<HashMap<Integer, CBORObject>> myList = new ArrayList<HashMap<Integer, CBORObject>>();
			myResults.put(Integer.valueOf(resultLabel), myList);
		}
		myResults.get(Integer.valueOf(resultLabel)).add(resultContent);
	}
	
	public void removeResults() {
		resMessage1.clear();
		resMessage2Pre.clear();
		resMessage2Post.clear();
		resMessage3Pre.clear();
		resMessage3Post.clear();
		resMessage4.clear();
	}
	
	public void removeResults(int messageNumber, boolean postValidation) {
		HashMap<Integer, List<HashMap<Integer, CBORObject>>> myResults = whichResults(messageNumber, postValidation);
		myResults.clear();
	}
	
	public void removeResultSet(int messageNumber, int keyValue, boolean postValidation) {
		HashMap<Integer, List<HashMap<Integer, CBORObject>>> myResults = whichResults(messageNumber, postValidation);
		if (myResults.size() == 0)
			return;
		myResults.remove(Integer.valueOf(keyValue));
	}
	
	private void addErrorResult(int messageNumber, boolean postValidation, String errorMessage, int responseCode) {
		HashMap<Integer, CBORObject> errorMap = new HashMap<Integer, CBORObject>();
		
		errorMap.put(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION),
				 CBORObject.FromObject(errorMessage));
		errorMap.put(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE),
			 CBORObject.FromObject(responseCode));

		addResult(messageNumber, postValidation, Constants.SIDE_PROCESSOR_OUTER_ERROR, errorMap);
	}
	
	private HashMap<Integer, List<HashMap<Integer, CBORObject>>> whichResults(int messageNumber, boolean postValidation) {
		switch(messageNumber) {
			case Constants.EDHOC_MESSAGE_1:
				return resMessage1;
			case Constants.EDHOC_MESSAGE_2:
				return (postValidation == false) ? resMessage2Pre : resMessage2Post;
			case Constants.EDHOC_MESSAGE_3:
				return (postValidation == false) ? resMessage3Pre : resMessage3Post;
			case Constants.EDHOC_MESSAGE_4:
				return resMessage4;
		}
		return null;
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
	
	// sideProcessorInfo includes useful pieces information for processing EAD_1
	// 0) A CBOR integer, with value MEHOD
	// 1) A CBOR array of integers, including all the integers specified in SUITES_I, in the same order
	// 2) A CBOR byte string, with value G_X
	// 3) A CBOR byte string, with value C_I (in its original, binary format)
	//
	// ead1 includes the actual EAD items from EAD_1
	public void sideProcessingMessage1(CBORObject[] sideProcessorInfo, CBORObject[] ead1) {
		
		// Go through the EAD_1 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// ...
		//
		
	}

	// sideProcessorInfo includes useful pieces information for processing EAD_2, in this order:
	// 0) A CBOR byte string, with value G_Y
	// 1) A CBOR byte string, with value C_R (in its original, binary format)
	// 2) A CBOR map, as ID_CRED_R 
	//
	// ead2 includes the actual EAD items from EAD_2
	public void sideProcessingMessage2PreVerification(CBORObject[] sideProcessorInfo, CBORObject[] ead2) {
				
		CBORObject gY = sideProcessorInfo[0];
		CBORObject connectionIdentifierResponder = sideProcessorInfo[1];
		CBORObject idCredR = sideProcessorInfo[2];
		
		CBORObject peerCredentialCBOR = findValidPeerCredential(idCredR, ead2);
		
		if (peerCredentialCBOR == null) {
			addErrorResult(Constants.EDHOC_MESSAGE_2, false,
						  "Unable to retrieve a valid peer credential from ID_CRED_R",
						  ResponseCode.BAD_REQUEST.value);
			return;
    	}
		else {
			HashMap<Integer, CBORObject> resultContent = new HashMap<Integer, CBORObject>();
			resultContent.put(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_CRED_VALUE), peerCredentialCBOR);
			addResult(Constants.EDHOC_MESSAGE_2, false, Constants.SIDE_PROCESSOR_OUTER_CRED, resultContent);
		}
		
		// Go through the EAD_2 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// ...
		//
		
	}

	// sideProcessorInfo includes useful pieces information for processing EAD_2, in this order:
	// 0) A CBOR byte string, with value G_Y
	// 1) A CBOR byte string, with value C_R (in its original, binary format)
	// 2) A CBOR map, as ID_CRED_R 
	//
	// ead2 includes the actual EAD items from EAD_2
	public void sideProcessingMessage2PostVerification(CBORObject[] sideProcessorInfo, CBORObject[] ead2) {
		CBORObject gY = sideProcessorInfo[0];
		CBORObject connectionIdentifierResponder = sideProcessorInfo[1];
		CBORObject idCredR = sideProcessorInfo[2];
		
		// Go through the EAD_2 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// ...
		//
		
	}

	// sideProcessorInfo includes useful pieces information for processing EAD_3, in this order:
	// 0) A CBOR map, as ID_CRED_I
	//
	// ead3 includes the actual EAD items from EAD_3
	public void sideProcessingMessage3PreVerification(CBORObject[] sideProcessorInfo, CBORObject[] ead3) {
		
		CBORObject idCredI = sideProcessorInfo[0];
		
		CBORObject peerCredentialCBOR = findValidPeerCredential(idCredI, ead3);
		
		if (peerCredentialCBOR == null) {
			addErrorResult(Constants.EDHOC_MESSAGE_3, false,
						  "Unable to retrieve a valid peer credential from ID_CRED_I",
						  ResponseCode.BAD_REQUEST.value);
			return;
    	}
		else {
			HashMap<Integer, CBORObject> resultContent = new HashMap<Integer, CBORObject>();
			resultContent.put(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_CRED_VALUE), peerCredentialCBOR);
			addResult(Constants.EDHOC_MESSAGE_3, false, Constants.SIDE_PROCESSOR_OUTER_CRED, resultContent);
		}
		
		// Go through the EAD_3 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// ...
		//
		
	}

	// sideProcessorInfo includes useful pieces information for processing EAD_3, in this order:
	// 0) A CBOR map, as ID_CRED_I
	//
	// ead3 includes the actual EAD items from EAD_3
	public void sideProcessingMessage3PostVerification(CBORObject[] sideProcessorInfo, CBORObject[] ead3) {
		
		// Go through the EAD_3 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// ...
		//
		
	}
	
	// ead4 includes the actual EAD items from EAD_4
	public void sideProcessingMessage4(CBORObject[] ead4) {

		// Go through the EAD_4 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// ...
		//

	}
	
	public void showResultsFromSideProcessing(int messageNumber, boolean postValidation) {
		HashMap<Integer, List<HashMap<Integer, CBORObject>>> myResults = whichResults(messageNumber, postValidation);
		if (myResults.size() == 0)
			return;

		String myStr = new String("Results of side processing of message_" + messageNumber);
		if (messageNumber == Constants.EDHOC_MESSAGE_2 || messageNumber == Constants.EDHOC_MESSAGE_3) {
			myStr = (postValidation == false) ? (myStr + " before") : (myStr + " after");
			myStr = myStr + " message verification";
		}
		System.out.println(myStr);
		
		for (Integer i : myResults.keySet()) {
			System.out.println("Processing result for the EAD item with ead_label: " + i.intValue());
			
			List<HashMap<Integer, CBORObject>> myList = myResults.get(i);
			
			// Print the processing results for each instance of this EAD item 
			for(HashMap<Integer, CBORObject> myMap : myList) {
				for (Integer j : myMap.keySet()) {
					CBORObject obj = myMap.get(j);
					System.out.print("Result element #" + j.intValue() + ": " + obj.toString());				
				}	
			}			
			System.out.println("\n");
		}		
		
	}
	
	private CBORObject findValidPeerCredential(CBORObject idCredX, CBORObject[] ead) {
		CBORObject peerCredentialCBOR = null;
		
		if (peerCredentials.containsKey(idCredX)) {
	    	peerCredentialCBOR = peerCredentials.get(idCredX);
	    	
	    	// TODO: Check whether the authentication credential is still valid (for applicable credential types)
	    	
	    	// TODO: Check whether the authentication credential is good to use in the context of this EDHOC session
		}		
		else if (trustModel == Constants.TRUST_MODEL_STRICT) {
				return peerCredentialCBOR;
		}

		// TODO: Add support for the alternative trust models
    			
		return peerCredentialCBOR;
	}

}