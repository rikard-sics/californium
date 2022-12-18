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
	
	// This data structure collects the produced EAD items to include in an outgoing EDHOC message.
	//
	// The outer map key indicates the outgoing EDHOC message in question.
	//
	// Each inner list specifies a sequence of element pairs (CBOR integer, CBOR byte string) or of elements (CBOR integer),
	// for EAD items that specify or do not specify an ead_value, respectively. The CBOR integer specifies the ead_label in case
	// of non-critical EAD item, or the corresponding negative value in case of critical EAD item.
	private HashMap<Integer, List<CBORObject>> producedEADs = new HashMap<Integer, List<CBORObject>>();
	
	// This data structure collects instructions provided by the application for producing EAD items
	// to include in outgoing EDHOC messages. The production of these EAD items is not related to or
	// triggered by the consumption of other EAD items included in incoming EDHOC messages.
	// 
	// This data structure can be null if the application does not specify the production of any of such EAD items. 
	//
	// The outer map key indicates the outgoing EDHOC message in question.
	//
	// Each inner list specifies a sequence of element pairs (CBOR integer, CBOR map).
	// The CBOR integer specifies the ead_label in case of non-critical EAD item,
	// or the corresponding negative value in case of critical EAD item.
	// The CBOR map provides input on how to produce the EAD item,
	// with the map keys from a namespace specific of the ead_label.
	private HashMap<Integer, List<CBORObject>> eadProductionInput = new HashMap<Integer, List<CBORObject>>();


	public SideProcessor(int trustModel, HashMap<CBORObject, CBORObject> peerCredentials,
						 HashMap<Integer, List<CBORObject>> eadProductionInput) {

		this.trustModel = trustModel;
		this.peerCredentials = peerCredentials;
		this.session = null;
		
		this.eadProductionInput = eadProductionInput;

	}
	
	/**
    * Return the results obtained from the side processing
    * 
    * @param messageNumber  The number of EDHOC message that the EAD items refer to
    * @param postValidation  True to select the results of EAD processing after EDHOC message validation, or false otherwise
    * @return  The results obtained from consuming/producing EAD items for the EDHOC message.
    */
	public HashMap<Integer, List<HashMap<Integer, CBORObject>>> getResults(int messageNumber, boolean postValidation) {
		return whichResults(messageNumber, postValidation);
	}
	
	/**
    * Store a result obtained from the side processing
    * 
    * @param messageNumber  The number of EDHOC message that the EAD items refer to
    * @param postValidation  True to select the results of EAD processing after EDHOC message validation, or false otherwise
    * @param resultLabel   Identifier of the specific map where to store this result
    * @param resultContent   The result to store
    */
	private void addResult(int messageNumber, boolean postValidation, int resultLabel, HashMap<Integer, CBORObject> resultContent) {
		HashMap<Integer, List<HashMap<Integer, CBORObject>>> myResults = whichResults(messageNumber, postValidation);
		
		if (!myResults.containsKey(Integer.valueOf(resultLabel))) {
			List<HashMap<Integer, CBORObject>> myList = new ArrayList<HashMap<Integer, CBORObject>>();
			myResults.put(Integer.valueOf(resultLabel), myList);
		}
		myResults.get(Integer.valueOf(resultLabel)).add(resultContent);
	}
	
	/**
    * Delete all the results obtained from the side processing
	*/
	public void removeResults() {
		resMessage1.clear();
		resMessage2Pre.clear();
		resMessage2Post.clear();
		resMessage3Pre.clear();
		resMessage3Post.clear();
		resMessage4.clear();
	}
	
	/**
    * Delete all the results from the side processing related to an EDHOC message
    *  
    * @param messageNumber  The number of EDHOC message that the EAD items refer to
    * @param postValidation  True to select the results of EAD processing after EDHOC message validation, or false otherwise
    */
	public void removeResults(int messageNumber, boolean postValidation) {
		HashMap<Integer, List<HashMap<Integer, CBORObject>>> myResults = whichResults(messageNumber, postValidation);
		myResults.clear();
	}

	/**
    * Delete a specific result set obtained from the side processing related to an EDHOC message
    *  
    * @param messageNumber  The number of EDHOC message that the EAD items refer to
    * @param keyValue   The identifier of the result set to delete
    * @param postValidation  True to select the results of EAD processing after EDHOC message validation, or false otherwise
    */
	public void removeResultSet(int messageNumber, int keyValue, boolean postValidation) {
		HashMap<Integer, List<HashMap<Integer, CBORObject>>> myResults = whichResults(messageNumber, postValidation);
		if (myResults.size() == 0)
			return;
		myResults.remove(Integer.valueOf(keyValue));
	}
	
	/**
    * Store an error result obtained from the side processing
    * 
    * @param messageNumber  The number of EDHOC message that the EAD items refer to
    * @param postValidation  True to select the results of EAD processing after EDHOC message validation, or false otherwise
    * @param errorMessage   The error message
    * @param responseCode   The CoAP response error code to use, if following up with an EDHOC error message as a CoAP response
    */
	private void addErrorResult(int messageNumber, boolean postValidation, String errorMessage, int responseCode) {
		HashMap<Integer, CBORObject> errorMap = new HashMap<Integer, CBORObject>();
		
		errorMap.put(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_DESCRIPTION),
				 CBORObject.FromObject(errorMessage));
		errorMap.put(Integer.valueOf(Constants.SIDE_PROCESSOR_INNER_ERROR_RESP_CODE),
			 CBORObject.FromObject(responseCode));

		addResult(messageNumber, postValidation, Constants.SIDE_PROCESSOR_OUTER_ERROR, errorMap);
	}
	
	public List<CBORObject> getProducedEADs(int messageNumber) {
		return producedEADs.get(Integer.valueOf(messageNumber));
	}
	
	/**
 	 * @param messageNumber  The number of the outgoing EDHOC message that will include the EAD item
 	 * @param eadLabel  The ead_label of the EAD item to include, or its corresponding negative value if the EAD item is critical
 	 * @param eadValue  The ead_value of the EAD item to include, or null if the ead_value is not present 
	 */
	private void addProducedEAD(int messageNumber, CBORObject eadLabel, CBORObject eadValue) {

		if (!producedEADs.containsKey(Integer.valueOf(messageNumber))) {
			producedEADs.put(Integer.valueOf(messageNumber), new ArrayList<CBORObject>());
		}
		List<CBORObject> myList = producedEADs.get(Integer.valueOf(messageNumber));
		myList.add(eadLabel);
		if (eadValue != null) {
			myList.add(eadValue);
		}
		
	}
	
	/**
	 * Return the correct map to look at, as including the desired results obtained from the side processing
	 * 
 	 * @param messageNumber  The number of the outgoing EDHOC message that will include the EAD item
     * @param postValidation  True to select the results of EAD processing after EDHOC message validation, or false otherwise
     * @return  The map including the desired results obtained from the side processing
	 */
	
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
	
	/**
	 * Associates this SideProcessor object with the EDHOC session to consider
	 * 
 	 * @param session  The EDHOC session
	 */
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
	
	/**
	 * Entry point for processing EAD items from EAD_1
	 * 
 	 * @param sideProcessorInfo  Information generally required for processing EAD_1
  	 * @param ead1  The EAD items from EAD_1, including only items that the endpoint understands and excluding padding
	 */
	// sideProcessorInfo includes useful pieces information for processing EAD_1
	// 0) A CBOR integer, with value MEHOD
	// 1) A CBOR array of integers, including all the integers specified in SUITES_I, in the same order
	// 2) A CBOR byte string, with value G_X
	// 3) A CBOR byte string, with value C_I (in its original, binary format)
	public void sideProcessingMessage1(CBORObject[] sideProcessorInfo, CBORObject[] ead1) {
		
		// Go through the EAD_1 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// This may further trigger the production of new EAD items to include in the next, outgoing EDHOC message.
		// In such a case, invoke eadProductionDispatcher() for each of those EAD items to produce.
		//
		// ...
		//
		
	}

	/**
	 * Entry point for processing EAD items from EAD_2 before message verification
	 * 
 	 * @param sideProcessorInfo  Information generally required for processing EAD_2
  	 * @param ead2  The EAD items from EAD_2, including only items that the endpoint understands and excluding padding
	 */
	// sideProcessorInfo includes useful pieces information for processing EAD_2, in this order:
	// 0) A CBOR byte string, with value G_Y
	// 1) A CBOR byte string, with value C_R (in its original, binary format)
	// 2) A CBOR map, as ID_CRED_R
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
		// This may further trigger the production of new EAD items to include in the next, outgoing EDHOC message.
		// In such a case, invoke eadProductionDispatcher() for each of those EAD items to produce.
		//
		// ...
		//
		
	}

	/**
	 * Entry point for processing EAD items from EAD_2 after message verification
	 * 
 	 * @param sideProcessorInfo  Information generally required for processing EAD_2
  	 * @param ead2  The EAD items from EAD_2, including only items that the endpoint understands and excluding padding
	 */
	// sideProcessorInfo includes useful pieces information for processing EAD_2, in this order:
	// 0) A CBOR byte string, with value G_Y
	// 1) A CBOR byte string, with value C_R (in its original, binary format)
	// 2) A CBOR map, as ID_CRED_R
	public void sideProcessingMessage2PostVerification(CBORObject[] sideProcessorInfo, CBORObject[] ead2) {
		CBORObject gY = sideProcessorInfo[0];
		CBORObject connectionIdentifierResponder = sideProcessorInfo[1];
		CBORObject idCredR = sideProcessorInfo[2];
		
		// Go through the EAD_2 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// This may further trigger the production of new EAD items to include in the next, outgoing EDHOC message.
		// In such a case, invoke eadProductionDispatcher() for each of those EAD items to produce.
		//
		// ...
		//
		
	}

	/**
	 * Entry point for processing EAD items from EAD_3 before message verification
	 * 
 	 * @param sideProcessorInfo  Information generally required for processing EAD_3
  	 * @param ead3  The EAD items from EAD_3, including only items that the endpoint understands and excluding padding
	 */
	// sideProcessorInfo includes useful pieces information for processing EAD_3, in this order:
	// 0) A CBOR map, as ID_CRED_I
	//
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
		// This may further trigger the production of new EAD items to include in the next, outgoing EDHOC message.
		// In such a case, invoke eadProductionDispatcher() for each of those EAD items to produce.
		//
		// ...
		//
		
	}

	/**
	 * Entry point for processing EAD items from EAD_3 before message verification
	 * 
 	 * @param sideProcessorInfo  Information generally required for processing EAD_3
  	 * @param ead3  The EAD items from EAD_3, including only items that the endpoint understands and excluding padding
	 */
	// sideProcessorInfo includes useful pieces information for processing EAD_3, in this order:
	// 0) A CBOR map, as ID_CRED_I
	//
	public void sideProcessingMessage3PostVerification(CBORObject[] sideProcessorInfo, CBORObject[] ead3) {
		
		// Go through the EAD_3 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// This may further trigger the production of new EAD items to include in the next, outgoing EDHOC message.
		// In such a case, invoke eadProductionDispatcher() for each of those EAD items to produce.
		//
		// ...
		//
		
	}
	
	/**
	 * Entry point for processing EAD items from EAD_4
	 * 
  	 * @param ead4  The EAD items from EAD_4, including only items that the endpoint understands and excluding padding
	 */
	public void sideProcessingMessage4(CBORObject[] ead4) {

		// Go through the EAD_4 items, if any
		//
		// For each EAD item, invoke the corresponding consume() method, and then addResult(). 
		// Stop in case the consumption of an EAD item returns a fatal error.
		//
		// This may further trigger the production of new EAD items to include in the next, outgoing EDHOC message.
		// In such a case, invoke eadProductionDispatcher() for each of those EAD items to produce.
		//
		// ...
		//

	}
	
	/**
 	 * @param messageNumber  The number of the outgoing EDHOC message that will include the EAD item
 	 * @return  False in case of malformed input, or true otherwise.
 	 *          This is not related to the correct/failed production of EAD items. 
	 */
	public boolean produceIndependentEADs(int messageNumber) {
		
		if (eadProductionInput == null || !eadProductionInput.containsKey(Integer.valueOf(messageNumber)))
			return true;
		
		List<CBORObject> myList = eadProductionInput.get(Integer.valueOf(messageNumber));
		
		if ((myList.size() % 2) == 1)
			return false;
		
		int index = 0;
		int size = myList.size();
		
		while (index < size) {
			
			if (myList.get(Integer.valueOf(index)).getType() != CBORType.Integer)
				return false;
			if (myList.get(Integer.valueOf(index + 1)).getType() != CBORType.Map)
				return false;
			
			boolean critical = false;
			int eadLabel = myList.get(Integer.valueOf(index)).AsInt32();
			if (eadLabel < 0) {
				critical = true;
				eadLabel = -eadLabel;
			}
			index++;
			CBORObject productionInput = myList.get(Integer.valueOf(index));
			CBORObject[] eadItem = eadProductionDispatcher(eadLabel, critical, messageNumber, productionInput);
			
			if (eadItem[0].getType() != CBORType.Integer && eadItem[0].getType() != CBORType.TextString)
				return false;
			
			// A fatal error occurred while producing this EAD item
			if (eadItem[0].getType() == CBORType.TextString) {
				if (eadItem[1].getType() != CBORType.ByteString)
					return false;
				
				addErrorResult(messageNumber, true, eadItem[0].AsString(), eadItem[1].AsInt32());
				break;
			}
			
			addProducedEAD(messageNumber, eadItem[0], eadItem[1]);
			
			index++;
			
		}
		
		return true;
		
	}
	
	/**
	 * Invoke the produce() method of the right EAD item to produce
	 * 
 	 * @param eadLabel  The ead_label of the EAD item to produce
	 * @param critical  True if the EAD item has to be produced as critical, or false otherwise
 	 * @param messageNumber  The number of the next, outgoing EDHOC message that will include the produced EAD item
 	 * @param input  A CBOR map providing input on how to produce the EAD item. The map keys belong to a namespace specific of the ead_label. 
 	 * @return  The same result returned by the produce() method of the specific EAD item to produce.
	 */
	public CBORObject[] eadProductionDispatcher(int eadLabel, boolean critical, int messageNumber, CBORObject input) {
		
		// This has to be populated with the invocation of the produce() method for the EAD item to produce
		switch(eadLabel) {
			// CASE NNN:
			// return EAD_NNN.produce(critical, messageNumber, productionInput);
		}
		
		return null; // placeholder, until the invocation to an actual produce() method is included above
		
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
	
	/**
	 * Look for an authentication credential of the other peer to use, by relying on
	 * the associated ID_CRED_X specified in the incoming EDHOC message_2 or message_3.
	 * This considers the trust model used by the endpoint for trusting new authentication credentials.
	 * 
 	 * @param idCredX  The identifier of the peer's authentication credential specified in the incoming EDHOC message
	 * @param ead  The EAD items specified in the incoming EDHOC message,
	 *             including only items that the endpoint understands and excluding padding
 	 * @return  The peer's authentication credential wrapped into a CBOR byte string,
 	 *          or null in case a peer's authentication credential to use is not found. 
	 */
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