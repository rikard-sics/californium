package org.eclipse.californium.edhoc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.StringUtil;

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
	private HashMap<CBORObject, OneKey> peerPublicKeys = new HashMap<CBORObject, OneKey>();
    
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
	
	// This data structure collects the number of occurrences of EAD items in different EDHOC messages
	//
	// The outer map key is the EAD label
	//
	// The inner map key is a value from (1, 2, 3, 4), denoting one of the four EDHOC messages
	// The inner map value is the number of times that the EAD item with that EAD label has occurred in that EDHOC message 
	private HashMap<Integer, HashMap<Integer, Integer>> eadItemsOccurrences = new HashMap<Integer, HashMap<Integer, Integer>>();


	public SideProcessor(int trustModel, HashMap<CBORObject, OneKey> peerPublicKeys,
						 HashMap<CBORObject, CBORObject> peerCredentials,
						 HashMap<Integer, List<CBORObject>> eadProductionInput) {

		this.trustModel = trustModel;
		this.peerPublicKeys = peerPublicKeys;
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
		
		removeResults(Constants.EDHOC_MESSAGE_1, false);
		removeResults(Constants.EDHOC_MESSAGE_2, false);
		removeResults(Constants.EDHOC_MESSAGE_2, true);
		removeResults(Constants.EDHOC_MESSAGE_3, false);
		removeResults(Constants.EDHOC_MESSAGE_3, true);
		removeResults(Constants.EDHOC_MESSAGE_4, false);

	}
	
	/**
    * Delete all the results from the side processing related to an EDHOC message
    *  
    * @param messageNumber  The number of EDHOC message that the EAD items refer to
    * @param postValidation  True to select the results of EAD processing after EDHOC message validation, or false otherwise
    */
	public void removeResults(int messageNumber, boolean postValidation) {
		HashMap<Integer, List<HashMap<Integer, CBORObject>>> myResults = whichResults(messageNumber, postValidation);
		
		for (Integer index : myResults.keySet()) {
			eadSpecificCleanup(myResults, index.intValue());
		}
		
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
		
		eadSpecificCleanup(myResults, keyValue);
		
		myResults.remove(Integer.valueOf(keyValue));
	}
	
	/**
	  * Contextually with the deletion of the results from the processing
	  * of an EAD item, perform cleanup actions specific to that EAD item, 
	  *  
	  * @param messageNumber  The number of EDHOC message that the EAD items refer to
	  * @param keyValue   The identifier of the result set to delete
	  * @param postValidation  True to select the results of EAD processing after EDHOC message validation, or false otherwise
	*/
	private void eadSpecificCleanup(HashMap<Integer, List<HashMap<Integer, CBORObject>>> myResults, final int eadLabel) {
		
		List<HashMap<Integer, CBORObject>> resultList = myResults.get(Integer.valueOf(eadLabel));
		
		if (resultList == null) {
			return;
		}
		
		CBORObject peerCred = null;
		CBORObject ownCred = null;
		
		/*
		 * Template for each entry
		 * 
		if (eadLabel == Constants.EAD_LABEL_TBD) {
		  // TBD
		}
		*/
				
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
		
		if (ead1 != null && ead1.length > 0) {
			if (eadConsumptionDispatcher(org.eclipse.californium.edhoc.Constants.EDHOC_MESSAGE_1, false, sideProcessorInfo, ead1) == false) {
				return;
			}
		}
		
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
		
		if (ead2 != null && ead2.length > 0) {
			if (eadConsumptionDispatcher(org.eclipse.californium.edhoc.Constants.EDHOC_MESSAGE_2, false, sideProcessorInfo, ead2) == false) {
				return;
			}
		}
		
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
		
		if (ead2 != null && ead2.length > 0) {
			if (eadConsumptionDispatcher(org.eclipse.californium.edhoc.Constants.EDHOC_MESSAGE_2, true, sideProcessorInfo, ead2) == false) {
				return;
			}
		}
		
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
		
		if (ead3 != null && ead3.length > 0) {
			if (eadConsumptionDispatcher(org.eclipse.californium.edhoc.Constants.EDHOC_MESSAGE_3, false, sideProcessorInfo, ead3) == false) {
				return;
			}
		}
		
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
		
		if (ead3 != null && ead3.length > 0) {
			if (eadConsumptionDispatcher(org.eclipse.californium.edhoc.Constants.EDHOC_MESSAGE_3, true, sideProcessorInfo, ead3) == false) {
				return;
			}
		}
		
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
		
		if (ead4 != null && ead4.length > 0) {
			if (eadConsumptionDispatcher(org.eclipse.californium.edhoc.Constants.EDHOC_MESSAGE_4, false, null, ead4) == false) {
				return;
			}
		}

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
			
			// The production of this EAD item is actually not supported. Silently continue.
			if (eadItem == null) {
				continue;
			}
			
			if (eadItem[0].getType() != CBORType.Integer && eadItem[0].getType() != CBORType.TextString)
				return false;
			
			// A fatal error occurred while producing this EAD item
			if (eadItem[0].getType() == CBORType.TextString) {
				if (eadItem[1].getType() != CBORType.Integer)
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
	
	/**
	 * Invoke the consume() method of the right EAD item to consume
	 * 
	 * Due to early parsing of the EAD field when processing the EDHOC message, an EAD item considered here is always supported 
	 * 
 	 * @param messageNumber  The number of the incoming EDHOC message that includes the EAD item to consume
 	 * @param postValidation  True to indicate EAD processing after EDHOC message validation, or false otherwise
 	 * @param sideProcessorInfo  Information generally required for processing the EAD field. It can be null, when processing the EAD_4 field
 	 * @param eadField  The EAD field from the incoming EDHOC message
 	 * @return  True in case of no error when processing any critical item, in order to continue the EDHOC session can continue 
 	 *          False in case of error when processing any critical item, in order to abort the EDHOC session 
	 */
	public boolean eadConsumptionDispatcher(int messageNumber, boolean postValidation, CBORObject[] sideProcessorInfo, CBORObject[] eadField) {
		
		int index = 0;
		boolean success = true;
		
		while (index < eadField.length) {
			int eadLabel = eadField[index].AsInt32();
			byte[] eadValue = null;
			index++;
			if ((index < eadField.length) && ((eadField[index].getType()) == CBORType.ByteString)) {
				eadValue = eadField[index].GetByteString();
				index++;
			}
			
			boolean critical = false;
			if (eadLabel < 0) {
				critical = true;
				eadLabel = -eadLabel;
			}
			
			if (eadItemsOccurrences.containsKey(Integer.valueOf(eadLabel)) == false) {
				HashMap<Integer, Integer> innerMap = new HashMap<Integer, Integer>();
				innerMap.put(Integer.valueOf(Constants.EDHOC_MESSAGE_1), Integer.valueOf(0));
				innerMap.put(Integer.valueOf(Constants.EDHOC_MESSAGE_2), Integer.valueOf(0));
				innerMap.put(Integer.valueOf(Constants.EDHOC_MESSAGE_3), Integer.valueOf(0));
				innerMap.put(Integer.valueOf(Constants.EDHOC_MESSAGE_4), Integer.valueOf(0));
				eadItemsOccurrences.put(Integer.valueOf(eadLabel), innerMap);
			}
			
			// This has to be populated with the invocation of the consume() method for the EAD item to produce
			switch(eadLabel) {
				/*
				 Template case
				
				 case Constants.EAD_LABEL_TBD:
				 if (postValidation == false) {
					// This EAD item is intended to be processed only before validating the peer's authentication credential 
					success = eadConsumeTBD(critical, messageNumber, postValidation, sideProcessorInfo, eadValue);
				 }
				 break;
				*/
			}
			
			if (success == false) {
				break;
			}
		}
		return success;
		
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
					System.out.println("Result element #" + j.intValue() + ": " + obj.toString());				
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
		boolean newCredential = true;
		CBORObject peerCredentialContainer = null;
		CBORObject peerCredentialCBOR = null;

		if (peerCredentials.containsKey(idCredX)) {
			newCredential = false;
			peerCredentialContainer = peerCredentials.get(idCredX);
	    	peerCredentialCBOR = CBORObject.DecodeFromBytes(peerCredentialContainer.GetByteString());
		}
		
		if (peerCredentialContainer == null) {

			// CRED_X was not found among the stored authentication credentials.
			// Then, ID_CRED_X has to specify CRED_X by value.
			
			Set<CBORObject> credTypesForCredByValue = new HashSet<>();
			credTypesForCredByValue.add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCWT));
			credTypesForCredByValue.add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS));
			credTypesForCredByValue.add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5CHAIN));
			
			boolean credByValue = false;
			for (CBORObject obj : idCredX.getKeys()) {
				if (credTypesForCredByValue.contains(obj)) {
					peerCredentialCBOR = idCredX.get(obj);
					credByValue = true;
					break;
				}
			}
			
			if (credByValue == false) {
				// ID_CRED_X does not transport CRED_X by value
				
				// Check for any relevant EAD items that transport the authentication credential by value
				
				return null;
			}
			
			if (trustModel == Constants.TRUST_MODEL_NO_LEARNING) {
				// Only already known CRED_X are admitted to use
				
				// Admit potential exception for well-defined circumstances
				
				System.err.println("New authentication credentials cannot be learned during an EDHOC session");
				
				return null;
			}
	
		}
		
		int credentialType = -1;
		
		if (idCredX.getKeys().contains(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KID))) {

			if (peerCredentialCBOR.getType().equals(CBORType.Array)) {
				credentialType = Constants.CRED_TYPE_CWT;
			}
			if (peerCredentialCBOR.getType().equals(CBORType.Map)) {
				credentialType = Constants.CRED_TYPE_CCS;
			}
		}
		if (idCredX.getKeys().contains(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCWT))) {
			credentialType = Constants.CRED_TYPE_CWT;
		}
		if (idCredX.getKeys().contains(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS))) {
			credentialType = Constants.CRED_TYPE_CCS;
		}
		if (idCredX.getKeys().contains(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5CHAIN)) ||
			idCredX.getKeys().contains(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5T)) ||
			idCredX.getKeys().contains(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5U))) {
			credentialType = Constants.CRED_TYPE_X509;
		}
		
		if (credentialType < 0) {
			return null;
		}
		
		// Check whether the authentication credential is valid (for applicable credential types)
		
		boolean validCred = false;
		
		switch(credentialType) {
			case Constants.CRED_TYPE_CWT:
				validCred = validateCWT(peerCredentialCBOR, newCredential);
				if (validCred && newCredential) {
					if (storeNewCWT(peerCredentialCBOR) == false) {
						return null;
					}
				}
				break;
			case Constants.CRED_TYPE_CCS:
				validCred = validateCCS(peerCredentialCBOR, newCredential);
				if (validCred && newCredential) {
					if (storeNewCCS(peerCredentialCBOR) == false) {
						return null;
					}
				}
				break;
			case Constants.CRED_TYPE_X509:
				validCred = validateX5chain(peerCredentialCBOR, newCredential);
				if (validCred && newCredential) {
					if (storeNewX509(peerCredentialCBOR) == false) {
						return null;
					}
				}
				break;
		}

		if (validCred == false) {
			
			if (newCredential == false) {
			// Remove all the stored entries for the authentication credential corresponding public key

				this.peerCredentials.remove(idCredX);
				this.peerPublicKeys.remove(idCredX);
				
				for (CBORObject key : this.peerCredentials.keySet()) {
					if (this.peerCredentials.get(key).equals(peerCredentialContainer)) {
						this.peerCredentials.remove(key);
						this.peerPublicKeys.remove(key);
					}
				}
			}
			
			return null;
		}

		if (peerCredentialContainer == null) {
			// If this point is reached, the authentication credential is valid and learned now.
			// The container to return was stored in the appropriate data structure and can be retrieved from there.
		
			peerCredentialContainer = this.peerCredentials.get(idCredX);
		}
		
    	// TODO: Check whether the authentication credential is good to use in the context of this EDHOC session
		
		return peerCredentialContainer;
	}
	
	/**
	 * Store a CWT as the authentication credential of another peer,
	 * together with the corresponding public key specified therein
	 * 
 	 * @param cwt  The CWT as a CBOR array
 	 * @return  True if the storing succeeds, or false otherwise. 
	 */
	private boolean storeNewCWT(CBORObject cwt) {
		
		// Store two entries, using the COSE Header Parameters 'kcwt' and 'kid', thus allowing
		// a retrieval in case a later ID_CRED_X specifies the credential by value or by reference
		
		// TBD
		
		return true;
		
	}
	
	/**
	 * Store a CCS as the authentication credential of another peer,
	 * together with the corresponding public key specified therein
	 * 
 	 * @param ccs  The CCS as a CBOR map
 	 * @return  True if the storing succeeds, or false otherwise. 
	 */
	private boolean storeNewCCS(CBORObject ccs) {
		
		// Store two entries, using the COSE Header Parameters 'kccs' and 'kid', thus allowing
		// a retrieval in case a later ID_CRED_X specifies the credential by value or by reference

		OneKey peerPublicKey = null;

		CBORObject coseKey = ccs.get(CBORObject.FromObject(Constants.CWT_CLAIMS_CNF)).
								 get(CBORObject.FromObject(Constants.CWT_CNF_COSE_KEY));
		
		int curve = 0;
		int keyType = coseKey.get(Constants.COSE_KEY_COMMON_PARAM_KTY).AsInt32();
		
		if (keyType == Constants.COSE_KEY_TYPE_OKP || keyType == Constants.COSE_KEY_TYPE_EC2) {
			curve = coseKey.get(Constants.COSE_KEY_TYPE_PARAM_CRV).AsInt32();
			
			byte[] x = null;			
			byte[] y = null;
			
			x  = coseKey.get(Constants.COSE_KEY_TYPE_PARAM_X).GetByteString();			
			if (keyType == Constants.COSE_KEY_TYPE_EC2) {
				y  = coseKey.get(Constants.COSE_KEY_TYPE_PARAM_Y).GetByteString();
			}
			
			if (curve == Constants.CURVE_X25519) {
				peerPublicKey =  SharedSecretCalculation.buildCurve25519OneKey(null, x);
			}
			if (curve == Constants.CURVE_Ed25519) {
				peerPublicKey =  SharedSecretCalculation.buildEd25519OneKey(null, x);
			}
			if (curve == Constants.CURVE_P256) {
				peerPublicKey =  SharedSecretCalculation.buildEcdsa256OneKey(null, x, y);
			}
			
			if (peerPublicKey == null) {
				return false;
			}
			
		}
		
		CBORObject peerCredentialContainer = CBORObject.FromObject(ccs.EncodeToBytes());
		
		CBORObject idCredKccs = Util.buildIdCredKccs(ccs);
		peerPublicKeys.put(idCredKccs, peerPublicKey);
		peerCredentials.put(idCredKccs, peerCredentialContainer);
		
		// If the COSE Key specifies 'kid', store one additional entry identified by the 'kid' value
		if (coseKey.ContainsKey(Constants.COSE_KEY_COMMON_PARAM_KID)) {
			CBORObject kidCBOR = coseKey.get(Constants.COSE_KEY_COMMON_PARAM_KID);
			if (kidCBOR.getType().equals(CBORType.ByteString)) {
				byte[] kid = coseKey.get(Constants.COSE_KEY_COMMON_PARAM_KID).GetByteString();
				CBORObject idCredKid = Util.buildIdCredKid(kid);
				peerPublicKeys.put(idCredKid, peerPublicKey);
				peerCredentials.put(idCredKid, peerCredentialContainer);
			}
		}
		
		return true;
		
	}
	
	/**
	 * Store an X.509 certificate as the authentication credential of another peer,
	 * together with the corresponding public key specified therein.
	 * 
	 * Note that only the end-entity certificate associated with the other peer is considered.
	 * 
 	 * @param cwt  A CBOR byte string with value an end-entity X.509 certificate
  	 * @return  True if the storing succeeds, or false otherwise. 
	 */
	private boolean storeNewX509(CBORObject x509) {
		
		// Store two entries, using the COSE Header Parameters 'x5chain' and 'x5t', thus allowing
		// a retrieval in case a later ID_CRED_X specifies the credential by value or by reference
		
		// TBD
		
		return true;
		
	}
	
	/**
	 * Determine whether a CWT is valid or not
	 * 
 	 * @param cwt  The CWT as a CBOR array
	 * @param newCredential  True if the CWT was not already stored when invoking this method, or false otherwise
 	 * @return  True if the CWT is valid, or false otherwise. 
	 */
	private boolean validateCWT(final CBORObject cwt, final boolean newCredential) {
		
		if (newCredential) {
			// The credential is new, so more thorough checks are required
			
			if (cwt.getType().equals(CBORType.Array) == false) {
				return false;
			}
			
			// TBD
		}
		
		// TBD
		
		return true;
		
	}
	
	/**
	 * Determine whether a CCS is valid or not
	 * 
 	 * @param ccs  The CCS as a CBOR map
	 * @param newCredential  True if the CCS was not already stored when invoking this method, or false otherwise
 	 * @return  True if the CCS is valid, or false otherwise. 
	 */
	private boolean validateCCS(final CBORObject ccs, final boolean newCredential) {
		
		if (newCredential) {
			// The credential is new, so more thorough checks are required
			
			if (ccs.getType().equals(CBORType.Map) == false) {
				return false;
			}
			if (ccs.ContainsKey(CBORObject.FromObject(Constants.CWT_CLAIMS_CNF)) == false) {
				return false;
			}
			
			CBORObject cnfValue = ccs.get(CBORObject.FromObject(Constants.CWT_CLAIMS_CNF));
			if (cnfValue.getType().equals(CBORType.Map) == false) {
				return false;
			}
			if (cnfValue.ContainsKey(CBORObject.FromObject(Constants.CWT_CNF_COSE_KEY)) == false) {
				return false;
			}
			
			CBORObject coseKeyValue = cnfValue.get(CBORObject.FromObject(Constants.CWT_CNF_COSE_KEY));
			
			if (checkCoseKey(coseKeyValue) == false) {
				return false;
			}
			
		}
		
		if (ccs.ContainsKey(Constants.CWT_CLAIMS_EXP)) {
			Long expValue = ccs.get(Constants.CWT_CLAIMS_EXP).AsInt64Value();
			if (expValue < (System.currentTimeMillis() / 1000)) {
				// The credential is expired
				return false;
			}
		}

		return true;
		
	}
	
	/**
	 * Determine whether an end-entity X.509 certificate is valid or not
	 * 
 	 * @param x5chain  A CBOR byte string with value the serialization of an x5chain.
 	 * 				   - If the credential is not new, the value of the CBOR byte string is the binary encoding
 	 * 		   		     of a CBOR byte string, whose value is the end-entity X.509 certificate of the other peer
 	 * 				   - If the credential is new, the value of the CBOR byte string is the binary encoding
 	 * 				     of a chain of X.509 certificates, i.e., either:
 	 * 				     - The binary encoding of a CBOR byte string, whose value is the end-entity X.509 certificate of the other peer; or
 	 * 				     - The binary encoding of a CBOR array. Each element of the array is a CBOR byte string, whose value
 	 *                     is an X.509 certificate. The first element corresponds to the end-entity X.509 certificate of the other peer.
 	 * 
	 * @param newCredential  True if the end-entity X.509 certificate was not already stored
	 *                       when invoking this method, or false otherwise
 	 * @return  True if the end-entity X.509 certificate is valid, or false otherwise. 
	 */
	private boolean validateX5chain(final CBORObject x5chain, final boolean newCredential) {
		
		if (newCredential) {
			// The credential is new, so more thorough checks are required
			
			CBORType cborType = x5chain.getType();
			
			if ((cborType.equals(CBORType.ByteString) == false) && (cborType.equals(CBORType.Array) == false)) {
				return false;
			}
			if (cborType.equals(CBORType.Array)) {
				int size = x5chain.size();
				if (size < 2) {
					return false;
				}
				for (int i = 0; i < size; i++) {
					if (x5chain.get(i).getType().equals(CBORType.ByteString) == false) {
						return false;
					}
				}
			}
			
			// TBD
		}
		
		// TBD
		
		return true;
		
	}
	
	/**
	 * Check whether a COSE Key is well-formed
	 * 
	 * This method does not perform cryptographic-relevant validation (e.g., correctness
	 * of the public key coordinates), which is left to later invocation of the COSE library
	 * 
 	 * @param coseKey  The COSE Key as a CBOR map
 	 * @return  True if the COSE Key is well-formed, or false otherwise. 
	 */
	private boolean checkCoseKey(final CBORObject coseKey) {
		
		if (coseKey.getType().equals(CBORType.Map) == false) {
			return false;
		}
		if (coseKey.ContainsKey(CBORObject.FromObject(Constants.COSE_KEY_COMMON_PARAM_KTY)) == false) {
			return false;
		}
		if (coseKey.get(CBORObject.FromObject(Constants.COSE_KEY_COMMON_PARAM_KTY)).getType().equals(CBORType.Integer) == false) {
			return false;
		}
		
		int curve = 0;
		int keyType = coseKey.get(CBORObject.FromObject(Constants.COSE_KEY_COMMON_PARAM_KTY)).AsInt32();
		if ((keyType == Constants.COSE_KEY_TYPE_OKP) || (keyType == Constants.COSE_KEY_TYPE_EC2)) {
			if (coseKey.ContainsKey(CBORObject.FromObject(Constants.COSE_KEY_TYPE_PARAM_CRV)) == false ||
				coseKey.ContainsKey(CBORObject.FromObject(Constants.COSE_KEY_TYPE_PARAM_X)) == false) {
				return false;
			}
			if (coseKey.get(CBORObject.FromObject(Constants.COSE_KEY_TYPE_PARAM_CRV)).getType().equals(CBORType.Integer) == false) {
				return false;
			}
			if (coseKey.get(CBORObject.FromObject(Constants.COSE_KEY_TYPE_PARAM_X)).getType().equals(CBORType.ByteString) == false) {
				return false;
			}
			curve = coseKey.get(CBORObject.FromObject(Constants.COSE_KEY_TYPE_PARAM_CRV)).AsInt32();
		}
		else {
			return false;
		}
		
		if (keyType == Constants.COSE_KEY_TYPE_OKP) {
			if (curve != Constants.CURVE_X25519 && curve != Constants.CURVE_Ed25519) {
				return false;
			}
		}
		if (keyType == Constants.COSE_KEY_TYPE_EC2) {
			if (curve != Constants.CURVE_P256) {
				return false;
			}
			if (coseKey.ContainsKey(CBORObject.FromObject(Constants.COSE_KEY_TYPE_PARAM_Y)) == false) {
				return false;
			}
			if (coseKey.get(CBORObject.FromObject(Constants.COSE_KEY_TYPE_PARAM_Y)).getType().equals(CBORType.ByteString) == false) {
				return false;
			}
		}
		
		return true;
		
	}
	
	/*
	 * After successfully completing an EDHOC session, perform follow-up actions related to EAD items provided in the session
	 */
	public void eadProcessingFollowUp() {
		
		for (Integer i : this.resMessage1.keySet()) {
			
			// If processing results for a certain EAD item are present, invoke the
			// corresponding method to perform follow-up actions based on those
			
		}
		
		for (Integer i : this.resMessage2Pre.keySet()) {
			
			// If processing results for a certain EAD item are present, invoke the
			// corresponding method to perform follow-up actions based on those
			
		}

		for (Integer i : this.resMessage2Post.keySet()) {
			
			// If processing results for a certain EAD item are present, invoke the
			// corresponding method to perform follow-up actions based on those
			
		}
		
		for (Integer i : this.resMessage3Pre.keySet()) {
			
			// If processing results for a certain EAD item are present, invoke the
			// corresponding method to perform follow-up actions based on those

		}

		for (Integer i : this.resMessage3Post.keySet()) {
			
			// If processing results for a certain EAD item are present, invoke the
			// corresponding method to perform follow-up actions based on those
			
		}
		
		for (Integer i : this.resMessage4.keySet()) {
			
			// If processing results for a certain EAD item are present, invoke the
			// corresponding method to perform follow-up actions based on those
			
		}
		
	}

}
