package org.eclipse.californium.edhoc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
	
	// The application profile to use
	private AppProfile appProfile;
	
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

	// This data structure tracks the prescriptive information that has been specified in the
	// EAD item "Supported EDHOC Application Profiles" of an outgoing EDHOC message during an EDHOC session
	//
	// The map key is the CBOR Object used as abbreviation for a prescriptive EDHOC_Information parameter
	// that has been exchanged between the two peers during the EDHOC session
	//
	// The map value specifies details about the occurred use of the EDHOC_Information parameter during the
	// EDHOC session. The semantics of the map value depends on the specific EDHOC_Information parameter
	private HashMap<CBORObject, CBORObject> prescriptiveInfoOutgoing = new HashMap<CBORObject, CBORObject>();
	
	// This data structure tracks the prescriptive information that has been specified in the
	// EAD item "Supported EDHOC Application Profiles" of an incoming EDHOC message during an EDHOC session
	//
	// The map key is the CBOR Object used as abbreviation for a prescriptive EDHOC_Information parameter
	// that has been exchanged between the two peers during the EDHOC session
	//
	// The map value specifies details about the occurred use of the EDHOC_Information parameter during the
	// EDHOC session. The semantics of the map value depends on the specific EDHOC_Information parameter
	private HashMap<CBORObject, CBORObject> prescriptiveInfoIncoming = new HashMap<CBORObject, CBORObject>();
	
	// Set of prescriptive EDHOC_Information parameters identified by their integer Profile ID
	private Set<Integer> prescriptiveParameters = new HashSet<>();
	
	// Catalogue of EDHOC application profiles identified by the respective Profile ID
	// 
	// The map label is the Profile ID of the EDHOC application profile stored in the map entry
	// The map value is a CBOR map, i.e., the EDHOC Application Profile Object
	//     specifying the EDHOC application profile stores in the map entry
	private AppProfileCatalogue appProfileCatalogue = new AppProfileCatalogue();

	public SideProcessor(int trustModel, HashMap<CBORObject, OneKey> peerPublicKeys,
						 HashMap<CBORObject, CBORObject> peerCredentials,
						 HashMap<Integer, List<CBORObject>> eadProductionInput,
						 AppProfile appProfile) {

		this.trustModel = trustModel;
		this.peerPublicKeys = peerPublicKeys;
		this.peerCredentials = peerCredentials;
		this.session = null;
		this.appProfile = appProfile;
		
		this.eadProductionInput = eadProductionInput;
		
		prescriptiveParameters.add(Integer.valueOf(Constants.EDHOC_INFORMATION_MESSAGE_4));
		prescriptiveParameters.add(Integer.valueOf(Constants.EDHOC_INFORMATION_EXPORTER_OUT_LEN));
		
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
	  * @param myResults  The set of results to look into
	  * @param eadLabel  The EAD label of the EAD item for which cleanup has to be performed.
	  *                  When the value is 0, it does not actually refer to the EAD item Padding,
	  *                  but rather to the processed authentication credential of the other peer.
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
	// 0) A CBOR integer, with value METHOD
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
			
			System.out.println("\n@SideProcessor produceIndependentEADs():");
			for (int i = 0; i < eadItem.length; i++) {
				System.out.println(eadItem[i].toString());
			}
			System.out.println("");
			
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
			case Constants.EAD_LABEL_SUPPORTED_EDHOC_APP_PROF:
				return eadProduceSupportedEdhocApplicationProfiles(critical, messageNumber, input);
		
			// CASE NNN:
			// return EAD_NNN.produce(critical, messageNumber, productionInput);
		}
		
		return null; // placeholder, until the invocation to an actual produce() method is included above
		
	}
	
	/**
	 * Production of the EAD item "Supported EDHOC Application Profiles"
	 * 
	 * @param critical  True if the EAD item has to be produced as critical, or false otherwise
 	 * @param messageNumber  The number of the next, outgoing EDHOC message that will include the produced EAD item
 	 * @param input  A CBOR map providing input on how to produce the EAD item.
 	 *               The map keys belong to a namespace specific of the ead_label. 
 	 * @return  Null in case of error with no follow-up. Otherwise, a CBOR array with two elements:
 	 *           i) the EAD label and the EAD value; or
 	 *          ii) the error text string and the response error code 
	 */
	private CBORObject[] eadProduceSupportedEdhocApplicationProfiles(boolean critical, int messageNumber, CBORObject input) {
		
		if (critical == false) {
			return null;
		}
		switch (messageNumber) {
			case Constants.EDHOC_MESSAGE_1:
			case Constants.EDHOC_MESSAGE_2:
				break;
			default:
				return null;
		}
		if (input == null || (input.getType() != CBORType.Map)) {
			return null;
		}
		if (input.ContainsKey(Constants.EAD_ITEM_INPUT_SUPPORTED_EDHOC_APP_PROF_VALUE) == false) {
			return null;
		}
		if (input.get(Constants.EAD_ITEM_INPUT_SUPPORTED_EDHOC_APP_PROF_VALUE).getType() != CBORType.ByteString) {
			return null;
		}
		
		byte[] rawEadValue = input.get(Constants.EAD_ITEM_INPUT_SUPPORTED_EDHOC_APP_PROF_VALUE).GetByteString();
		CBORObject[] objectList = null;
		try {
		    objectList = CBORObject.DecodeSequenceFromBytes(rawEadValue);
		}
		catch (Exception e) {
		    return null;
		}
		
		CBORObject paramLabel = null;
		CBORObject paramValue = null;
		CBORObject profileObject = null;
		
	    for (int i = 0; i < objectList.length; i++) {
	    	if (objectList[i].equals(CBORObject.True)) {
	    		continue;
	    	}
	    	if (objectList[i].getType() == CBORType.Integer || objectList[i].getType() == CBORType.Array) {
	    		int profileId;
	    		
	    		// Determine the Profile ID identifying the EDHOC_Application_Profile Object
	    		if (objectList[i].getType() == CBORType.Integer) {
	    			profileId = objectList[i].AsInt32();
	    		}
	    		else if (objectList[i].getType() == CBORType.Array && objectList[i].get(0).getType() == CBORType.Integer) {
	    			profileId = objectList[i].get(0).AsInt32();
	    		}
	    		else {
	    			return null;
	    		}
	    		profileObject = appProfileCatalogue.getAppProfileById(profileId);
	    		if (profileObject == null) {
	    			// Unknown EDHOC Application Profile
	    			continue;
	    		}
	    		
	    	}
	    	if (objectList[i].getType() == CBORType.Map) {
	    		profileObject = objectList[i];
	    	}
	    	
	    	// Check whether a prescriptive parameter is specified
	    	Iterator<Integer> paramIterator = prescriptiveParameters.iterator();
	    	while(paramIterator.hasNext()) {
	    		paramLabel = CBORObject.FromObject(paramIterator.next().intValue());
				paramValue = profileObject.get(paramLabel);
				
		    	if (paramValue == null) {
					continue;
				}
				if (handlePrescriptiveParameters(paramLabel, paramValue, messageNumber, false) == false) {
					return null;
				}
	    	}
	    	
	    }
	    
	    CBORObject eadLabel = CBORObject.FromObject(-1 * Constants.EAD_LABEL_SUPPORTED_EDHOC_APP_PROF);
	    CBORObject eadValue = input.get(Constants.EAD_ITEM_INPUT_SUPPORTED_EDHOC_APP_PROF_VALUE);
	    
	    if (messageNumber == Constants.EDHOC_MESSAGE_2 &&
	    	prescriptiveInfoIncoming.isEmpty() == false &&
	    	prescriptiveInfoOutgoing.isEmpty() == false) {
	    	// This peer is the Responder and it has specified prescriptive information in the prepared EAD item.
	    	//
	    	// If such information contradicts prescriptive information from the Initiator, redact the ead_value
	    	// prepared by the Responder accordingly, and use the result for the EAD item to include in EDHOC message_2
	    	
	    	List<CBORObject> redactedList = redactSupportedEdhocApplicationProfilesFromResponder(objectList);
	    	if (redactedList.isEmpty()) {
	    		eadValue = CBORObject.FromObject(CBORObject.NewMap().EncodeToBytes());
	    	}
	    	else {
	    		eadValue = CBORObject.FromObject(Util.buildCBORSequence(redactedList));
	    	}
	    	
	    }
	    
		CBORObject[] ret = new CBORObject[2];
		ret[0] = eadLabel;
		ret[1] = eadValue;
		
		return ret;
	}
	
	private List<CBORObject> redactSupportedEdhocApplicationProfilesFromResponder(CBORObject[] objectList) {
		
		CBORObject paramLabel = null;
		CBORObject paramValue = null;
		List<CBORObject> redactedList = new ArrayList<>();
		
		for (int i = 0; i < objectList.length; i++) {
			
			if (objectList[i].getType() == CBORType.Integer || objectList[i].getType() == CBORType.Array) {
				int profileId;
				CBORObject obj = null;
				
				if (objectList[i].getType() == CBORType.Integer) {
					profileId = objectList[i].AsInt32();
					obj = appProfileCatalogue.getAppProfileById(profileId);
				}
				if (objectList[i].getType() == CBORType.Array) {
					profileId = objectList[i].get(0).AsInt32();
					obj = appProfileCatalogue.getAppProfileById(profileId);
				}
				if (obj == null) {
					continue;
				}
				
				boolean keep = true;
				Iterator<Integer> paramIterator = prescriptiveParameters.iterator();
		    	while(paramIterator.hasNext()) {
		    		paramLabel = CBORObject.FromObject(paramIterator.next().intValue());
					paramValue = obj.get(paramLabel);
					
			    	if (paramValue == null) {
			    		continue;
					}

			    	if (paramLabel.AsInt32() == Constants.EDHOC_INFORMATION_MESSAGE_4) {
			    		CBORObject baselineValue = prescriptiveInfoIncoming.get(paramLabel);
			    		if (baselineValue != null && paramValue.equals(baselineValue) == false) {
			    			// Do not include this item in the redacted list and move to the next one
			    			keep = false;
							break;
			    		}
			    	}
		    	}
		    	
		    	if (keep == true) {
			    	// Confirm this item in the redacted list
			    	redactedList.add(objectList[i]);
		    	}
				
			}
			
			if (objectList[i].getType() == CBORType.Map) {
				
				CBORObject redactedMap = CBORObject.NewMap();
				for (CBORObject key : objectList[i].getKeys()) {
					redactedMap.Add(key, objectList[i].get(key));
				}
				
				Iterator<Integer> paramIterator = prescriptiveParameters.iterator();
		    	while(paramIterator.hasNext()) {
		    		paramLabel = CBORObject.FromObject(paramIterator.next().intValue());
					paramValue = redactedMap.get(paramLabel);
					
			    	if (paramValue == null) {
			    		continue;
					}

			    	if (paramLabel.AsInt32() == Constants.EDHOC_INFORMATION_MESSAGE_4) {
			    		CBORObject baselineValue = prescriptiveInfoIncoming.get(paramLabel);
			    		if (baselineValue != null && paramValue.equals(baselineValue) == false) {
			    			// Do not include this element in the redacted map
			    			redactedMap.Remove(paramLabel);
			    		}
			    	}
			    	
			    	if (paramLabel.AsInt32() == Constants.EDHOC_INFORMATION_EXPORTER_OUT_LEN) {
			    		CBORObject baselineValue = prescriptiveInfoIncoming.get(paramLabel);
			    		if (baselineValue != null) {
			    			// Revise or remove this element in the redacted map
			    			
			    			CBORObject revisedArray = CBORObject.NewArray();
			    			Set<Integer> usedExporterLabels = new HashSet<>();
			    			for (CBORObject key : baselineValue.getKeys()) {
			    				usedExporterLabels.add(Integer.valueOf(key.AsInt32()));
			    			}
			    			for (int pair = 0; pair < paramValue.size(); pair++) {
		    					int exporterLabel = paramValue.get(pair).get(0).AsInt32();
		    					if (usedExporterLabels.contains(Integer.valueOf(exporterLabel)) == false) {
		    						CBORObject innerArray = CBORObject.NewArray();
		    						int exporterOutputLength = paramValue.get(pair).get(1).AsInt32();
		    						innerArray.Add(exporterLabel);
		    						innerArray.Add(exporterOutputLength);
		    						revisedArray.Add(innerArray);
		    					}
		    				}
			    			redactedMap.Remove(paramLabel);
			    			if (revisedArray.size() != 0) {
			    				redactedMap.Add(paramLabel, revisedArray);
			    			}
			    		}
			    	}

		    	}
		    	
		    	// Add the redacted map to the redacted list
		    	redactedList.add(redactedMap);
				
			}
			
		}
		
		return redactedList;
		
	}
	
	/**
	 * Handle prescriptive information exchanged during the EDHOC session
	 * 
     * @param paramLabel  A CBOR object used as label to identify the EDHOC_Information parameter
 	 * @param paramValue  A CBOR object specifying the value of the EDHOC_Information parameter
 	 * @param messageNumber  The number of the incoming/outgoing EDHOC message that specifies the prescriptive information
 	 * @param direction  True if the EDHOC message is incoming, or false otherwise
 	 * @return  True if the prescriptive information is used in a consistent way, or false otherwise
	 */
	private boolean handlePrescriptiveParameters(CBORObject paramLabel, CBORObject paramValue, int messageNumber, boolean incoming) {
		
		HashMap<CBORObject, CBORObject> prescriptiveInfo;
		if (incoming == false) {
			prescriptiveInfo = prescriptiveInfoOutgoing;
		}
		else {
			prescriptiveInfo = prescriptiveInfoIncoming;
		}
		
		if (paramLabel.getType() == CBORType.Integer && paramLabel.AsInt32() == Constants.EDHOC_INFORMATION_MESSAGE_4) {
		
			if (paramValue.equals(CBORObject.True) == false && paramValue.equals(CBORObject.False) == false) {
				return false;
			}
			
			boolean success = true;
			
			// Check whether the prescriptive parameter message_4 is being used in a consistent way
			CBORObject foundObj = prescriptiveInfo.get(CBORObject.FromObject(Constants.EDHOC_INFORMATION_MESSAGE_4));
			if (foundObj == null) {
				// The parameter message_4 has not been found yet during the EDHOC session.
				// Hence, track this first use for future checks during the EDHOC session.
				prescriptiveInfo.put(CBORObject.FromObject(Constants.EDHOC_INFORMATION_MESSAGE_4), paramValue);
			}
			else {
				if (foundObj.equals(paramValue) == false) {
					// The parameter message_4 has been found multiple times during the EDHOC session,
					// but not always with the same value; hence, abort the EDHOC session
					success = false;
				}
				// Else, the parameter message_4 has been found multiple times during the EDHOC session,
				// but always with the same value; hence, continue the EDHOC session
			}
			
			if (messageNumber == Constants.EDHOC_MESSAGE_1) {
				return success;
			}
			
			if (messageNumber == Constants.EDHOC_MESSAGE_2 && incoming == true) {
				// The Initiator also verifies that the prescriptive parameter message_4 is used by the Responder in
				// a way that is consistent with any previous indication given by the Initiator in EDHOC message_1
				foundObj = prescriptiveInfoOutgoing.get(CBORObject.FromObject(Constants.EDHOC_INFORMATION_MESSAGE_4));
				if (foundObj != null) {
					if (foundObj.equals(paramValue) == false) {
						// The parameter message_4 has been found multiple times during the EDHOC session,
						// but not always with the same value; hence, abort the EDHOC session
						success = false;
					}
					// Else, the indications about the parameter message_4 from the Responder are not
					// contradicting the indications from the Initiator; hence, continue the EDHOC session
				}
			}

			return success;
			
		}
		
		if (paramLabel.getType() == CBORType.Integer && paramLabel.AsInt32() == Constants.EDHOC_INFORMATION_EXPORTER_OUT_LEN) {
			
			if (paramValue.getType() != CBORType.Array || paramValue.size() < 1) {
				return false;
			}
			
			// Check whether the prescriptive parameter exporter_out_len is being used in a consistent way
			CBORObject foundObj = prescriptiveInfo.get(CBORObject.FromObject(Constants.EDHOC_INFORMATION_EXPORTER_OUT_LEN));
			
			if (foundObj == null) {
				// The parameter exporter_out_en has not been found yet during the EDHOC session.
				// Hence, track this first use for future checks during the EDHOC session.
				foundObj = CBORObject.NewMap();
				prescriptiveInfo.put(CBORObject.FromObject(Constants.EDHOC_INFORMATION_EXPORTER_OUT_LEN), foundObj);
			}
							
			for (int i = 0; i < paramValue.size(); i++) {
				CBORObject innerArray = paramValue.get(i);
				if (innerArray.getType() != CBORType.Array || innerArray.size() != 2) {
					return false;
				}
				CBORObject exporterLabelAsCbor = innerArray.get(0);
				CBORObject exporterOutLenAsCbor = innerArray.get(1);
				if (exporterLabelAsCbor.getType() != CBORType.Integer || exporterOutLenAsCbor.getType() != CBORType.Integer) {
					return false;
				}
				if (exporterLabelAsCbor.AsInt32() < 0 || exporterOutLenAsCbor.AsInt32() < 0) {
					return false;
				}
				
				if (foundObj.get(exporterLabelAsCbor) == null) {
					// Exporter output lengths for a given exporter label have not been found yet during the EDHOC session,
					// but always with the same value; hence, continue the EDHOC session
					foundObj.Add(exporterLabelAsCbor, exporterOutLenAsCbor);
					
					// Update the Exporter output length to be used later in the EDHOC session
					boolean updateExporterOutputLength = true;
					if (messageNumber == Constants.EDHOC_MESSAGE_2 && incoming == false) {
						CBORObject initiatorObj = prescriptiveInfoIncoming.get(CBORObject.FromObject(
								   											   Constants.EDHOC_INFORMATION_EXPORTER_OUT_LEN));
						if (initiatorObj != null) {
							if (initiatorObj.ContainsKey(exporterLabelAsCbor)) {
								// If the Initiator indicated an output length for this Exporter Label, the Responder must
								// use that length; the length from the Responder is later going to be removed from ead_value
								updateExporterOutputLength = false;
							}
						}
					}
					
					if (updateExporterOutputLength == true) {
						appProfile.setExporterOutputLength(exporterLabelAsCbor.AsInt32Value(), exporterOutLenAsCbor.AsInt32());
					}
										
					continue;
				}
				else {						
					if (foundObj.get(exporterLabelAsCbor).AsInt32() != exporterOutLenAsCbor.AsInt32()) {
						// Exporter output lengths for a given exporter label have been found multiple times during
						// the EDHOC session, but not always with the same value; hence, abort the EDHOC session
						return false;
					}
					// Else, exporter output lengths for a given exporter label have been found multiple times
					// during the EDHOC session, but always with the same value; hence, continue the EDHOC session
					continue;
				}
			}

			if (messageNumber == Constants.EDHOC_MESSAGE_1) {
				return true;
			}
			
			if (messageNumber == Constants.EDHOC_MESSAGE_2 && incoming == true) {
				// The Initiator also verifies that the prescriptive parameter exporter_out_len is used by the Responder in
				// a way that is consistent with any previous indication given by the Initiator in EDHOC message_1
				foundObj = prescriptiveInfoOutgoing.get(CBORObject.FromObject(Constants.EDHOC_INFORMATION_EXPORTER_OUT_LEN));
				if (foundObj != null) {
					CBORObject responderObj = prescriptiveInfoIncoming.get(CBORObject.FromObject(
																		   Constants.EDHOC_INFORMATION_EXPORTER_OUT_LEN));
					if (responderObj != null) {
						for (CBORObject key : foundObj.getKeys()) {
							if (responderObj.ContainsKey(key)) {
								// If the Initiator indicated an output length for an Exporter Label, the Responder must not
								// indicate the same or a different output length for that Exporter label
								return false;
							}
						}
					}
					// Else, the indications about the parameter exporter_out_len from the Responder are not
					// contradicting the indications from the Initiator; hence, continue the EDHOC session
				}
			}

			return true;
		
		}
		
		return false;
		
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
 	 * @return  True in case of no error when processing any critical item, in order to continue the EDHOC session 
 	 *          False in case of error when processing any critical item, in order to abort the EDHOC session 
	 */
	public boolean eadConsumptionDispatcher(int messageNumber, boolean postValidation,
										    CBORObject[] sideProcessorInfo, CBORObject[] eadField) {
		
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
			
			HashMap<Integer, Integer> innerMap = new HashMap<Integer, Integer>();
			if (eadItemsOccurrences.containsKey(Integer.valueOf(eadLabel)) == false) {
				innerMap.put(Integer.valueOf(Constants.EDHOC_MESSAGE_1), Integer.valueOf(0));
				innerMap.put(Integer.valueOf(Constants.EDHOC_MESSAGE_2), Integer.valueOf(0));
				innerMap.put(Integer.valueOf(Constants.EDHOC_MESSAGE_3), Integer.valueOf(0));
				innerMap.put(Integer.valueOf(Constants.EDHOC_MESSAGE_4), Integer.valueOf(0));
				eadItemsOccurrences.put(Integer.valueOf(eadLabel), innerMap);
			}
			
			// This has to be populated with the invocation of the consume() method for the EAD item to produce
			switch(eadLabel) {
			
				 case Constants.EAD_LABEL_SUPPORTED_EDHOC_APP_PROF:
					 if (postValidation == false) {
						// This EAD item must not be present multiple times in the EAD field of EDHOC message_1
						// and message_2, while it is always silently ignored if present in the EAD field of
						// EDHOC message_3 of message_4
						if (messageNumber == Constants.EDHOC_MESSAGE_1 || messageNumber == Constants.EDHOC_MESSAGE_2) {
							if (eadItemsOccurrences.get(Integer.valueOf(eadLabel)).
								get(Integer.valueOf(messageNumber)) != Integer.valueOf(0)) {
								addErrorResult(messageNumber, postValidation,
											   "Error when processing the EAD item \"Supported EDHOC Application Profiles\""
											   + "in EDHOC message",
											   ResponseCode.BAD_REQUEST.value);
								return false;
							}
						}
						
						success = eadConsumeSupportedEdhocApplicationProfiles(critical, messageNumber, postValidation,
								                                              sideProcessorInfo, eadValue);
					 }
					 break;

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
			
			if (postValidation == false) {
				innerMap = eadItemsOccurrences.get(Integer.valueOf(eadLabel));
				int newValue = innerMap.get(Integer.valueOf(messageNumber)).intValue() + 1;
				innerMap.put(Integer.valueOf(messageNumber), Integer.valueOf(newValue));
			}
			
			if (success == false) {
				break;
			}
		}
		return success;
		
	}
	
	private boolean eadConsumeSupportedEdhocApplicationProfiles(boolean critical, int messageNumber, boolean postValidation,
												  				CBORObject[] sideProcessorInfo, byte[] eadValue) {
		if (critical == false || eadValue == null) {
			addErrorResult(messageNumber, postValidation,
						   "Error when processing the EAD item \"Supported EDHOC Application Profiles\" in EDHOC message",
						   ResponseCode.BAD_REQUEST.value);
			return false;
		}
		switch (messageNumber) {
			// This EAD item is intended only for message_1 and message_2. It is silently ignored otherwise.
			case Constants.EDHOC_MESSAGE_1:
			case Constants.EDHOC_MESSAGE_2:
				break;
			case Constants.EDHOC_MESSAGE_3:
			case Constants.EDHOC_MESSAGE_4:
				return true;
			default:
				addErrorResult(messageNumber, postValidation,
							   "Error when processing the EAD item \"Supported EDHOC application profiles\" in EDHOC message",
							   ResponseCode.BAD_REQUEST.value);
				return false;
		}
		
		System.out.println("\n@SideProcessor eadConsumeSupportedEdhocApplicationProfiles():");
		System.out.println("Supported EDHOC Application Profiles: " + CBORObject.FromObject(eadValue).toString() + "\n");
		
		boolean success = true;
				
		// Check ead_value
		
		CBORObject[] objectList = null;
		try {
			objectList = CBORObject.DecodeSequenceFromBytes(eadValue);
		}
		catch (Exception e) {
			addErrorResult(messageNumber, postValidation,
					   "Error when processing the EAD item \"Supported EDHOC Application Profiles\" in EDHOC message",
					   ResponseCode.BAD_REQUEST.value);
			return false;
		}
	
		CBORObject paramLabel = null;
		CBORObject paramValue = null;
		CBORObject profileObject = null;
		
		for (int i = 0; i < objectList.length; i++) {
			
			if (objectList[i].equals(CBORObject.True) == false && objectList[i].getType() != CBORType.Integer &&
				objectList[i].getType() != CBORType.Array && objectList[i].getType() != CBORType.Map) {
				success = false;
				break;
			}

			if (objectList[i].equals(CBORObject.True)) {
				
				if (i != 0 || messageNumber != Constants.EDHOC_MESSAGE_1) {
					success = false;
					break;
				}

				continue;
			}
			
			if (objectList[i].getType() == CBORType.Integer) {
				
				int profileId = objectList[i].AsInt32();
				profileObject = appProfileCatalogue.getAppProfileById(profileId);
	    		if (profileObject == null) {
	    			// Unknown EDHOC Application Profile
	    			continue;
	    		}

			}
			
			if (objectList[i].getType() == CBORType.Array) {
				
				if (objectList[i].size() < 2) {
					success = false;
					break;
				}
				
				for (int j = 0; j < objectList[i].size(); j++) {
					if (j == 0) {
						if (objectList[i].get(j).getType() != CBORType.Integer) {
							success = false;
							break;
						}
					}
					else if (objectList[i].get(j).getType() != CBORType.Integer || objectList[i].get(j).AsInt32() < 0) {
						success = false;
						break;
					}
				}
				
				int profileId = objectList[i].get(0).AsInt32();
				profileObject = appProfileCatalogue.getAppProfileById(profileId);
	    		if (profileObject == null) {
	    			// Unknown EDHOC Application Profile
	    			continue;
	    		}

			}
			
			if (objectList[i].getType() == CBORType.Map) {
				
				if (eadConsumeSupportedEdhocApplicationProfilesCheckMap(objectList[i], messageNumber, sideProcessorInfo) == false) {
					success = false;
					break;
				}
								
				profileObject = objectList[i];

			}
			
	    	// Check whether a prescriptive parameter is specified
	    	Iterator<Integer> paramIterator = prescriptiveParameters.iterator();
	    	while(paramIterator.hasNext()) {
	    		paramLabel = CBORObject.FromObject(paramIterator.next().intValue());
				paramValue = profileObject.get(paramLabel);
				
		    	if (paramValue == null) {
					continue;
				}
				if (handlePrescriptiveParameters(paramLabel, paramValue, messageNumber, true) == false) {
					success = false;
					break;
				}
	    	}

	    	if (success == false) {
	    		break;
	    	}
	    	
		}

		if (success == false) {
			addErrorResult(messageNumber, postValidation,
					   "Error when processing the EAD item \"Supported EDHOC Application Profiles\" in EDHOC message",
					   ResponseCode.BAD_REQUEST.value);
			return false;
		}
		
		// If this peer is the Responder and the Initiator has asked to advertise
		// the supported EDHOC application profiles, be sure to do so in EDHOC message_2
		if (messageNumber == Constants.EDHOC_MESSAGE_1 && appProfile.getAdvertiseAsResponder() == false) {
			if (objectList[0].equals(CBORObject.True)) {
				List <CBORObject> baselineList = new ArrayList<CBORObject>(appProfile.getAdvertisedAppProfiles());
				
				CBORObject nextValue;
				CBORObject input = CBORObject.NewMap();
				if (baselineList.isEmpty() == true) {
					List <CBORObject> dummyList = new ArrayList<CBORObject>();
					dummyList.add(CBORObject.NewMap());
					nextValue = CBORObject.FromObject(Util.buildCBORSequence(dummyList));
				}
				else {
					nextValue = CBORObject.FromObject(Util.buildCBORSequence(baselineList));
				}
				input.Add(Constants.EAD_ITEM_INPUT_SUPPORTED_EDHOC_APP_PROF_VALUE, nextValue);
				
				List<CBORObject> listMessage2 = new ArrayList<CBORObject>();
				listMessage2.add(CBORObject.FromObject(-1 * Constants.EAD_LABEL_SUPPORTED_EDHOC_APP_PROF));
				listMessage2.add(CBORObject.FromObject(input));
				eadProductionInput.put(Integer.valueOf(Constants.EDHOC_MESSAGE_2), listMessage2);
				
			}
		}
		
		// Prepare the result
		HashMap<Integer, CBORObject> results = new HashMap<Integer, CBORObject>();
		
		results.put(Constants.SIDE_PROCESSOR_INNER_SUPPORTED_EDHOC_APP_PROF_VALUE, CBORObject.FromObject(eadValue));
		
		addResult(messageNumber, postValidation, Constants.EAD_LABEL_SUPPORTED_EDHOC_APP_PROF, results);

		return success;
		
	}
	
	// Perform consistency checks on an EDHOC Information Object within the
	// EAD value of an incoming EAD item "Supported EDHOC Application Profiles"
	private boolean eadConsumeSupportedEdhocApplicationProfilesCheckMap(CBORObject object, int messageNumber,
																		CBORObject[] sideProcessorInfo) {
		
		for (CBORObject key : object.getKeys()) {
			if (key.getType() != CBORType.Integer &&
				key.getType() != CBORType.TextString) {
					return false;
			}
			if (key.AsInt32() == Constants.EDHOC_INFORMATION_SESSION_ID ||
				key.AsInt32() == Constants.EDHOC_INFORMATION_URI_PATH ||
				key.AsInt32() == Constants.EDHOC_INFORMATION_INITIATOR ||
				key.AsInt32() == Constants.EDHOC_INFORMATION_RESPONDER ||
				key.AsInt32() == Constants.EDHOC_INFORMATION_APP_PROF) {
				return false;
			}
			if (key.AsInt32() == Constants.EDHOC_INFORMATION_METHODS ||
				key.AsInt32() == Constants.EDHOC_INFORMATION_CIPHER_SUITES ||
				key.AsInt32() == Constants.EDHOC_INFORMATION_CRED_TYPES) {
				if (object.get(key).getType() != CBORType.Integer &&
					object.get(key).getType() != CBORType.Array) {
					return false;
				}
				if (object.get(key).getType() == CBORType.Array) {
					if (object.get(key).size() < 2) {
						return false;
					}
					for (int i = 0; i < object.get(key).size(); i++) {
						if (object.get(key).get(i).getType() != CBORType.Integer) {
							return false;
						}
					}
				}
			}
			if (key.AsInt32() == Constants.EDHOC_INFORMATION_ID_CRED_TYPES) {
				if (object.get(key).getType() != CBORType.Integer &&
					object.get(key).getType() != CBORType.TextString &&
					object.get(key).getType() != CBORType.Array) {
					return false;
				}
				if (object.get(key).getType() == CBORType.Array) {
					if (object.get(key).size() < 2) {
						return false;
					}
					for (int i = 0; i < object.get(key).size(); i++) {
						if (object.get(key).get(i).getType() != CBORType.Integer &&
							object.get(key).get(i).getType() != CBORType.TextString) {
							return false;
						}
					}
				}
			}
			if (key.AsInt32() == Constants.EDHOC_INFORMATION_MESSAGE_4 ||
				key.AsInt32() == Constants.EDHOC_INFORMATION_COMB_REQ ||
				key.AsInt32() == Constants.EDHOC_INFORMATION_PSK_RESUMPTION) {
				if (object.get(key).getType() != CBORType.Boolean) {
					return false;
				}
				if (key.AsInt32() == Constants.EDHOC_INFORMATION_MESSAGE_4) {
					boolean b = object.get(key).equals(CBORObject.True) ? true : false;
					if (b != appProfile.getUseMessage4()) {
						return false;
					}
				}
			}
			if (key.AsInt32() == Constants.EDHOC_INFORMATION_EADS) {
				if (object.get(key).getType() != CBORType.Integer &&
					object.get(key).getType() != CBORType.Array) {
					return false;
				}
				if (object.get(key).getType() == CBORType.Integer && object.get(key).AsInt32() < 0) {
					return false;
				}
				if (object.get(key).getType() == CBORType.Array) {
					if (object.get(key).size() < 2) {
						return false;
					}
					for (int i = 0; i < object.get(key).size(); i++) {
						if (object.get(key).get(i).getType() != CBORType.Integer ||
							object.get(key).AsInt32() < 0) {
							return false;
						}
					}
				}
			}
			if (key.AsInt32() == Constants.EDHOC_INFORMATION_TRUST_ANCHORS) {
				if (object.get(key).getType() != CBORType.Map) {
					return false;
				}
				if (object.get(key).size() < 1) {
					return false;
				}
				for (CBORObject outerKey : object.get(key).getKeys()) {
					if (outerKey.getType() != CBORType.Integer) {
						return false;
					}
					if (object.get(key).get(outerKey).getType() != CBORType.Map &&
						object.get(key).get(outerKey).getType() != CBORType.Array) {
						return false;
					}
					if (object.get(key).get(outerKey).getType() == CBORType.Map) {
						if (object.get(key).get(outerKey).size() != 1) {
							return false;
						}
						for (CBORObject innerKey : object.get(key).get(outerKey).getKeys()) {
							if (innerKey.getType() != CBORType.Integer && innerKey.getType() != CBORType.TextString) {
								return false;
							}
						}
					}
					if (object.get(key).get(outerKey).getType() == CBORType.Array) {
						if (object.get(key).get(outerKey).size() < 2) {
							return false;
						}
						for (int i = 0; i < object.get(key).get(outerKey).size(); i++) {
							if (object.get(key).get(outerKey).get(i).getType() != CBORType.Map) {
								return false;
							}
							if (object.get(key).get(outerKey).get(i).size() != 1) {
								return false;
							}
							for (CBORObject innerKey : object.get(key).get(outerKey).get(i).getKeys()) {
								if (innerKey.getType() != CBORType.Integer && innerKey.getType() != CBORType.TextString) {
									return false;
								}
							}
						}
					}
				}
			}
			
			if (key.AsInt32() == Constants.EDHOC_INFORMATION_EXPORTER_OUT_LEN) {
				if (object.get(key).getType() != CBORType.Array) {
					return false;
				}
				if (object.get(key).size() < 1) {
					return false;
				}
				for (int i = 0; i < object.get(key).size(); i++) {
					if (object.get(key).get(i).getType() != CBORType.Array) {
						return false;
					}
					if (object.get(key).get(i).size() != 2) {
						return false;
					}
					if (object.get(key).get(i).get(0).getType() != CBORType.Integer ||
						object.get(key).get(i).get(1).getType() != CBORType.Integer) {
						return false;
					}
					int exporterLabel = object.get(key).get(i).get(0).AsInt32();
					int indicatedLength = object.get(key).get(i).get(1).AsInt32();
					if (exporterLabel < 0 || indicatedLength < 0) {
						return false;
					}
					if (exporterLabel != Constants.EXPORTER_LABEL_OSCORE_MASTER_SECRET &&
						exporterLabel != Constants.EXPORTER_LABEL_OSCORE_MASTER_SALT) {
						return false;
					}
					if (exporterLabel == Constants.EXPORTER_LABEL_OSCORE_MASTER_SECRET) {
						int selectedCipherSuite = Constants.EDHOC_CIPHER_SUITE_23;
						if (messageNumber == Constants.EDHOC_MESSAGE_1) {
							int indexLast = sideProcessorInfo[1].size() - 1;
							selectedCipherSuite = sideProcessorInfo[1].get(indexLast).AsInt32();
						}
						if (messageNumber == Constants.EDHOC_MESSAGE_2) {
							selectedCipherSuite = session.getSelectedCipherSuite();
						}
						int defaultLength = EdhocSession.getKeyLengthAppAEAD(selectedCipherSuite);
						if (defaultLength == 0 || indicatedLength < defaultLength) {
							return false;
						}
					}
				}
			}
			
		}
		
		return true;
		
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
