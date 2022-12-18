package org.eclipse.californium.edhoc;

import java.util.HashMap;

import com.upokecenter.cbor.CBORObject;

/*
 * An interface External Authorization Data items
 */

public interface EAD {

	/**
	 * @param critical  True if the EAD item has to be produced as critical, or false otherwise
 	 * @param messageNumber  The number of the next, outgoing EDHOC message that will include the produced EAD item
 	 * @param input  A CBOR map providing input on how to produce the EAD item. The map keys belong to a namespace specific of the ead_label. 
	 * @return  The returned CBOR array includes either:
	 *            i) Only a CBOR integer as ead_label of the produced EAD item, in case this has no ead_value;
	 *           ii) A CBOR integer as ead_label of the produced EAD item,
	 *               followed by a CBOR byte string as its ead_value;
	 *          iii) A CBOR text string with the description of an occurred fatal error,
	 *               followed by a CBOR integer specifying the CoAP error response code.
	 */
	public abstract CBORObject[] produce(boolean critical, int messageNumber, CBORObject productionInput);
	
	/**
	 * @param critical  True if the EAD item has to be processed as critical, or false otherwise
 	 * @param messageNumber  The number of the incoming EDHOC message including the EAD item to process
 	 * @param eadValue  The ead_value of the EAD item to process, or null if the ead_value is not present
	 * @return  The results of the EAD item consumption, organized as follows.
	 *          The outer map has key either -1 in case of fatal error, or 0 in case of success.
	 *          In the former case, the inner map specifies the error description as a
	 *          CBOR text string, and the CoAP error response code as a CBOR integer.
	 *          In the later case, the inner map specifies the individual information elements related
	 *          to the EAD consumption result; the map keys belong to a namespace specific of the ead_label. 
	 */
	public abstract HashMap<Integer, HashMap<Integer, CBORObject>> consume(boolean critical, int messageNumber, CBORObject eadValue);
	
}
