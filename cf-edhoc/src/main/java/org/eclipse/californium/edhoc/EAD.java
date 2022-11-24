package org.eclipse.californium.edhoc;

import java.util.HashMap;

import com.upokecenter.cbor.CBORObject;

/*
 * An interface External Authorization Data items
 */

public interface EAD {
	
	// Information to produce the EAD item is provided in the 'input' parameter.
	// 
	// The returned array includes no elements in case of error. Otherwise, it includes
	// the ead_label as first element and, optionally, ead_value as second element.
	public abstract CBORObject[] produce(CBORObject[] input);
	
	
	// The EAD item to consume is provided in the 'ead' parameter, with its ead_label
	// as first element and, optionally, its ead_value as second element.
	// 
	// The results of the processing are written in the 'results' parameter 
	public abstract void consume(CBORObject[] ead, HashMap<Integer, CBORObject> results);
	
}
