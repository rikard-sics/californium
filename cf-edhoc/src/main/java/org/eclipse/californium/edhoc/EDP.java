package org.eclipse.californium.edhoc;

import com.upokecenter.cbor.CBORObject;

/*
 * An interface to process External Authorization Data
 */

public interface EDP {
	
	// Process the External Authorization Data EAD_1 from EDHOC message_1
	public abstract void processEAD1(CBORObject[] ead1);
	
	// Process the External Authorization Data EAD_2 from EDHOC message_2
	public abstract void processEAD2(CBORObject[] ead2);
	
	// Process the External Authorization Data EAD_3 from EDHOC message_3
	public abstract void processEAD3(CBORObject[] ead3);
	
	// Perform common consistency checks on the External Authorization Data
	public abstract boolean consistencyCheck(CBORObject[] ead);
	
}
