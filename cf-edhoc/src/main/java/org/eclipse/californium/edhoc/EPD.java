package org.eclipse.californium.edhoc;

/*
 * An interface to process External Authorization Data
 */

public interface EPD {
	
	// Process the External Authorization Data EAD_1 from EDHOC message_1
	public abstract void processEAD1(byte[] ead1);
	
	// Process the External Authorization Data EAD_2 from EDHOC message_2
	public abstract void processEAD2(byte[] ead2);
	
	// Process the External Authorization Data EAD_3 from EDHOC message_3
	public abstract void processEAD3(byte[] ead3);
	
}
