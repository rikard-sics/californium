package org.eclipse.californium.edhoc;

/*
 * A simple processor of External Authorization Data, for testing purpose
 * 
 */

public class KissEDP implements EDP {

	// Process the External Authorization Data EAD_1 from EDHOC message_1
	@Override
	public void processEAD1(byte[] ead1) {
		// Do nothing
		System.out.println("Entered processEAD1()");
	}
	
	// Process the External Authorization Data EAD_2 from EDHOC message_2
	@Override
	public void processEAD2(byte[] ead2) {
		// Do nothing
		System.out.println("Entered processEAD2()");
	}
	
	// Process the External Authorization Data EAD_3 from EDHOC message_3
	@Override
	public void processEAD3(byte[] ead3) {
		// Do nothing
		System.out.println("Entered processEAD3()");
	}
	
}
