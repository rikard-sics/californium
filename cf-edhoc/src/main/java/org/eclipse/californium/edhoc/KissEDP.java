package org.eclipse.californium.edhoc;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/*
 * A simple processor of External Authorization Data, for testing purpose
 * 
 */

public class KissEDP implements EDP {

	// Process the External Authorization Data EAD_1 from EDHOC message_1
	@Override
	public void processEAD1(CBORObject[] ead1) {

		System.out.println("Entered processEAD1()");
		
		overviewEAD(ead1);
	}
	
	// Process the External Authorization Data EAD_2 from EDHOC message_2
	@Override
	public void processEAD2(CBORObject[] ead2) {

		System.out.println("Entered processEAD2()");

		overviewEAD(ead2);
	}
	
	// Process the External Authorization Data EAD_3 from EDHOC message_3
	@Override
	public void processEAD3(CBORObject[] ead3) {

		System.out.println("Entered processEAD3()");
		
		overviewEAD(ead3);
	}
	
	// Process the External Authorization Data EAD_4 from EDHOC message_4
	@Override
	public void processEAD4(CBORObject[] ead4) {

		System.out.println("Entered processEAD4()");
		
		overviewEAD(ead4);
	}
	
	// Print a generic overview of External Authorization Data from an EDHOC message
	private void overviewEAD(CBORObject[] ead) {
		
		System.out.println("EAD overview\n");
		
		for (int i = 0; i < ead.length; i++) {
			
			// This element must be an integer indicating the EAD Label
			if (i % 2 == 0) {
				if (ead[i].getType() != CBORType.Integer) {
					System.out.println("Malformed or invalid data item #" + (i/2));
					i += 2; // skip the companion data element
					continue;
				}
				System.out.println("The data item #" + (i/2) + " has EAD Label " + ead[i].AsInt32());
			}
			
			// This element includes the actual EAD Value according to the specified EAD Label
			if (i % 2 == 1) {
				Util.nicePrint("The data item #" + (i/2) + " has Value ", ead[i].GetByteString());
			}
			
		}

		System.out.println("\n");
	}
	
}
