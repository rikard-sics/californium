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
		if (!consistencyCheck(ead1)) {
			System.out.println("Malformed or invalid EAD1");
		}
		
		int eadType = ead1[0].AsInt32();
		System.out.println("EAD1 has type: " + eadType + "\n");
	}
	
	// Process the External Authorization Data EAD_2 from EDHOC message_2
	@Override
	public void processEAD2(CBORObject[] ead2) {

		System.out.println("Entered processEAD2()");
		if (!consistencyCheck(ead2)) {
			System.out.println("Malformed or invalid EAD2");
		}
		
		int eadType = ead2[0].AsInt32();
		System.out.println("EAD2 has type: " + eadType + "\n");
	}
	
	// Process the External Authorization Data EAD_3 from EDHOC message_3
	@Override
	public void processEAD3(CBORObject[] ead3) {

		System.out.println("Entered processEAD3()");
		if (!consistencyCheck(ead3)) {
			System.out.println("Malformed or invalid EAD3");
		}
		
		int eadType = ead3[0].AsInt32();
		System.out.println("EAD3 has type: " + eadType + "\n");
	}
	
	// Perform common consistency checks on the External Authorization Data
	@Override
	public boolean consistencyCheck(CBORObject[] ead) {
		
		boolean ret = true;
		
		if (ead.length < 2) {
			ret = false;
		}
		if (ead[0].getType() != CBORType.Integer) {
			ret = false;
		}

		return ret;
		
	}
	
}
