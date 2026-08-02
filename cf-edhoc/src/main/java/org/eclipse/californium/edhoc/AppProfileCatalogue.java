/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Marco Tiloca (RISE)
 *    
 ******************************************************************************/

package org.eclipse.californium.edhoc;

import java.util.HashMap;
import com.upokecenter.cbor.CBORObject;

public class AppProfileCatalogue {

	// Catalogue of EDHOC application profiles identified by the respective Profile ID
	// 
	// The map label is the Profile ID of the EDHOC application profile stored in the map entry
	// The map value is a CBOR map, i.e., the EDHOC Application Profile Object
	//     specifying the EDHOC application profile stores in the map entry
	public static HashMap<Integer, CBORObject> catalogue = new HashMap<Integer, CBORObject>();
	
	public AppProfileCatalogue() {
		buildCatalogue();
	}
	
	public CBORObject getAppProfileById(int profileId) {
		return catalogue.get(Integer.valueOf(profileId));
	}
	
	private void buildCatalogue() {
		
		CBORObject myMap;
		CBORObject myArray;
		
		// Application Profile MINIMAL-CS-2
		myMap = CBORObject.NewMap();
		myMap.Add(Constants.EDHOC_INFORMATION_METHODS, Constants.EDHOC_AUTH_METHOD_3);
		myMap.Add(Constants.EDHOC_INFORMATION_CIPHER_SUITES, Constants.EDHOC_CIPHER_SUITE_2);
		myMap.Add(Constants.EDHOC_INFORMATION_CRED_TYPES, Constants.CRED_TYPE_CCS);
		myMap.Add(Constants.EDHOC_INFORMATION_ID_CRED_TYPES, Constants.COSE_HEADER_PARAM_KID);
		myMap.Add(Constants.EDHOC_INFORMATION_APP_PROF, Constants.APPLICATION_PROFILE_MINIMAL_CS_2);
		catalogue.put(Integer.valueOf(Constants.APPLICATION_PROFILE_MINIMAL_CS_2), myMap);
		
		// Application Profile MINIMAL-CS-0
		myMap = CBORObject.NewMap();
		myMap.Add(Constants.EDHOC_INFORMATION_METHODS, Constants.EDHOC_AUTH_METHOD_3);
		myMap.Add(Constants.EDHOC_INFORMATION_CIPHER_SUITES, Constants.EDHOC_CIPHER_SUITE_0);
		myMap.Add(Constants.EDHOC_INFORMATION_CRED_TYPES, Constants.CRED_TYPE_CCS);
		myMap.Add(Constants.EDHOC_INFORMATION_ID_CRED_TYPES, Constants.COSE_HEADER_PARAM_KID);
		myMap.Add(Constants.EDHOC_INFORMATION_APP_PROF, Constants.APPLICATION_PROFILE_MINIMAL_CS_0);
		catalogue.put(Integer.valueOf(Constants.APPLICATION_PROFILE_MINIMAL_CS_0), myMap);
		
		// Application Profile BASIC-CS-2-X509
		myMap = CBORObject.NewMap();
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_0));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_3));
		myMap.Add(Constants.EDHOC_INFORMATION_METHODS, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_CIPHER_SUITES, Constants.EDHOC_CIPHER_SUITE_2);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_CCS));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_X509));
		myMap.Add(Constants.EDHOC_INFORMATION_CRED_TYPES, myArray);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KID));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5T));
		myMap.Add(Constants.EDHOC_INFORMATION_ID_CRED_TYPES, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_APP_PROF, Constants.APPLICATION_PROFILE_BASIC_CS_2_X509);
		catalogue.put(Integer.valueOf(Constants.APPLICATION_PROFILE_BASIC_CS_2_X509), myMap);
		
		// Application Profile BASIC-CS-0-X509
		myMap = CBORObject.NewMap();
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_0));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_3));
		myMap.Add(Constants.EDHOC_INFORMATION_METHODS, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_CIPHER_SUITES, Constants.EDHOC_CIPHER_SUITE_0);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_CCS));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_X509));
		myMap.Add(Constants.EDHOC_INFORMATION_CRED_TYPES, myArray);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KID));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5T));
		myMap.Add(Constants.EDHOC_INFORMATION_ID_CRED_TYPES, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_APP_PROF, Constants.APPLICATION_PROFILE_BASIC_CS_0_X509);
		catalogue.put(Integer.valueOf(Constants.APPLICATION_PROFILE_BASIC_CS_0_X509), myMap);
		
		// Application Profile BASIC-CS-2-C509
		myMap = CBORObject.NewMap();
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_0));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_3));
		myMap.Add(Constants.EDHOC_INFORMATION_METHODS, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_CIPHER_SUITES, Constants.EDHOC_CIPHER_SUITE_2);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_CCS));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_C509));
		myMap.Add(Constants.EDHOC_INFORMATION_CRED_TYPES, myArray);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KID));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5T));
		myMap.Add(Constants.EDHOC_INFORMATION_ID_CRED_TYPES, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_APP_PROF, Constants.APPLICATION_PROFILE_BASIC_CS_2_C509);
		catalogue.put(Integer.valueOf(Constants.APPLICATION_PROFILE_BASIC_CS_2_C509), myMap);
		
		// Application Profile BASIC-CS-0-C509
		myMap = CBORObject.NewMap();
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_0));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_3));
		myMap.Add(Constants.EDHOC_INFORMATION_METHODS, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_CIPHER_SUITES, Constants.EDHOC_CIPHER_SUITE_0);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_CCS));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_C509));
		myMap.Add(Constants.EDHOC_INFORMATION_CRED_TYPES, myArray);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KID));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5T));
		myMap.Add(Constants.EDHOC_INFORMATION_ID_CRED_TYPES, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_APP_PROF, Constants.APPLICATION_PROFILE_BASIC_CS_0_C509);
		catalogue.put(Integer.valueOf(Constants.APPLICATION_PROFILE_BASIC_CS_0_C509), myMap);
		
		// Application Profile INTERMEDIATE-CS-2
		myMap = CBORObject.NewMap();
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_0));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_3));
		myMap.Add(Constants.EDHOC_INFORMATION_METHODS, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_CIPHER_SUITES, Constants.EDHOC_CIPHER_SUITE_2);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_CCS));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_X509));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_C509));
		myMap.Add(Constants.EDHOC_INFORMATION_CRED_TYPES, myArray);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KID));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5T));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5CHAIN));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5T));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5C));
		myMap.Add(Constants.EDHOC_INFORMATION_ID_CRED_TYPES, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_APP_PROF, Constants.APPLICATION_PROFILE_INTERMEDIATE_CS_2);
		catalogue.put(Integer.valueOf(Constants.APPLICATION_PROFILE_INTERMEDIATE_CS_2), myMap);
		
		// Application Profile INTERMEDIATE-CS-0
		myMap = CBORObject.NewMap();
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_0));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_3));
		myMap.Add(Constants.EDHOC_INFORMATION_METHODS, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_CIPHER_SUITES, Constants.EDHOC_CIPHER_SUITE_0);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_CCS));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_X509));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_C509));
		myMap.Add(Constants.EDHOC_INFORMATION_CRED_TYPES, myArray);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KID));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5T));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5CHAIN));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5T));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5C));
		myMap.Add(Constants.EDHOC_INFORMATION_ID_CRED_TYPES, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_APP_PROF, Constants.APPLICATION_PROFILE_INTERMEDIATE_CS_0);
		catalogue.put(Integer.valueOf(Constants.APPLICATION_PROFILE_INTERMEDIATE_CS_0), myMap);
		
		// Application Profile EXTENSIVE
		myMap = CBORObject.NewMap();
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_0));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_1));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_2));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_AUTH_METHOD_3));
		myMap.Add(Constants.EDHOC_INFORMATION_METHODS, myArray);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_CIPHER_SUITE_0));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_CIPHER_SUITE_1));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_CIPHER_SUITE_2));
		myArray.Add(CBORObject.FromObject(Constants.EDHOC_CIPHER_SUITE_3));
		myMap.Add(Constants.EDHOC_INFORMATION_CIPHER_SUITES, myArray);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_CCS));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_CWT));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_X509));
		myArray.Add(CBORObject.FromObject(Constants.CRED_TYPE_C509));
		myMap.Add(Constants.EDHOC_INFORMATION_CRED_TYPES, myArray);
		myArray = CBORObject.NewArray();
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KID));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCWT));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5T));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5CHAIN));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5T));
		myArray.Add(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5C));
		myMap.Add(Constants.EDHOC_INFORMATION_ID_CRED_TYPES, myArray);
		myMap.Add(Constants.EDHOC_INFORMATION_APP_PROF, Constants.APPLICATION_PROFILE_EXTENSIVE);
		catalogue.put(Integer.valueOf(Constants.APPLICATION_PROFILE_EXTENSIVE), myMap);
		
		// REMOVE WHEN DONE
		// System.out.println("\n\n" + catalogue.toString() + "\n\n\n");
		
	}
	
}
