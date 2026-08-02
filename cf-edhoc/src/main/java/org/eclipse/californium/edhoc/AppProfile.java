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
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/

package org.eclipse.californium.edhoc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

public class AppProfile {

	// Supported authentication methods
	Set<Integer> authMethods = new HashSet<Integer>();
		
	// Set to true if message_4 has to be sent by the Responder
	private boolean useMessage4;
	
	// Set to true if used for keying OSCORE
	private boolean usedForOSCORE;
	
	// Set to true if supporting the EDHOC+OSCORE request
	// If set to true, it implies conversionMethodOscoreToEdhoc equal to CONVERSION_ID_CORE (1)
	private boolean supportCombinedRequest;

	// The complete advertisement of supported EDHOC application profiles
	//
	// Each element of the list is a CBOR object composing the CBOR sequence APP_PROF_SEQ
	private List <CBORObject> advertisedAppProfiles = new ArrayList<CBORObject>();

	// Set to true if this peer acting as Initiator will advertise its application profiles
	private boolean advertiseAsInitiator;

	// Set to true if this peer acting as Responder will advertise its application profiles
	private boolean advertiseAsResponder;

	// Set to true if this peer acting as Initiator will ask the other peer
	// acting as Responder to advertise its application profiles
	private boolean askResponderToAdvertise;

	// The following data structure specifies the output lengths to consider when using EDHOC Exporter
	//
	// The map key is an Exporter label
	// The map value is the output length (in bytes) for that Exporter label; if the indicated output length is -1,
	// the actual output length is a default value to be determined at runtime
	private HashMap<Integer, Integer> exporterOutputLengths = new HashMap<>();
	
	public AppProfile(Set<Integer> authMethods, boolean useMessage4, boolean usedForOSCORE, boolean supportCombinedRequest,
			          List <CBORObject> advertisedAppProfiles, boolean advertiseAsInitiator, boolean advertiseAsResponder,
			          boolean askResponderToAdvertise) {
		
		this.authMethods = authMethods;
		this.useMessage4 = useMessage4;
		this.usedForOSCORE = usedForOSCORE;
		this.supportCombinedRequest = supportCombinedRequest;
		
		this.advertisedAppProfiles = advertisedAppProfiles;
		this.advertiseAsInitiator = advertiseAsInitiator;
		this.advertiseAsResponder = advertiseAsResponder;
		this.askResponderToAdvertise = askResponderToAdvertise;
		
		this.exporterOutputLengths.put(Integer.valueOf(Constants.EXPORTER_LABEL_OSCORE_MASTER_SECRET), -1);
		this.exporterOutputLengths.put(Integer.valueOf(Constants.EXPORTER_LABEL_OSCORE_MASTER_SALT), 8);
		
	}
	
	public boolean isAuthMethodSupported(int method) {
		return authMethods.contains(method);
	}
	
	public boolean getUseMessage4() {
		return this.useMessage4;
	}
	
	public boolean getUsedForOSCORE() {
		return this.usedForOSCORE;
	}
	
	public boolean getSupportCombinedRequest() {
		return this.supportCombinedRequest;
	}
	
	public List<CBORObject> getAdvertisedAppProfiles() {
		return this.advertisedAppProfiles;
	}
	
	public boolean getAdvertiseAsInitiator() {
		return this.advertiseAsInitiator;
	}
	
	public boolean getAdvertiseAsResponder() {
		return this.advertiseAsResponder;
	}
	
	public boolean getAskResponderToAdvertise() {
		return this.askResponderToAdvertise;
	}
	
	// The returned value x is such that:
	//
	// * x >= 0, if x is the exporter output length to use
	// * x = -1, if the default value use has to be determined at runtime
	// * x = -2, if no exporter output length is found for the specified Exporter label
	public int getExporterOutputLength(int exporterLabel) {
		Integer length = exporterOutputLengths.get(Integer.valueOf(exporterLabel));
		if (length == null) {
			return -2;
		}
		return length.intValue();
	}
	
	public void setExporterOutputLength(int exporterLabel, int exporterOutputLength) {
		if (exporterOutputLengths.get(Integer.valueOf(exporterLabel)) != null) {
			exporterOutputLengths.put(Integer.valueOf(exporterLabel), Integer.valueOf(exporterOutputLength));
		}
	}
	
}
