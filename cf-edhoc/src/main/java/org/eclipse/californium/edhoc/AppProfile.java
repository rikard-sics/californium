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

import java.util.HashSet;
import java.util.Set;

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
	
	public AppProfile(Set<Integer> authMethods, boolean useMessage4, boolean usedForOSCORE, boolean supportCombinedRequest) {
		
		this.authMethods = authMethods;
		this.useMessage4 = useMessage4;
		this.usedForOSCORE = usedForOSCORE;
		this.supportCombinedRequest = supportCombinedRequest;
		
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
	
}
