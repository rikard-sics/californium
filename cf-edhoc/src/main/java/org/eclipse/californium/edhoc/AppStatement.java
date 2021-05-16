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

public class AppStatement {

	// Supported correlation
	// True if correlation 1 or 2 have to be used
	// False if correlation 0 has to be used 
	boolean correlation;
	
	// Supported authentication methods
	Set<Integer> authMethods = new HashSet<Integer>();
	
	// Set to true if the CBOR simple value Null (i.e., the 0xf6 byte) has to be used as first element of message_1
	private boolean useNullByte;
	
	// Set to true if message_4 has to be sent by the Responder
	private boolean useMessage4;
	
	public AppStatement(boolean correlation, Set<Integer> authMethods, boolean useNullByte, boolean useMessage4) {
		
		this.correlation = correlation;
		this.authMethods = authMethods;
		this.useNullByte = useNullByte;
		this.useMessage4 = useMessage4;
		
	}

	public boolean getCorrelation() {
		
		return correlation;
		
	}
	
	public boolean isAuthMethodSupported(int method) {
		
		return authMethods.contains(method);
		
	}
	
	public boolean getUseNullByte() {
		
		return useNullByte;
		
	}
	
	public boolean getUseMessage4() {
		
		return this.useMessage4;
		
	}
		
}
