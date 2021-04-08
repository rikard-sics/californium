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

public class AppStatement {
	
	// Set to true if the Null byte has to be used as first element of message_1
	private boolean useNullByte;
	
	// Set to true if message_4 has to be sent by the Responder
	private boolean useMessage4;
	
	public AppStatement(boolean useNullByte, boolean useMessage4) {
		
		this.useNullByte = useNullByte;
		this.useMessage4 = useMessage4;
		
	}
	
	public boolean getUseNullByte() {
		
		return useNullByte;
		
	}
	
	public boolean getUseMessage4() {
		
		return this.useMessage4;
		
	}
		
}
