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

import java.util.List;

import org.eclipse.californium.cose.OneKey;

public class EdhocState {

	List<Integer> supportedCiphersuites;
	
	boolean initiator;
	int currentStep;
	int ciphersuite;
	
	int authenticationMethod;
	int correlationMethod;
	OneKey longTermKey;
	OneKey ephemeralKey;
	
	int peerAuthenticationMethod;
	OneKey peerLongTermPublicKey;
	OneKey peerEphemeralPublicKey;
	
	// Inner Key-Derivation Keys
	byte[] prk_2e = null;
	byte[] prk_3e2m = null;
	byte[] prk_4x3m = null;
	
	// Transcript Hashes
	byte[] TH2 = null;
	byte[] TH3 = null;
	byte[] TH4 = null;
	
	
	public EdhocState(boolean initiator, List<Integer> ciphersuites, int auth, int corr, OneKey ltk, OneKey ek) {
		
		this.supportedCiphersuites = ciphersuites;
		
		if(initiator)
			currentStep = Constants.EDHOC_BEFORE_M1;
		else
			currentStep = Constants.EDHOC_BEFORE_M2;
		
		this.authenticationMethod = auth;
		this.correlationMethod = corr;
		
		this.longTermKey = ltk;
		this.ephemeralKey = ek;
		
	}
	
	public void setCiphersuite(int ciphersuite) {
		this.ciphersuite = ciphersuite;
	}
	
	public int getCiphersuite() {
		return this.ciphersuite;
	}
	
	public void setPRK2e(byte[] inputKey) {
		this.prk_2e = inputKey;
	}
	
	public byte[] getPRK2e() {
		return this.prk_2e;
	}
	
	public void setPRK3e2m(byte[] inputKey) {
		this.prk_3e2m = inputKey;
	}
	
	public byte[] getPRK3e2m() {
		return this.prk_3e2m;
	}
	
	public void setPRK4x3m(byte[] inputKey) {
		this.prk_4x3m = inputKey;
	}
	
	public byte[] getPRK4x3m() {
		return this.prk_4x3m;
	}
	
	public void setTH2(byte[] inputTH) {
		this.TH2 = inputTH;
	}
	
	public byte[] getTH2() {
		return this.TH2;
	}
	
	public void setTH3(byte[] inputTH) {
		this.TH3 = inputTH;
	}
	
	public byte[] getTH3() {
		return this.TH3;
	}
	
	public void setTH4(byte[] inputTH) {
		this.TH4 = inputTH;
	}
	
	public byte[] getTH4() {
		return this.TH4;
	}

}
