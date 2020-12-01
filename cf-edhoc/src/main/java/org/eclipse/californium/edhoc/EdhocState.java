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
	
	boolean initiator;
	int method;
	int correlation;
	int currentStep;
	OneKey longTermKey;
	OneKey ephemeralKey;
	List<Integer> supportedCiphersuites;

	int ciphersuite;
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
		
	public EdhocState(boolean initiator, int methodCorr, OneKey ltk, OneKey ek, List<Integer> ciphersuites) {
		
		this.initiator = initiator;
		this.method = methodCorr / 4;
		this.correlation = methodCorr % 4;
		currentStep = initiator ? Constants.EDHOC_BEFORE_M1 : Constants.EDHOC_BEFORE_M2;
		this.longTermKey = ltk;
		this.ephemeralKey = ek;
		this.supportedCiphersuites = ciphersuites;
		
	}
	
	public boolean isInitiator() {
		return this.initiator;
	}
	
	public int getMethod() {
		return this.method;
	}
	
	public int getCorrelation() {
		return this.correlation;
	}
	
	public void setCurrentStep(int newStep) {
		this.currentStep = newStep;
	}
	
	public int getCurrentStep() {
		return this.currentStep;
	}

	public void setCiphersuite(int ciphersuite) {
		this.ciphersuite = ciphersuite;
	}
	
	public int getCiphersuite() {
		return this.ciphersuite;
	}
	
	public void setPeerLongTermPublicKey(OneKey peerKey) {
		this.peerLongTermPublicKey = peerKey;
	}
	
	public OneKey getPeerLongTermPublicKey() {
		return this.peerLongTermPublicKey;
	}
	
	public void setPeerEphemeralPublicKey(OneKey peerKey) {
		this.peerEphemeralPublicKey = peerKey;
	}
	
	public OneKey getPeerEphemeralPublicKey() {
		return this.peerEphemeralPublicKey;
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
