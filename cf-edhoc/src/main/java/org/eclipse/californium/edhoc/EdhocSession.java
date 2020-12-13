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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import com.upokecenter.cbor.CBORObject;

public class EdhocSession {
	
	private boolean initiator;
	private int method;
	private int correlation;
	private byte[] connectionId;
	private OneKey longTermKey;
	private OneKey ephemeralKey;
	private List<Integer> supportedCiphersuites;
	
	private int currentStep;
	private int selectedCiphersuite;
	
	private byte[] peerConnectionId;
	private List<Integer> peerSupportedCiphersuites = null;
	private OneKey peerLongTermPublicKey = null;
	private OneKey peerEphemeralPublicKey = null;
	
	// Inner Key-Derivation Keys
	private byte[] prk_2e = null;
	private byte[] prk_3e2m = null;
	private byte[] prk_4x3m = null;
	
	// Transcript Hashes
	private byte[] TH2 = null;
	private byte[] TH3 = null;
	private byte[] TH4 = null;
	
	public EdhocSession(boolean initiator, int methodCorr, byte[] connectionId, OneKey ltk, List<Integer> cipherSuites) {
		
		this.initiator = initiator;
		this.method = methodCorr / 4;
		this.correlation = methodCorr % 4;
		this.connectionId = connectionId;
		this.longTermKey = ltk;
		this.supportedCiphersuites = cipherSuites;
		
		this.selectedCiphersuite = supportedCiphersuites.get(0); 
		if (this.selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_0 || this.selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_1)
				this.ephemeralKey = Util.generateKeyPair(KeyKeys.OKP_X25519.AsInt32());
		else if (this.selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_2 || this.selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_3)
			this.ephemeralKey = Util.generateKeyPair(KeyKeys.EC2_P256.AsInt32());
		
		currentStep = initiator ? Constants.EDHOC_BEFORE_M1 : Constants.EDHOC_BEFORE_M2;
		
	}
	
	/**
	 * @return  True if this peer is the initiator, or False otherwise 
	 */
	public boolean isInitiator() {
		return this.initiator;
	}
	
	/**
	 * @return  the authentication method of this peer 
	 */
	public int getMethod() {
		return this.method;
	}
	
	/**
	 * @return  the correlation method
	 */
	public int getCorrelation() {
		return this.correlation;
	}
	
	/**
	 * @return  the integer value combining the authentication method and correlation method
	 */
	public int getMethodCorr() {
		return (4 * this.method) + this.correlation;
	}
	
	/**
	 * @return  the Connection Identifier of this peer
	 */
	public byte[] getConnectionId() {
		return this.connectionId;
	}	
	
	/**
	 * @return  the long-term key pair of this peer 
	 */
	public OneKey getLongTermKey() {
		
		return this.longTermKey;
		
	}
	
	/**
	 * @param ek  the ephemeral key pair of this peer 
	 */
	public void setEphemeralKey(OneKey ek) {
		
		this.ephemeralKey = ek;
		
	}
	
	/**
	 * @return  the ephemeral key pair of this peer 
	 */
	public OneKey getEphemeralKey() {
		
		return this.ephemeralKey;
		
	}
	
	/**
	 * @param cipherSuites  the supported ciphersuites to indicate in EDHOC messages
	 */
	public void setSupportedCipherSuites(List<Integer> cipherSuites) {

		this.supportedCiphersuites = cipherSuites;
		
	}
	
	/**
	 * @return  the supported ciphersuites to indicate in EDHOC messages
	 */
	public List<Integer> getSupportedCipherSuites() {

		return this.supportedCiphersuites;
		
	}
	
	/**
	 * Set the current step in the execution of the EDHOC protocol
	 * @param newStep   the new step to set 
	 */
	public void setCurrentStep(int newStep) {
		this.currentStep = newStep;
	}
	
	/**
	 * @return  the current step in the execution of the EDHOC protocol 
	 */
	public int getCurrentStep() {
		return this.currentStep;
	}

	/**
	 * Set the selected ciphersuite for this EDHOC session
	 * @param cipherSuite   the selected ciphersuite 
	 */
	public void setSelectedCiphersuite(int ciphersuite) {
		this.selectedCiphersuite = ciphersuite;
	}

	/**
	 * @return  the selected ciphersuite for this EDHOC session 
	 */
	public int getSelectedCiphersuite() {
		return this.selectedCiphersuite;
	}
	
	/**
	 * Set the Connection Identifier of the other peer
	 * @param peerId   the Connection Id of the other peer
	 */
	public void setPeerConnectionId(byte[] peerId) {
		this.peerConnectionId = peerId;
	}

	/**
	 * @return  the Connection Identifier of the other peer
	 */
	public byte[] getPeerConnectionId() {
		return this.peerConnectionId;
	}
	
	/**
	 * Set the list of the ciphersuites supported by the peer
	 * @param peerSupportedCiphersuites   the list of the ciphersuites supported by the peer
	 */
	public void setPeerSupportedCipherSuites(List<Integer> peerSupportedCiphersuites) {
		this.peerSupportedCiphersuites = peerSupportedCiphersuites;
	}

	/**
	 * @return  the list of the ciphersuites supported by the peer
	 */
	public List<Integer> getPeerSupportedCipherSuites() {
		return this.peerSupportedCiphersuites;
	}
	
	/**
	 * Set the long-term public key of the other peer
	 * @param peerKey   the long-term public key of the other peer 
	 */
	public void setPeerLongTermPublicKey(OneKey peerKey) {
		this.peerLongTermPublicKey = peerKey;
	}

	/**
	 * @return  the long-term public key of the other peer
	 */
	public OneKey getPeerLongTermPublicKey() {
		return this.peerLongTermPublicKey;
	}

	/**
	 * Set the ephemeral public key of the other peer
	 * @param peerKey   the ephemeral public key of the other peer 
	 */
	public void setPeerEphemeralPublicKey(OneKey peerKey) {
		this.peerEphemeralPublicKey = peerKey;
	}

	/**
	 * @return  the ephemeral public key of the other peer
	 */
	public OneKey getPeerEphemeralPublicKey() {
		return this.peerEphemeralPublicKey;
	}
	
	/**
	 * Set the inner key PRK2e
	 * @param inputKey   the inner key PRK2e
	 */
	public void setPRK2e(byte[] inputKey) {
		this.prk_2e = inputKey;
	}
	
	/**
	 * @return  the inner key PRK2e
	 */
	public byte[] getPRK2e() {
		return this.prk_2e;
	}

	/**
	 * Set the inner key PRK3e2m
	 * @param inputKey   the inner key PRK3e2m
	 */
	public void setPRK3e2m(byte[] inputKey) {
		this.prk_3e2m = inputKey;
	}

	/**
	 * @return  the inner key PRK3e2m
	 */
	public byte[] getPRK3e2m() {
		return this.prk_3e2m;
	}
	
	/**
	 * Set the inner key PRK4x3m
	 * @param inputKey   the inner key PRK4x3m
	 */
	public void setPRK4x3m(byte[] inputKey) {
		this.prk_4x3m = inputKey;
	}
	
	/**
	 * @return  the inner key PRK4x3m
	 */
	public byte[] getPRK4x3m() {
		return this.prk_4x3m;
	}
	
	/**
	 * Set the Transcript Hash TH2 
	 * @param inputTH   the Transcript Hash TH2
	 */
	public void setTH2(byte[] inputTH) {
		this.TH2 = inputTH;
	}
	
	/**
	 * @return  the Transcript Hash TH2
	 */
	public byte[] getTH2() {
		return this.TH2;
	}
	
	/**
	 * Set the Transcript Hash TH3 
	 * @param inputTH   the Transcript Hash TH3
	 */
	public void setTH3(byte[] inputTH) {
		this.TH3 = inputTH;
	}
	
	/**
	 * @return  the Transcript Hash TH3
	 */
	public byte[] getTH3() {
		return this.TH3;
	}
	
	/**
	 * Set the Transcript Hash TH4
	 * @param inputTH   the Transcript Hash TH4
	 */
	public void setTH4(byte[] inputTH) {
		this.TH4 = inputTH;
	}
	
	/**
	 * @return  the Transcript Hash TH4
	 */
	public byte[] getTH4() {
		return this.TH4;
	}
	
	/**
	 * EDHOC-Exporter interface
	 * @param label   The label to use to derive the OKM
	 * @param len   The intended length of the OKM to derive, in bytes
	 * @return  the application key, or null if the EDHOC execution is not completed yet
	 */
	public byte[] edhocExporter(String label, int len) throws InvalidKeyException, NoSuchAlgorithmException {
		
		if (this.currentStep != Constants.EDHOC_AFTER_M3)
			return null;
		
		return edhocKDF(this.prk_4x3m, this.TH4, label, len);
		
	}
	
	/**
	 * EDHOC-specific version of KDF, building the 'info' parameter of HKDF-Expand from a transcript_hash and a label
	 * @param prk   The Pseudo Random Key
	 * @param transcript_hash   The transcript hash
	 * @param label   The label to use to derive the OKM
	 * @param len   The intended length of the OKM to derive, in bytes
	 * @return  the OKM generated by HKDF-Expand
	 */
	private byte[] edhocKDF(byte[] prk, byte[] transcript_hash, String label, int len) 
			throws InvalidKeyException, NoSuchAlgorithmException {
		
		int edhoc_aead_id;
		
		if(selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_0 || selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_2)
			edhoc_aead_id = 10; // AES-CCM-16-64-128
		else if(selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_1 || selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_3)
			edhoc_aead_id = 30; // AES-CCM-16-128-128
		else
			return null;
		
		CBORObject infoArray = CBORObject.NewArray();
		
		infoArray.Add(edhoc_aead_id);
		infoArray.Add(transcript_hash);
		infoArray.Add(label);
		infoArray.Add(len);
		
		byte[] info = infoArray.EncodeToBytes();
		
		return Hkdf.expand(prk, info, len);
		
	}

}


