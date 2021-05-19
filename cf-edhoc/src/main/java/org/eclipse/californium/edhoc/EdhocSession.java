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

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import com.upokecenter.cbor.CBORObject;

public class EdhocSession {
	
	private boolean firstUse;
	
	private boolean initiator;
	private int method;
	private int correlation;
	private byte[] connectionId;
	private OneKey longTermKey;
	private CBORObject idCred;
	private byte[] cred; // This is the serialization of a CBOR object
	private OneKey ephemeralKey;
	private List<Integer> supportedCiphersuites;
	private AppStatement appStatement;
	
	// The processor to use for External Authorization Data.
	//
	// It is required to be also in the EDHOC session, to be accessible
	// also by the EDHOC layer, when receiving an EDHOC+OSCORE request
	// targeting a different resource than an EDHOC resource. 
	private EDP edp;
	
	private int currentStep;
	private int selectedCiphersuite;
	
	private byte[] peerConnectionId;
	private List<Integer> peerSupportedCiphersuites = null;
	private CBORObject peerIdCred = null;
	private OneKey peerLongTermPublicKey = null;
	private OneKey peerEphemeralPublicKey = null;
	
	// Stored EDHOC Message 1
	private byte[] message1 = null;
	
	// Stored CIPHERTEXT 2
	private byte[] ciphertext2 = null;
	
	// Inner Key-Derivation Keys
	private byte[] prk_2e = null;
	private byte[] prk_3e2m = null;
	private byte[] prk_4x3m = null;
	
	// Transcript Hashes
	private byte[] TH2 = null;
	private byte[] TH3 = null;
	private byte[] TH4 = null;
	
	// EDHOC message_3 , to be used for building an EDHOC+OSCORE request
	private byte[] message3 = null;
	
	public EdhocSession(boolean initiator, int methodCorr, byte[] connectionId, OneKey ltk,
						CBORObject idCred, byte[] cred, List<Integer> cipherSuites,
						AppStatement appStatement, EDP edp) {
		
		this.firstUse = true;
		
		this.initiator = initiator;
		this.method = methodCorr / 4;
		this.correlation = methodCorr % 4;
		this.connectionId = connectionId;
		this.longTermKey = ltk;
		this.idCred = idCred;
		this.cred = cred;
		this.supportedCiphersuites = cipherSuites;
		this.appStatement = appStatement;
		this.edp = edp;
		
		this.selectedCiphersuite = supportedCiphersuites.get(0);		
		setEphemeralKey();
		
		this.peerConnectionId = null;
		
		currentStep = initiator ? Constants.EDHOC_BEFORE_M1 : Constants.EDHOC_BEFORE_M2;
		
	}
	
	/**
	 * Delete all ephemeral keys and other temporary material used during the session
	 */
	public void deleteTemporaryMaterial() {
		
		this.ephemeralKey = null;
		this.peerEphemeralPublicKey = null;
		this.prk_2e = null;
		this.prk_3e2m = null;
		this.TH2 = null;
		this.TH3 = null;
		
	}
	
	/**
	 */
	public void setAsUsed() {
		this.firstUse = false;
	}

	/**
	 * @return  True if this is the first use of this session, or false otherwise 
	 */
	public boolean getFirstUse() {
		return this.firstUse;
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
	 * @return  the correlation
	 */
	public int getCorrelation() {
		return this.correlation;
	}
	
	/**
	 * @return  the integer value combining the authentication method and correlation
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
	 * @return  the ID_CRED for the long term key of this peer  
	 */
	public CBORObject getIdCred() {
		
		return this.idCred;
		
	}
	
	/**
	 * @return  the CRED for the long term key of this peer  
	 */
	public byte[] getCred() {
		
		return this.cred;
		
	}
	
	/**
	 * @param ek  the ephemeral key pair of this peer 
	 */
	public void setEphemeralKey(OneKey ek) {
		
		this.ephemeralKey = ek;
		
	}
	
	/**
	 * @param ek  the ephemeral key pair of this peer 
	 */
	public void setEphemeralKey() {
		
		OneKey ek = null;
		if (this.selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_0 || this.selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_1)
			ek = Util.generateKeyPair(KeyKeys.OKP_X25519.AsInt32());
		else if (this.selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_2 || this.selectedCiphersuite == Constants.EDHOC_CIPHER_SUITE_3)
			ek = Util.generateKeyPair(KeyKeys.EC2_P256.AsInt32());
		
		setEphemeralKey(ek);
		
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
	 * @return  the applicability statement used for this session
	 */
	public AppStatement getApplicabilityStatement() {

		return this.appStatement;
		
	}
	
	/**
	 * @return  the processor of External Authorization Data used for this session
	 */
	public EDP getEdp() {
		
		return this.edp;
		
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
	 * Set the ID_CRED of the long-term public key of the other peer
	 */
	public void setPeerIdCred(CBORObject idCred) {
		this.peerIdCred = idCred;
	}
	
	/**
	 * @return  the ID_CRED of the long-term public key of the other peer
	 */
	public CBORObject getPeerIdCred() {
		return this.peerIdCred;
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
	 * @param prk2e   the inner key PRK_2e
	 */
	public void setPRK2e(byte[] prk2e) {
		this.prk_2e = new byte[prk2e.length];
		System.arraycopy(prk2e,  0, this.prk_2e, 0, prk2e.length);
	}
	
	/**
	 * @return  the inner key PRK_2e
	 */
	public byte[] getPRK2e() {
		return this.prk_2e;
	}

	/**
	 * @param prk3e2m   the inner key PRK_3e2m
	 */
	public void setPRK3e2m(byte[] prk3e2m) {
		this.prk_3e2m = new byte[prk3e2m.length];
		System.arraycopy(prk3e2m,  0, this.prk_3e2m, 0, prk3e2m.length);
	}
	
	/**
	 * @return  the inner key PRK3e2m
	 */
	public byte[] getPRK3e2m() {
		return this.prk_3e2m;
	}
	
	/**
	 * @param prk4x3m   the inner key PRK4x3m
	 */
	public void setPRK4x3m(byte[] prk4x3m) {
		this.prk_4x3m = new byte[prk4x3m.length];
		System.arraycopy(prk4x3m,  0, this.prk_4x3m, 0, prk4x3m.length);
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
	 * @return  the EDHOC Message 1
	 */
	public byte[] getMessage1() {
		return this.message1;
	}
	
	/**
	 * @param msg  an EDHOC Message 1 to store for later computation of TH2
	 */
	public void setMessage1(byte[] msg) {
		this.message1 = new byte[msg.length];
		System.arraycopy(msg, 0, this.message1, 0, msg.length);
	}
	
    /**
     *  Clean up the stored EDHOC Message 1
     */
	public void cleanMessage1() {
		this.message1 = null;
	}
	
    /**
     * @return  the EDHOC Message 3
     */
	public byte[] getMessage3() {
		return this.message3;
	}
	
    /**
     * @param msg   The EDHOC message_3 to store, before an EDHOC+OSCORE request
     */
	public void setMessage3(byte[] msg) {
		this.message3 = new byte[msg.length];
		System.arraycopy(msg, 0, this.message3, 0, msg.length);
	}
	
    /**
     *  Clean up the stored EDHOC Message 3
     */
	public void cleanMessage3() {
		this.message3 = null;
	}
	
	/**
	 * @return  the CIPHERTEXT 2
	 */
	public byte[] getCiphertext2() {
		return this.ciphertext2;
	}
	
	/**
	 * @param ct  store a CIPHERTEXT 2 for later computation of TH3
	 */
	public void setCiphertext2(byte[] ct) {
		this.ciphertext2 = new byte[ct.length];
		System.arraycopy(ct, 0, this.ciphertext2, 0, ct.length);
	}
	
	/**
	 * EDHOC-Exporter interface
	 * @param label   The label to use to derive the OKM
	 * @param len   The intended length of the OKM to derive, in bytes
	 * @return  the application key, or null if the EDHOC execution is not completed yet
	 */
	public byte[] edhocExporter(String label, int len) throws InvalidKeyException, NoSuchAlgorithmException {
		
		if (this.currentStep != Constants.EDHOC_AFTER_M3 && this.currentStep != Constants.EDHOC_SENT_M3)
			return null;
		
		return edhocKDF(this.prk_4x3m, this.TH4, label, len);
		
	}
	
	/**
	 * EDHOC-KeyUpdate function, to preserve Perfect Forward Secrecy by updating the key PRK_4x3m
	 * @param nonce   The nonce to use for renewing PRK_4x3m
	 * @return  true in case of success, or false if the EDHOC execution is not completed yet
	 */
	public boolean edhocKeyUpdate(byte[] nonce) throws InvalidKeyException, NoSuchAlgorithmException {
		
		if (this.currentStep != Constants.EDHOC_AFTER_M3)
			return false;
		
		this.prk_4x3m = Hkdf.extract(nonce, this.prk_4x3m);
		
		return true;
		
	}
	
	/**
	 * EDHOC-specific version of KDF, building the 'info' parameter of HKDF-Expand from a transcript_hash and a label
	 * @param prk   The Pseudo Random Key
	 * @param transcript_hash   The transcript hash
	 * @param label   The label to use to derive the OKM
	 * @param len   The intended length of the OKM to derive, in bytes
	 * @return  the OKM generated by HKDF-Expand
	 */
	public byte[] edhocKDF(byte[] prk, byte[] transcript_hash, String label, int len) 
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

    /**
     *  Get an OSCORE Master Secret using the EDHOC-Exporter
     * @param session   The used EDHOC session
     * @return  the OSCORE Master Secret, or null in case of errors
     */
	public static byte[] getMasterSecretOSCORE(EdhocSession session) {

	    int keyLength = 0;
	    byte[] masterSecret = null;
	    int selectedCiphersuite = session.getSelectedCiphersuite();
	    
	    switch (selectedCiphersuite) {
	    	case Constants.EDHOC_CIPHER_SUITE_0:
	    	case Constants.EDHOC_CIPHER_SUITE_1:
	    	case Constants.EDHOC_CIPHER_SUITE_2:
	    	case Constants.EDHOC_CIPHER_SUITE_3:
	    		keyLength = 16;
	    }
	    
	    try {
			masterSecret = session.edhocExporter("OSCORE Master Secret", keyLength);
		} catch (InvalidKeyException e) {
			System.err.println("Error when the OSCORE Master Secret" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when the OSCORE Master Secret" + e.getMessage());
		}
	    
	    return masterSecret;
		
	}
	
    /**
     *  Get an OSCORE Master Salt using the EDHOC-Exporter
     * @param session   The used EDHOC session
     * @return  the OSCORE Master Salt, or null in case of errors
     */
	public static byte[] getMasterSaltOSCORE(EdhocSession session) {

	    byte[] masterSalt = null;
	    
	    try {
			masterSalt = session.edhocExporter("OSCORE Master Salt", 8);
		} catch (InvalidKeyException e) {
			System.err.println("Error when the OSCORE Master Salt" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when the OSCORE Master Salt" + e.getMessage());
		}
	    
	    return masterSalt;
		
	}
	
    /**
     *  Get the application AEAD algorithm associated to the selected ciphersuite
     * @param cipherSuite   The selected ciphersuite
     * @return  the application AEAD algorithm associated to the selected ciphersuite
     */
	public static AlgorithmID getAppAEAD(int cipherSuite) {

		AlgorithmID alg = null;
	    
		switch (cipherSuite) {
			case Constants.EDHOC_CIPHER_SUITE_0:
			case Constants.EDHOC_CIPHER_SUITE_1:
			case Constants.EDHOC_CIPHER_SUITE_2:
			case Constants.EDHOC_CIPHER_SUITE_3:
				alg = AlgorithmID.AES_CCM_16_64_128;
		}
	    
	    return alg;
		
	}
		
    /**
     *  Get the application hkdf algorithm associated to the selected ciphersuite
     * @param cipherSuite   The selected ciphersuite
     * @return  the application hkdf algorithm associated to the selected ciphersuite
     */
	public static AlgorithmID getAppHkdf(int cipherSuite) {

		AlgorithmID alg = null;
	    
		switch (cipherSuite) {
			case Constants.EDHOC_CIPHER_SUITE_0:
			case Constants.EDHOC_CIPHER_SUITE_1:
			case Constants.EDHOC_CIPHER_SUITE_2:
			case Constants.EDHOC_CIPHER_SUITE_3:
				alg = AlgorithmID.HKDF_HMAC_SHA_256;
		}
	    
	    return alg;
		
	}
	
}


