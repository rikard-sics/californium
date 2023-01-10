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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.HashMapCtxDB;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

public class EdhocSession {
	
	// Authentication credentials of this peer
	//
    // At the top level, authentication credential are sorted by key usage of the authentication keys.
    // The outer map has label SIGNATURE_KEY or ECDH_KEY for distinguishing the two key usages. 
    
    // The asymmetric key pairs of this peer (one per supported curve)
	private HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
    
    // The identifiers of the authentication credentials of this peer
	private HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
    
    // The authentication credentials of this peer (one per supported curve)
	private HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();

	// The side processor to use with this session
	//
	// It is required to be also in the EDHOC session, to be accessible
	// also by the EDHOC layer, when receiving an EDHOC+OSCORE request
	// targeting a different resource than an EDHOC resource. 
	private SideProcessor sideProcessor;
	
	// The database of OSCORE Security Contexts.
	// It can be null, if the EDHOC session has occurred
	// with an EDHOC resource not used to key OSCORE
	private HashMapCtxDB db;
	
	private int currentStep;
	
	private boolean initiator;
	private boolean clientInitiated;
	private int method;
	private int selectedCipherSuite;
	private byte[] connectionId;
	private OneKey keyPair;
	private CBORObject idCred;
	private byte[] cred; // This is the serialization of a CBOR object
	private OneKey ephemeralKey;
	
	private List<Integer> supportedCipherSuites;
	private Set<Integer> supportedEADs;
	private AppProfile appProfile;
	private int trustModel;
	
	private byte[] peerConnectionId;
	private CBORObject peerIdCred = null;
	private byte[] peerCred = null; // This is the serialization of a CBOR object
	
	private OneKey peerLongTermPublicKey = null;
	private OneKey peerEphemeralPublicKey = null;
	private List<Integer> peerSupportedCipherSuites = null;
	
	// Stored hash of EDHOC Message 1
	private byte[] hashMessage1 = null;
	
	// Stored PLAINTEXT_2, as serialized CBOR sequence
	private byte[] plaintext2 = null;
	
	// Inner Key-Derivation Keys
	private byte[] prk_2e = null;
	private byte[] prk_3e2m = null;
	private byte[] prk_4e3m = null;
	
	// Transcript Hashes
	private byte[] TH2 = null;
	private byte[] TH3 = null;
	private byte[] TH4 = null;
	
	// Key to store after a successful EDHOC execution
	private byte[] prk_out = null;
	private byte[] prk_exporter = null;
	
	// EDHOC message_3 , to be used for building an EDHOC+OSCORE request
	private byte[] message3 = null;
	
	public EdhocSession(boolean initiator, boolean clientInitiated, int method, byte[] connectionId,
						HashMap<Integer, HashMap<Integer, OneKey>> keyPairs,
						HashMap<Integer, HashMap<Integer, CBORObject>> idCreds,
						HashMap<Integer, HashMap<Integer, CBORObject>> creds,
						List<Integer> cipherSuites, List<Integer> peerCipherSuites,
						Set<Integer> eads, AppProfile appProfile, int trustModel, HashMapCtxDB db) {
		
		this.initiator = initiator;
		this.clientInitiated = clientInitiated;
		this.method = method;
		this.connectionId = connectionId;
		
		this.keyPairs = keyPairs;
		this.idCreds = idCreds;
		this.creds = creds;
		
		this.keyPair = null;
		this.idCred = null;
		this.cred = null;
		this.ephemeralKey = null;
		
		this.supportedCipherSuites = cipherSuites;
		this.supportedEADs = eads;
		this.appProfile = appProfile;
		this.trustModel = trustModel;
		this.db = db;
		
		this.selectedCipherSuite = -1;
		
		this.peerConnectionId = null;
		this.peerSupportedCipherSuites = peerCipherSuites;
		
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
		
		if (this.appProfile.getUseMessage4() == false) {
			this.prk_4e3m = null;
			this.TH4 = null;
		}
		
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
	 * @return  True if the CoAP client is the initiator, or False otherwise 
	 */
	public boolean isClientInitiated() {
		return this.clientInitiated;
	}
		
	/**
	 * @return  the Connection Identifier of this peer
	 */
	public byte[] getConnectionId() {
		return this.connectionId;
	}	
	
	/**
	 * @return  the key pair of this peer 
	 */
	public OneKey getKeyPair() {
		
		return this.keyPair;
		
	}
	
	/**
	 * @return  the ID_CRED for the long term key of this peer  
	 */
	public CBORObject getIdCred() {
		
		return this.idCred;
		
	}
	
	/**
	 * @return  the CRED of this peer
	 */
	public byte[] getCred() {
		
		return this.cred;
		
	}
	
	/** 
	 */
	public void setAuthenticationCredential() {
		
		int keyUsage = -1;
		int curve = -1;
		
		if (this.method == Constants.EDHOC_AUTH_METHOD_0) {
			keyUsage = Constants.SIGNATURE_KEY;
		}
		if (this.method == Constants.EDHOC_AUTH_METHOD_1) {
			keyUsage = initiator ? Constants.SIGNATURE_KEY : Constants.ECDH_KEY;
		}
		if (this.method == Constants.EDHOC_AUTH_METHOD_2) {
			keyUsage = initiator ? Constants.ECDH_KEY : Constants.SIGNATURE_KEY;
		}
		if (this.method == Constants.EDHOC_AUTH_METHOD_3) {
			keyUsage = Constants.ECDH_KEY;
		}
		
		if (this.selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_0 || this.selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_1) {
			
			if (this.method == Constants.EDHOC_AUTH_METHOD_0) {
				curve = Constants.CURVE_Ed25519;
			}
			if (this.method == Constants.EDHOC_AUTH_METHOD_1) {
				curve = initiator ? Constants.CURVE_Ed25519 : Constants.CURVE_X25519;
			}
			if (this.method == Constants.EDHOC_AUTH_METHOD_2) {
				curve = initiator ? Constants.CURVE_X25519 : Constants.CURVE_Ed25519;
			}
			if (this.method == Constants.EDHOC_AUTH_METHOD_3) {
				curve = Constants.CURVE_X25519;
			}
			
		}
		if (this.selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_2 || this.selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_3) {
				curve = Constants.CURVE_P256;
		}
		
		this.keyPair = this.keyPairs.get(Integer.valueOf(keyUsage)).
									 get(Integer.valueOf(curve));
		this.cred = this.creds.get(Integer.valueOf(keyUsage)).
							   get(Integer.valueOf(curve)).GetByteString();
		this.idCred = this.idCreds.get(Integer.valueOf(keyUsage)).
								   get(Integer.valueOf(curve));
				
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
		if (this.selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_0 || this.selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_1)
			ek = Util.generateKeyPair(KeyKeys.OKP_X25519.AsInt32());
		else if (this.selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_2 || this.selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_3)
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
	 * @param cipherSuites  the supported cipher suites to indicate in EDHOC messages
	 */
	public void setSupportedCipherSuites(List<Integer> cipherSuites) {

		this.supportedCipherSuites = cipherSuites;
		
	}
	
	/**
	 * @return  the supported cipher suites to indicate in EDHOC messages
	 */
	public List<Integer> getSupportedCipherSuites() {

		return this.supportedCipherSuites;
		
	}
	
	/**
	 * @return  the supported EAD items
	 */
	public Set<Integer> getSupportedEADs() {

		return this.supportedEADs;
		
	}
	
	/**
	 * @return  the application profile used for this session
	 */
	public AppProfile getApplicationProfile() {

		return this.appProfile;
		
	}
	
	/**
	 * @return  the used trust model for validating authentication credentials of the other peer
	 */
	public int getTrustModel() {

		return this.trustModel;
		
	}	
	
	/**
	 * @return  the side processor object for this session
	 */
	public SideProcessor getSideProcessor() {
		
		return this.sideProcessor;
		
	}
	
	/**
	 * Set the side processor object for this session
	 * @param  the side processor object for this session
	 */
	public void setSideProcessor(SideProcessor sideProcessor) {
		
		this.sideProcessor = sideProcessor;
		
	}
	
	/**
	 * @return  the database of OSCORE Security Contexts
	 */
	public HashMapCtxDB getOscoreDb() {
		return this.db;
	}

	/**
	 * @return  the current step in the execution of the EDHOC protocol 
	 */
	public int getCurrentStep() {
		return this.currentStep;
	}
	
	/**
	 * Set the current step in the execution of the EDHOC protocol
	 * @param newStep   the new step to set 
	 */
	public void setCurrentStep(int newStep) {
		this.currentStep = newStep;
	}
	
	/**
	 * @return  the selected cipher suite for this EDHOC session 
	 */
	public int getSelectedCipherSuite() {
		return this.selectedCipherSuite;
	}
	
	/**
	 * Set the selected cipher suite for this EDHOC session
	 * @param cipherSuite   the selected cipher suite 
	 */
	public void setSelectedCipherSuite(int cipherSuite) {
		this.selectedCipherSuite = cipherSuite;
	}
	
	/**
	 * @return  the Connection Identifier of the other peer
	 */
	public byte[] getPeerConnectionId() {
		return this.peerConnectionId;
	}
	
	/**
	 * Set the Connection Identifier of the other peer
	 * @param peerId   the Connection Id of the other peer
	 */
	public void setPeerConnectionId(byte[] peerId) {
		this.peerConnectionId = peerId;
	}
	
	/**
	 * @return  the list of the cipher suites supported by the peer
	 */
	public List<Integer> getPeerSupportedCipherSuites() {
		return this.peerSupportedCipherSuites;
	}
	
	/**
	 * @return  the CRED of the other peer
	 */
	public byte[] getPeerCred() {
		return this.peerCred;
	}
	
	/**
	 * Set the CRED of the other peer
	 * @param peerCred   the CRED of the other peer 
	 */
	public void setPeerCred(byte[] peerCred) {
		this.peerCred = peerCred;
	}

	/**
	 * @return  the long-term public key of the other peer
	 */
	public OneKey getPeerLongTermPublicKey() {
		return this.peerLongTermPublicKey;
	}
	
	/**
	 * Set the long-term public key of the other peer
	 * @param peerKey   the long-term public key of the other peer 
	 */
	public void setPeerLongTermPublicKey(OneKey peerKey) {
		this.peerLongTermPublicKey = peerKey;
	}

	/**
	 * @return  the ID_CRED of the long-term public key of the other peer
	 */
	public CBORObject getPeerIdCred() {
		return this.peerIdCred;
	}
	
	/**
	 * Set the ID_CRED of the long-term public key of the other peer
	 */
	public void setPeerIdCred(CBORObject idCred) {
		this.peerIdCred = idCred;
	}

	/**
	 * @return  the ephemeral public key of the other peer
	 */
	public OneKey getPeerEphemeralPublicKey() {
		return this.peerEphemeralPublicKey;
	}
	
	/**
	 * Set the ephemeral public key of the other peer
	 * @param peerKey   the ephemeral public key of the other peer 
	 */
	public void setPeerEphemeralPublicKey(OneKey peerKey) {
		this.peerEphemeralPublicKey = peerKey;
	}

	/**
	 * @return  the inner key PRK_2e
	 */
	public byte[] getPRK2e() {
		return this.prk_2e;
	}
	
	/**
	 * @param prk2e   the inner key PRK_2e
	 */
	public void setPRK2e(byte[] prk2e) {
		this.prk_2e = new byte[prk2e.length];
		System.arraycopy(prk2e,  0, this.prk_2e, 0, prk2e.length);
	}

	/**
	 * @return  the inner key PRK_3e2m
	 */
	public byte[] getPRK3e2m() {
		return this.prk_3e2m;
	}
	
	/**
	 * @param prk3e2m   the inner key PRK_3e2m
	 */
	public void setPRK3e2m(byte[] prk3e2m) {
		this.prk_3e2m = new byte[prk3e2m.length];
		System.arraycopy(prk3e2m,  0, this.prk_3e2m, 0, prk3e2m.length);
	}

	/**
	 * @return  the inner key PRK_4e3m
	 */
	public byte[] getPRK4e3m() {
		return this.prk_4e3m;
	}
	
	/**
	 * @param prk4e3m   the inner key PRK_4e3m
	 */
	public void setPRK4e3m(byte[] prk4e3m) {
		if (prk4e3m == null)
			this.prk_4e3m = null;
		else {
			this.prk_4e3m = new byte[prk4e3m.length];
			System.arraycopy(prk4e3m,  0, this.prk_4e3m, 0, prk4e3m.length);
		}
	}
	
	/**
	 * @return  the Transcript Hash TH2
	 */
	public byte[] getTH2() {
		return this.TH2;
	}
	
	/**
	 * Set the Transcript Hash TH2 
	 * @param inputTH   the Transcript Hash TH2
	 */
	public void setTH2(byte[] inputTH) {
		this.TH2 = inputTH;
	}
		
	/**
	 * @return  the Transcript Hash TH3
	 */
	public byte[] getTH3() {
		return this.TH3;
	}
	
	/**
	 * Set the Transcript Hash TH3 
	 * @param inputTH   the Transcript Hash TH3
	 */
	public void setTH3(byte[] inputTH) {
		this.TH3 = inputTH;
	}
	
	/**
	 * @return  the Transcript Hash TH4
	 */
	public byte[] getTH4() {
		return this.TH4;
	}
	
	/**
	 * Set the Transcript Hash TH4
	 * @param inputTH   the Transcript Hash TH4
	 */
	public void setTH4(byte[] inputTH) {
		this.TH4 = inputTH;
	}

	/**
	 * @return  the key PRK_out
	 */
	public byte[] getPRKout() {
		return this.prk_out;
	}
	
	/**
	 * @param prkOut   the key PRK_out
	 */
	public void setPRKout(byte[] prkOut) {
		this.prk_out = new byte[prkOut.length];
		System.arraycopy(prkOut,  0, this.prk_out, 0, prkOut.length);
	}
	
	/**
	 * @return  the key PRK_exporter
	 */
	public byte[] getPRKexporter() {
		return this.prk_exporter;
	}
	
	/**
	 * @param prkOut   the key PRK_exporter
	 */
	public void setPRKexporter(byte[] prkExporter) {
		this.prk_exporter = new byte[prkExporter.length];
		System.arraycopy(prkExporter,  0, this.prk_exporter, 0, prkExporter.length);
	}
	
	/**
	 * @return  the hash of EDHOC Message 1
	 */
	public byte[] getHashMessage1() {
		return this.hashMessage1;
	}
	
	/**
	 * @param msg  an EDHOC Message 1 of which to store the hash for later computation of TH2
	 * @return  true in case of success, or false in case of error 
	 */
	public boolean setHashMessage1(byte[] msg) {
		
		byte[] hash = null;
		String hashAlgorithm = null;
		
		int selectedCipherSuite = getSelectedCipherSuite();
		hashAlgorithm = getEdhocHashAlg(selectedCipherSuite);

		try {
			hash = Util.computeHash(msg, hashAlgorithm);
		} catch (NoSuchAlgorithmException e) {
		    System.err.println("Invalid hash algorithm when computing the hash of EDHOC Message 1\n" + e.getMessage());
		    return false;
		}
		
		if (hash == null) {
		    System.err.println("Error when computing the hash of EDHOC Message 1\n");
			return false;
		}
		
		this.hashMessage1 = new byte[hash.length];
		System.arraycopy(hash, 0, this.hashMessage1, 0, hash.length);
		return true;
	}
	
    /**
     *  Clean up the stored hash of EDHOC Message 1
     */
	public void cleanMessage1() {
		this.hashMessage1 = null;
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
	 * @return  the PLAINTEXT_2
	 */
	public byte[] getPlaintext2() {
		return this.plaintext2;
	}

	/**
	 * @param pt  store a PLAINTEXT_2 for the later computation of TH3
	 */
	public void setPlaintext2(byte[] pt) {
		this.plaintext2 = new byte[pt.length];
		System.arraycopy(pt, 0, this.plaintext2, 0, pt.length);
	}
	
	/**
	 * EDHOC-Exporter function, to derive application keys
	 * @param label   The exporter_label to use to derive the OKM
	 * @param context   The context to use to derive the OKM, as a CBOR byte string
	 * @param len   The intended length of the OKM to derive, in bytes
	 * @return  the application key, or null in case of errors
	 */
	public byte[] edhocExporter(int label, CBORObject context, int len) throws InvalidKeyException, NoSuchAlgorithmException {
		
		if (label < 0 || context.getType() != CBORType.ByteString || len < 0)
			return null;
		
		if (this.currentStep != Constants.EDHOC_AFTER_M3 && this.currentStep != Constants.EDHOC_SENT_M3)
			return null;
	
		return edhocKDF(this.prk_exporter, label, context, len);
		
	}
	
	/**
	 * EDHOC-KeyUpdate function, to update the keys PRK_out and PRK_exporter
	 * @param context   The context to use, as a CBOR byte string
	 * @return  true in case of success, or false otherwise
	 */
	public boolean edhocKeyUpdate(CBORObject context) throws InvalidKeyException, NoSuchAlgorithmException {
		
		// The EDHOC execution is not completed yet
		if (this.currentStep != Constants.EDHOC_AFTER_M3)
			return false;
		
		// The provided context is not valid
		if (context == null || context.getType() != CBORType.ByteString)
			return false;
	
		// Update PRK_out
		int length = EdhocSession.getEdhocHashAlgOutputSize(this.selectedCipherSuite);
		try {
			this.prk_out = edhocKDF(this.prk_out, Constants.KDF_LABEL_PRK_OUT_KEY_UPDATE, context, length);
		} catch (InvalidKeyException e) {
			System.err.println("Error when updating PRK_out\n" + e.getMessage());
			return false;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when updating PRK_out\n" + e.getMessage());
			return false;
		}
	    Util.nicePrint("PRK_out (updated)", this.prk_out);
		
		// Update PRK_exporter
	    this.prk_exporter = MessageProcessor.computePRKexporter(this, this.prk_out);
	    if (prk_exporter == null) {
			System.err.println("Error when updating PRK_exporter\n");
			return false;
		}
	    Util.nicePrint("PRK_exporter (updated)", this.prk_exporter);

		return true;

	}
	
	/**
	 * EDHOC-KDF
	 * @param prk   The Pseudo Random Key
	 * @param label   The info_label to use to derive the OKM
	 * @param context   The context to use to derive the OKM, as a CBOR byte string
	 * @param length   The intended length of the OKM to derive, in bytes
	 * @return  the OKM generated by HKDF-Expand
	 */
	public byte[] edhocKDF(byte[] prk, int label, CBORObject context, int length)
			throws InvalidKeyException, NoSuchAlgorithmException {
		
		if (prk == null || context == null)
			return null;
		
		if (context.getType() != CBORType.ByteString)
			return null;
		
        // Prepare the 'info' CBOR sequence
        List<CBORObject> objectList = new ArrayList<>();
        objectList.add(CBORObject.FromObject(label));
        objectList.add(context);
        objectList.add(CBORObject.FromObject(length));
		byte[] info = Util.buildCBORSequence(objectList);
		
		byte[] okm = null;
		String hashAlgorithm = EdhocSession.getEdhocHashAlg(selectedCipherSuite);
		
		if (hashAlgorithm.equals("SHA-256") || hashAlgorithm.equals("SHA-384") || hashAlgorithm.equals("SHA-512")) {
			okm = Hkdf.expand(prk, info, length);
		}
		
		return okm;
		
	}

    /**
     *  Get an OSCORE Master Secret using the EDHOC-Exporter
     * @param session   The used EDHOC session
     * @return  the OSCORE Master Secret, or null in case of errors
     */
	public static byte[] getMasterSecretOSCORE(EdhocSession session) {

	    byte[] masterSecret = null;
	    int selectedCipherSuite = session.getSelectedCipherSuite();
	    
	    CBORObject context = CBORObject.FromObject(new byte[0]);
	    int keyLength = getKeyLengthAppAEAD(selectedCipherSuite);
	    
	    try {
			masterSecret = session.edhocExporter(Constants.EXPORTER_LABEL_OSCORE_MASTER_SECRET, context, keyLength);
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
	    CBORObject context = CBORObject.FromObject(new byte[0]);
	    
	    try {
			masterSalt = session.edhocExporter(Constants.EXPORTER_LABEL_OSCORE_MASTER_SALT, context, 8);
		} catch (InvalidKeyException e) {
			System.err.println("Error when the OSCORE Master Salt" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when the OSCORE Master Salt" + e.getMessage());
		}
	    
	    return masterSalt;
		
	}
	
    /**
     *  Get the EDHOC AEAD algorithm associated to the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the EDHOC AEAD algorithm associated to the selected cipher suite
     */
	public static AlgorithmID getEdhocAEADAlg(int cipherSuite) {

		AlgorithmID alg = null;
	    
    	switch (cipherSuite) {
			case Constants.EDHOC_CIPHER_SUITE_0:
			case Constants.EDHOC_CIPHER_SUITE_2:
				alg = AlgorithmID.AES_CCM_16_64_128;
				break;
			case Constants.EDHOC_CIPHER_SUITE_1:
			case Constants.EDHOC_CIPHER_SUITE_3:
				alg = AlgorithmID.AES_CCM_16_128_128;
				break;
		}
	    
	    return alg;
		
	}
	
    /**
     *  Get the key length (in bytes) for the EDHOC AEAD algorithm associated to the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the key length (in bytes) for the EDHOC AEAD algorithm associated to the selected cipher suite
     */
	public static int getKeyLengthEdhocAEAD(int cipherSuite) {

		int keyLength = 0;
	    
		switch (cipherSuite) {
	    	case Constants.EDHOC_CIPHER_SUITE_0:
	    	case Constants.EDHOC_CIPHER_SUITE_1:
	    	case Constants.EDHOC_CIPHER_SUITE_2:
	    	case Constants.EDHOC_CIPHER_SUITE_3:
	    		keyLength = 16;
		}
	    
	    return keyLength;
		
	}
	
    /**
     *  Get the IV length (in bytes) for the EDHOC AEAD algorithm associated to the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the IV length (in bytes) for the EDHOC AEAD algorithm associated to the selected cipher suite
     */
	public static int getIvLengthEdhocAEAD(int cipherSuite) {

		int ivLength = 0;
	    
		switch (cipherSuite) {
	    	case Constants.EDHOC_CIPHER_SUITE_0:
	    	case Constants.EDHOC_CIPHER_SUITE_1:
	    	case Constants.EDHOC_CIPHER_SUITE_2:
	    	case Constants.EDHOC_CIPHER_SUITE_3:
	    		ivLength = 13;
		}
	    
	    return ivLength;
		
	}
	
    /**
     *  Get the Tag length (in bytes) for the EDHOC AEAD algorithm associated to the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the Tag length (in bytes) for the EDHOC AEAD algorithm associated to the selected cipher suite
     */
	public static int getTagLengthEdhocAEAD(int cipherSuite) {

		int tagLength = 0;
	    
		switch (cipherSuite) {
	    	case Constants.EDHOC_CIPHER_SUITE_0:
	    	case Constants.EDHOC_CIPHER_SUITE_2:
	    		tagLength = 8;
	    		break;
	    	case Constants.EDHOC_CIPHER_SUITE_1:
	    	case Constants.EDHOC_CIPHER_SUITE_3:
	    		tagLength = 16;
		}
	    
	    return tagLength;
		
	}
	
    /**
     *  Get the EDHOC Hash algorithm associated to the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the EDHOC Hash algorithm associated to the selected cipher suite
     */
	public static String getEdhocHashAlg(int cipherSuite) {

		String hashAlg = null;
	    
		switch (cipherSuite) {
			case Constants.EDHOC_CIPHER_SUITE_0:
			case Constants.EDHOC_CIPHER_SUITE_1:
			case Constants.EDHOC_CIPHER_SUITE_2:
			case Constants.EDHOC_CIPHER_SUITE_3:
				hashAlg = "SHA-256";
		}
	    
	    return hashAlg;
		
	}
	
    /**
     *  Get the output size (in bytes) of the EDHOC Hash algorithm associated to the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the EDHOC output size (in bytes) of the Hash algorithm associated to the selected cipher suite
     */
	public static int getEdhocHashAlgOutputSize(int cipherSuite) {

		int outputSize = 0;
	    
		switch (cipherSuite) {
			case Constants.EDHOC_CIPHER_SUITE_0:
			case Constants.EDHOC_CIPHER_SUITE_1:
			case Constants.EDHOC_CIPHER_SUITE_2:
			case Constants.EDHOC_CIPHER_SUITE_3:
				outputSize = 32;
		}
	    
	    return outputSize;
		
	}
	
    /**
     *  Get the length (in bytes) of the ephemeral keys for the EDHOC key exchange algorithm
     *  (ECDH curve) associated to the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the length (in bytes) of the ephemeral keys for the EDHOC key exchange algorithm
     *          (ECDH curve) associated to the selected cipher suite
     */
	public static int getEphermeralKeyLength(int cipherSuite) {

		int keyLength = 0;
	    
		switch (cipherSuite) {
			case Constants.EDHOC_CIPHER_SUITE_0:
			case Constants.EDHOC_CIPHER_SUITE_1:
			case Constants.EDHOC_CIPHER_SUITE_2:
			case Constants.EDHOC_CIPHER_SUITE_3:
				keyLength = 32;
		}
	    
	    return keyLength;
		
	}
	
    /**
     *  Get the application AEAD algorithm associated to the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the application AEAD algorithm associated to the selected cipher suite
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
     *  Get the key length (in bytes) for the application AEAD algorithm associated to the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the key length (in bytes) for the application AEAD algorithm associated to the selected cipher suite
     */
	public static int getKeyLengthAppAEAD(int cipherSuite) {

		int keyLength = 0;
	    
		switch (cipherSuite) {
	    	case Constants.EDHOC_CIPHER_SUITE_0:
	    	case Constants.EDHOC_CIPHER_SUITE_1:
	    	case Constants.EDHOC_CIPHER_SUITE_2:
	    	case Constants.EDHOC_CIPHER_SUITE_3:
	    		keyLength = 16;
		}
	    
	    return keyLength;
		
	}
	
    /**
     *  Get the application HKDF algorithm associated to the application hash algorithm of the selected cipher suite
     * @param cipherSuite   The selected cipher suite
     * @return  the application hkdf algorithm associated to the selected cipher suite
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


