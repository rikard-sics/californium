/*******************************************************************************
 * Copyright (c) 2020 RISE SICS and others.
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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore.group;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map.Entry;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.ByteId;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;

/**
 * Class implementing a Group OSCORE context. It has one sender context and
 * multiple recipient contexts.
 *
 */
public class GroupCtx {

	// Parameters in common context
	byte[] masterSecret;
	byte[] masterSalt;
	AlgorithmID aeadAlg;
	AlgorithmID hkdfAlg;
	byte[] idContext;
	AlgorithmID algSign;
	AlgorithmID algSignEnc;
	int[][] parCountersign;
	AlgorithmID algKeyAgreement;
	int[][] parSecret;
	byte[] groupEncryptionKey;
	byte[] gmPublicKey;

	// Reference to the associated sender context
	public GroupSenderCtx senderCtx;

	// References to the associated recipient contexts
	public HashMap<ByteId, GroupRecipientCtx> recipientCtxMap;

	// Reference to the associated deterministic sender context
	GroupDeterministicSenderCtx deterministicSenderCtx;
	
	// Reference to the associated deterministic recipient context
	GroupDeterministicRecipientCtx deterministicRecipientCtx;
	
	// References to public keys without existing contexts
	// (For dynamic context generation)
	// TODO: Avoid double storage
	HashMap<ByteId, OneKey> publicKeysMap;

	boolean pairwiseModeResponses = false;
	boolean pairwiseModeRequests = false;

	private final static int MAX_UNFRAGMENTED_SIZE = 4096;
	
	/**
	 * Construct a Group OSCORE context.
	 * 
	 * @param masterSecret
	 * @param masterSalt
	 * @param aeadAlg
	 * @param hkdfAlg
	 * @param idContext
	 * @param algSign
	 * @param gmPublicKey
	 */
	public GroupCtx(byte[] masterSecret, byte[] masterSalt, AlgorithmID aeadAlg, AlgorithmID hkdfAlg, byte[] idContext,
			AlgorithmID algSign, byte[] gmPublicKey) {

		this.masterSecret = masterSecret;
		this.masterSalt = masterSalt;
		this.aeadAlg = aeadAlg;
		this.hkdfAlg = hkdfAlg;
		this.idContext = idContext;
		this.algSign = algSign;
		this.gmPublicKey = gmPublicKey;
		this.algSignEnc = aeadAlg; // Same if not indicated

		recipientCtxMap = new HashMap<ByteId, GroupRecipientCtx>();
		publicKeysMap = new HashMap<ByteId, OneKey>();

		// Default since not indicated
		this.algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

		// Set the par countersign value
		int[] countersign_alg_capab = getCountersignAlgCapab(algCountersign);
		int[] countersign_key_type_capab = getCountersignKeyTypeCapab(algCountersign);
		this.parCountersign = new int[][] { countersign_alg_capab, countersign_key_type_capab };

		// Set the alg secret and par secret values
		this.algSecret = AlgorithmID.ECDH_SS_HKDF_256;
		if (algCountersign == AlgorithmID.ECDSA_256 || algCountersign == AlgorithmID.ECDSA_384
				|| algCountersign == AlgorithmID.ECDSA_512) {
			this.parSecret = new int[][] { countersign_alg_capab, countersign_key_type_capab };
		} else {
			this.parSecret = new int[][] { countersign_alg_capab, new int[] { 1, 4 } };
		}
	}

	/**
	 * Construct a Group OSCORE context. New one to be used.
	 * 
	 * @param masterSecret
	 * @param masterSalt
	 * @param aeadAlg
	 * @param hkdfAlg
	 * @param idContext
	 * @param algSign
	 * @param gmPublicKey
	 * @param algSignEnc
	 * @param algKeyAgreement
	 */
	public GroupCtx(byte[] masterSecret, byte[] masterSalt, AlgorithmID aeadAlg, AlgorithmID hkdfAlg, byte[] idContext,
			AlgorithmID algSign, AlgorithmID algSignEnc, AlgorithmID algKeyAgreement, byte[] gmPublicKey) {

		this.masterSecret = masterSecret;
		this.masterSalt = masterSalt;
		this.aeadAlg = aeadAlg;
		this.hkdfAlg = hkdfAlg;
		this.idContext = idContext;
		this.algSign = algSign;
		this.gmPublicKey = gmPublicKey;
		this.algSignEnc = algSignEnc;
		this.algKeyAgreement = algKeyAgreement;

		recipientCtxMap = new HashMap<ByteId, GroupRecipientCtx>();
		publicKeysMap = new HashMap<ByteId, OneKey>();
	}

	/**
	 * Add a recipient context.
	 * 
	 * @param recipientId
	 * @param replayWindow
	 * @param otherEndpointPubKey
	 * @throws OSException
	 */
	public void addRecipientCtx(byte[] recipientId, int replayWindow, OneKey otherEndpointPubKey) throws OSException {
		GroupRecipientCtx recipientCtx = new GroupRecipientCtx(masterSecret, false, aeadAlg, null, recipientId, hkdfAlg,
				replayWindow, masterSalt, idContext, otherEndpointPubKey, null, this);

		recipientCtxMap.put(new ByteId(recipientId), recipientCtx);

	}
	
	/**
	 * Add a deterministic recipient context.
	 * 
	 * @param recipientId, i.e. the Sender Id of the deterministic client
	 * @param hash algorithm
	 * @throws OSException
	 */
	public void addDeterministicRecipientCtx(byte[] recipientId, int replayWindow, String hashAlg) throws OSException {
		
		if (deterministicRecipientCtx != null) {
			throw new OSException("Cannot add more than one Deterministic Recipient Context.");
		}
		
		GroupDeterministicRecipientCtx deterministicRecipientCtx = new GroupDeterministicRecipientCtx(
                masterSecret, false, aeadAlg, null, recipientId, hkdfAlg,
                replayWindow, masterSalt, idContext, MAX_UNFRAGMENTED_SIZE,
                hashAlg, this);

		this.deterministicRecipientCtx = deterministicRecipientCtx;

	}
	
	/**
	 * Add a sender context.
	 * 
	 * @param senderId
	 * @param ownPrivateKey
	 * @throws OSException
	 */
	public void addSenderCtx(byte[] senderId, OneKey ownPrivateKey) throws OSException {

		if (senderCtx != null) {
			throw new OSException("Cannot add more than one Sender Context.");
		}

		GroupSenderCtx senderCtx = new GroupSenderCtx(masterSecret, false, aeadAlg, senderId, null, hkdfAlg, 0,
				masterSalt, idContext, ownPrivateKey, null, this);
		this.senderCtx = senderCtx;

		this.groupEncryptionKey = deriveGroupEncryptionKey();
	}

	/**
	 * Add a recipient context with (U)CCS.
	 * 
	 * @param recipientId
	 * @param replayWindow
	 * @param otherEndpointPubKey
	 * @throws OSException
	 */
	public void addRecipientCtxCcs(byte[] recipientId, int replayWindow, MultiKey otherEndpointPubKey)
			throws OSException {
		GroupRecipientCtx recipientCtx;
		if (otherEndpointPubKey != null) {
			recipientCtx = new GroupRecipientCtx(masterSecret, false, aeadAlg, null, recipientId, hkdfAlg, replayWindow,
					masterSalt, idContext, otherEndpointPubKey.getCoseKey(), otherEndpointPubKey.getRawKey(), this);
		} else {
			recipientCtx = new GroupRecipientCtx(masterSecret, false, aeadAlg, null, recipientId, hkdfAlg, replayWindow,
					masterSalt, idContext, null, null, this);
		}

		recipientCtxMap.put(new ByteId(recipientId), recipientCtx);

	}

	/**
	 * Add a sender context with (U)CCS.
	 * 
	 * @param senderId
	 * @param ownPrivateKey
	 * @throws OSException
	 */
	public void addSenderCtxCcs(byte[] senderId, MultiKey ownPrivateKey) throws OSException {
		if (senderCtx != null) {
			throw new OSException("Cannot add more than one Sender Context.");
		}

		GroupSenderCtx senderCtx = new GroupSenderCtx(masterSecret, false, aeadAlg, senderId, null, hkdfAlg, 0,
				masterSalt, idContext, ownPrivateKey.getCoseKey(), ownPrivateKey.getRawKey(), this);
		this.senderCtx = senderCtx;

		this.groupEncryptionKey = deriveGroupEncryptionKey();
	}
	
	/**
	 * Add a deterministic sender context.
	 * 
	 * @param senderId of the deterministic client
	 * @param hash algorithm
	 * @throws OSException
	 */
	public void addDeterministicSenderCtx(byte[] senderId, String hashAlg) throws OSException {

		if (deterministicSenderCtx != null) {
			throw new OSException("Cannot add more than one Deterministic Sender Context.");
		}

		GroupDeterministicSenderCtx deterministicSenderCtx = new GroupDeterministicSenderCtx(
				                                                 masterSecret, false, aeadAlg,
				                                                 senderId, null, hkdfAlg, 0,
				                                                 masterSalt, idContext, MAX_UNFRAGMENTED_SIZE,
				                                                 hashAlg, this);
		
		this.deterministicSenderCtx = deterministicSenderCtx;
		this.deterministicSenderCtx.setIncludeContextId(true);
	}
	
	public GroupDeterministicSenderCtx getDeterministicSenderCtx() {
		
		return this.deterministicSenderCtx;
		
	}
	
	/**
	 * Retrieve the public key for the Group Manager associated to this context.
	 * 
	 * @return the public key for the GM for this context
	 */
	public byte[] getGmPublicKey() {
		return gmPublicKey;
	}

	/**
	 * Retrieve the public key for the Group Manager associated to this context.
	 * 
	 * @return the public key for the GM for this context
	 */
	public byte[] getGmPublicKey() {
		return gmPublicKey;
	}

	public int getCountersignatureLen() {
		switch (algSign) {
		case EDDSA:
		case ECDSA_256:
			return 64;
		case ECDSA_384:
			return 96;
		case ECDSA_512:
			return 132; // Why 132 and not 128?
		default:
			throw new RuntimeException("Unsupported countersignature algorithm!");
		}
	}

	/**
	 * Get the countersign_alg_capab array for an algorithm.
	 * 
	 * See Draft section 4.3.1 & Appendix H.
	 * 
	 * @param alg the countersignature algorithm
	 * @return the array countersign_alg_capab
	 */
	private int[] getCountersignAlgCapab(AlgorithmID alg) {
		switch (alg) {
		case EDDSA:
			return new int[] { KeyKeys.KeyType_OKP.AsInt32() };
		case ECDSA_256:
		case ECDSA_384:
		case ECDSA_512:
			return new int[] { KeyKeys.KeyType_EC2.AsInt32() };
		default:
			return null;
		}
	}

	/**
	 * Get the countersign_key_type_capab array for an algorithm.
	 * 
	 * See Draft section 4.3.1 & Appendix H.
	 * 
	 * @param alg the countersignature algorithm
	 * @return the array countersign_key_type_capab
	 */
	private int[] getCountersignKeyTypeCapab(AlgorithmID alg) {
		switch (alg) {
		case EDDSA:
			return new int[] { KeyKeys.KeyType_OKP.AsInt32(), KeyKeys.OKP_Ed25519.AsInt32() };
		case ECDSA_256:
			return new int[] { KeyKeys.KeyType_EC2.AsInt32(), KeyKeys.EC2_P256.AsInt32() };
		case ECDSA_384:
			return new int[] { KeyKeys.KeyType_EC2.AsInt32(), KeyKeys.EC2_P384.AsInt32() };
		case ECDSA_512:
			return new int[] { KeyKeys.KeyType_EC2.AsInt32(), KeyKeys.EC2_P521.AsInt32() };
		default:
			return null;
		}
	}

	/**
	 * Allow adding loose public keys without an associated context. These will
	 * be used during the dynamic context generation.
	 * 
	 * @param rid the RID for the other endpoint
	 * @param publicKey the public key
	 */
	public void addPublicKeyForRID(byte[] rid, OneKey publicKey) {
		publicKeysMap.put(new ByteId(rid), publicKey);
	}

	/**
	 * Get the public key added for a particular RID.
	 * 
	 * @param rid the RID
	 */
	OneKey getPublicKeyForRID(byte[] rid) {
		return publicKeysMap.get(new ByteId(rid));
	}

	/**
	 * Enable or disable using pairwise responses. TODO: Implement elsewhere to
	 * avoid cast?
	 * 
	 * @param b Whether pairwise responses should be used
	 */
	public void setPairwiseModeResponses(boolean b) {
		this.pairwiseModeResponses = b;
	}

	@Deprecated
	void setPairwiseModeRequests(boolean b) {
		this.pairwiseModeRequests = b;
	}

	/**
	 * Enable or disable using including a Partial IV in responses.
	 * 
	 * @param b Whether responses should include a PIV
	 */
	public void setResponsesIncludePartialIV(boolean b) {
		senderCtx.setResponsesIncludePartialIV(b);
	}

	/**
	 * Add this Group context to the context database. In essence it will its
	 * sender context and all its recipient context to the database. // TODO:
	 * Move to HashMapCtxDB?
	 * 
	 * @param uri
	 * @param db
	 * @throws OSException
	 */
	public void addToDb(String uri, HashMapCtxDB db) throws OSException {

		// Add the sender context and derive its pairwise keys
		senderCtx.derivePairwiseKeys();
		db.addContext(uri, senderCtx);

		// Add the recipient contexts and derive their pairwise keys
		for (Entry<ByteId, GroupRecipientCtx> entry : recipientCtxMap.entrySet()) {
			GroupRecipientCtx recipientCtx = entry.getValue();
			recipientCtx.derivePairwiseKey();

			db.addContext(recipientCtx);
		}
		
		// Add the deterministic recipient context
		if (deterministicRecipientCtx != null) {
			db.addContext(deterministicRecipientCtx);
		}

	}
	
	// TODO: Merge with below?
	byte[] deriveGroupEncryptionKey() {

		String digest = "";
		if (algKeyAgreement.toString().contains("HKDF_256")) {
			digest = "SHA256";
		} else if (algKeyAgreement.toString().contains("HKDF_512")) {
			digest = "SHA512";
		}

		CBORObject info = CBORObject.NewArray();
		int keyLength = this.algSignEnc.getKeySize() / 8;

		// Then derive the group encryption key
		info = CBORObject.NewArray();
		info.Add(Bytes.EMPTY);
		info.Add(this.idContext);
		info.Add(this.aeadAlg.AsCBOR());
		info.Add(CBORObject.FromObject("Group Encryption Key"));
		info.Add(keyLength);

		byte[] groupEncryptionKey = null;
		try {
			groupEncryptionKey = OSCoreCtx.deriveKey(senderCtx.getMasterSecret(), senderCtx.getSalt(), keyLength,
					digest, info.EncodeToBytes());

		} catch (CoseException e) {
			System.err.println(e.getMessage());
		}

		return groupEncryptionKey;
	}

	// TODO: Merge with below?
	byte[] derivePairwiseSenderKey(byte[] recipientId, byte[] recipientKey, OneKey recipientPublicKey,
			byte[] recipientPublicKeyRaw) {

		// TODO: Move? See below also
		if (recipientPublicKey == null || senderCtx.getPrivateKey() == null) {
			return null;
		}

		String digest = "";
		if (algKeyAgreement.toString().contains("HKDF_256")) {
			digest = "SHA256";
		} else if (algKeyAgreement.toString().contains("HKDF_512")) {
			digest = "SHA512";
		}

		CBORObject info = CBORObject.NewArray();
		int keyLength = this.aeadAlg.getKeySize() / 8;

		byte[] sharedSecret = null;

		if (this.algSign == AlgorithmID.EDDSA) {
			sharedSecret = generateSharedSecretEdDSA(senderCtx.getPrivateKey(), recipientPublicKey);
		} else if (this.algSign == AlgorithmID.ECDSA_256 || this.algSign == AlgorithmID.ECDSA_384
				|| this.algSign == AlgorithmID.ECDSA_512) {
			sharedSecret = generateSharedSecretECDSA(senderCtx.getPrivateKey(), recipientPublicKey);
		} else {
			System.err.println("Error: Unknown countersignature!");
		}

		// Then derive the pairwise sender key (for this recipient)
		info = CBORObject.NewArray();
		info.Add(senderCtx.getSenderId());
		info.Add(this.idContext);
		info.Add(this.aeadAlg.AsCBOR());
		info.Add(CBORObject.FromObject("Key"));
		info.Add(this.aeadAlg.getKeySize() / 8);

		byte[] keysConcatenated = Bytes.concatenate(senderCtx.getPublicKeyRaw(), recipientPublicKeyRaw);
		byte[] ikmSender = Bytes.concatenate(keysConcatenated, sharedSecret);

		byte[] pairwiseSenderKey = null;
		try {
			pairwiseSenderKey = OSCoreCtx.deriveKey(ikmSender, senderCtx.getSenderKey(), keyLength, digest,
					info.EncodeToBytes());

		} catch (CoseException e) {
			System.err.println(e.getMessage());
		}

		return pairwiseSenderKey;
	}

	byte[] derivePairwiseRecipientKey(byte[] recipientId, byte[] recipientKey, OneKey recipientPublicKey,
			byte[] recipientPublicKeyRaw) {

		if (recipientPublicKey == null || senderCtx.getPrivateKey() == null) {
			return null;
		}

		String digest = "";
		if (algKeyAgreement.toString().contains("HKDF_256")) {
			digest = "SHA256";
		} else if (algKeyAgreement.toString().contains("HKDF_512")) {
			digest = "SHA512";
		}
		CBORObject info = CBORObject.NewArray();
		int keyLength = this.aeadAlg.getKeySize() / 8;

		byte[] pairwiseRecipientKey = null;

		// First derive the recipient key
		info = CBORObject.NewArray();
		info.Add(recipientId);
		info.Add(this.idContext);
		info.Add(this.aeadAlg.AsCBOR());
		info.Add(CBORObject.FromObject("Key"));
		info.Add(keyLength);

		byte[] sharedSecret = null;

		if (this.algSign == AlgorithmID.EDDSA) {
			sharedSecret = generateSharedSecretEdDSA(senderCtx.getPrivateKey(), recipientPublicKey);
		} else if (this.algSign == AlgorithmID.ECDSA_256 || this.algSign == AlgorithmID.ECDSA_384
				|| this.algSign == AlgorithmID.ECDSA_512) {
			sharedSecret = generateSharedSecretECDSA(senderCtx.getPrivateKey(), recipientPublicKey);
		} else {
			System.err.println("Error: Unknown countersignature!");
		}

		byte[] keysConcatenated = Bytes.concatenate(recipientPublicKeyRaw, senderCtx.getPublicKeyRaw());
		byte[] ikmRecipient = Bytes.concatenate(keysConcatenated, sharedSecret);

		try {
			pairwiseRecipientKey = OSCoreCtx.deriveKey(ikmRecipient, recipientKey, keyLength, digest,
					info.EncodeToBytes());

		} catch (CoseException e) {
			System.err.println(e.getMessage());
		}

		return pairwiseRecipientKey;
	}

	/**
	 * Generate a shared secret when using ECDSA.
	 * 
	 * @param senderPrivateKey the public/private key of the sender
	 * @param recipientPublicKey the public key of the recipient
	 * @return the shared secret
	 */
	private byte[] generateSharedSecretECDSA(OneKey senderPrivateKey, OneKey recipientPublicKey) {

		byte[] sharedSecret = null;

		try {
			ECPublicKey recipientPubKey = (ECPublicKey) recipientPublicKey.AsPublicKey();
			ECPrivateKey senderPrivKey = (ECPrivateKey) senderPrivateKey.AsPrivateKey();

			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
			keyAgreement.init(senderPrivKey);
			keyAgreement.doPhase(recipientPubKey, true);

			sharedSecret = keyAgreement.generateSecret();
		} catch (GeneralSecurityException | CoseException e) {
			System.err.println("Could not generate the shared secret: " + e);
		}

		return sharedSecret;
	}

	/**
	 * Generate a shared secret when using EdDSA.
	 * 
	 * @param senderPrivateKey the public/private key of the sender
	 * @param recipientPublicKey the public key of the recipient
	 * @return the shared secret
	 */
	private byte[] generateSharedSecretEdDSA(OneKey senderPrivateKey, OneKey recipientPublicKey) {

		byte[] sharedSecret = null;
		try {
			sharedSecret = SharedSecretCalculation.calculateSharedSecret(recipientPublicKey, senderPrivateKey);
		} catch (CoseException e) {
			System.err.println("Could not generate the shared secret: " + e);
		}

		return sharedSecret;
	}

	/**
	 * Get the group encryption key from the common context (used for making a
	 * keystream to encrypt the signature).
	 * 
	 * @return the group encryption key
	 */
	public byte[] getGroupEncryptionKey() {
		return groupEncryptionKey;
	}

    /**
     *  Compute a hash value using the specified algorithm 
     * @param input   The content to hash
     * @param algorithm   The name of the hash algorithm to use
     * @return  the computed hash, or null in case of invalid input
     */
	public static byte[] computeHash (byte[] input, String algorithm) throws NoSuchAlgorithmException {
		
		if (input == null)
			return null;
		
		MessageDigest myDigest;
		
		if (algorithm.equals("SHA-256"))
			myDigest = MessageDigest.getInstance("SHA-256");
		else if (algorithm.equals("SHA-512"))
			myDigest = MessageDigest.getInstance("SHA-512");
		else
			return null;
		
		myDigest.reset();
		myDigest.update(input);
		return myDigest.digest();
		
	}

	/**
	 * HKDF Extract-and-Expand.
	 * 
	 * @param salt optional salt value
	 * @param ikm input keying material
	 * @param info context and application specific information
	 * @param len length of output keying material in octets
	 * @return output keying material
	 * 
	 * @throws InvalidKeyException if the HMAC procedure fails
	 * @throws NoSuchAlgorithmException if an unknown HMAC is used
	 */
	public static byte[] extractExpand(byte[] salt, byte[] ikm, byte[] info, int len)
			throws InvalidKeyException, NoSuchAlgorithmException {

		final String digest = "SHA256"; // Hash to use

		String HMAC_ALG_NAME = "Hmac" + digest;
		Mac hmac = Mac.getInstance(HMAC_ALG_NAME);
		int hashLen = hmac.getMacLength();

		// Perform extract
		if (salt.length == 0) {
			salt = new byte[] { 0x00 };
		}
		hmac.init(new SecretKeySpec(salt, HMAC_ALG_NAME));
		byte[] prk = hmac.doFinal(ikm);

		// Perform expand
		hmac.init(new SecretKeySpec(prk, HMAC_ALG_NAME));
		int c = (len / hashLen) + 1;
		byte[] okm = new byte[len];
		int maxLen = (hashLen * c > len) ? hashLen * c : len;
		byte[] T = new byte[maxLen];
		byte[] last = new byte[0];
		for (int i = 0; i < c; i++) {
			hmac.reset();
			hmac.update(last);
			hmac.update(info);
			hmac.update((byte) (i + 1));
			last = hmac.doFinal();
			System.arraycopy(last, 0, T, i * hashLen, hashLen);
		}
		System.arraycopy(T, 0, okm, 0, len);
		return okm;
	}

}
