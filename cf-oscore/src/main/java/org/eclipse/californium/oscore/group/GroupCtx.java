/*******************************************************************************
 * Copyright (c) 2023 RISE SICS and others.
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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map.Entry;

import javax.crypto.KeyAgreement;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.EncryptCommon;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
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
	AlgorithmID algGroupEnc;
	int[][] parCountersign;
	AlgorithmID algKeyAgreement;
	int[][] parSecret;
	byte[] signatureEncryptionKey;
	byte[] gmPublicKey;
	CRED_FORMAT authCredFmt;

	public enum CRED_FORMAT {
		CWT(0), CCS(1), X509(2), C509(3);

		public final int value;

		private CRED_FORMAT(int value) {
			this.value = value;
		}
	}

	// Reference to the associated sender context
	public GroupSenderCtx senderCtx;

	// References to the associated recipient contexts
	public HashMap<ByteId, GroupRecipientCtx> recipientCtxMap;

	// References to public keys without existing contexts
	// (For dynamic context generation)
	// TODO: Avoid double storage
	HashMap<ByteId, OneKey> publicKeysMap;

	boolean pairwiseModeResponses = false;
	boolean pairwiseModeRequests = false;

	/**
	 * Construct a Group OSCORE context. Uses default value for authCredFmt and
	 * uses same algGroupEnc as aeadAlg.
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

		this(masterSecret, masterSalt, aeadAlg, hkdfAlg, idContext, algSign, aeadAlg, AlgorithmID.ECDH_SS_HKDF_256,
				gmPublicKey, CRED_FORMAT.CCS);

	}

	/**
	 * Construct a Group OSCORE context. Uses default value for authCredFmt.
	 * 
	 * @param masterSecret
	 * @param masterSalt
	 * @param aeadAlg
	 * @param hkdfAlg
	 * @param idContext
	 * @param algSign
	 * @param gmPublicKey
	 * @param algGroupEnc
	 * @param algKeyAgreement
	 */
	public GroupCtx(byte[] masterSecret, byte[] masterSalt, AlgorithmID aeadAlg, AlgorithmID hkdfAlg, byte[] idContext,
			AlgorithmID algSign, AlgorithmID algGroupEnc, AlgorithmID algKeyAgreement, byte[] gmPublicKey) {

		this(masterSecret, masterSalt, aeadAlg, hkdfAlg, idContext, algSign, algGroupEnc, algKeyAgreement, gmPublicKey,
				CRED_FORMAT.CCS);
	}

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
	 * @param algGroupEnc
	 * @param algKeyAgreement
	 * @param authCredFmt
	 */
	public GroupCtx(byte[] masterSecret, byte[] masterSalt, AlgorithmID aeadAlg, AlgorithmID hkdfAlg, byte[] idContext,
			AlgorithmID algSign, AlgorithmID algGroupEnc, AlgorithmID algKeyAgreement, byte[] gmPublicKey,
			CRED_FORMAT authCredFmt) {

		this.masterSecret = masterSecret;
		this.masterSalt = masterSalt;
		this.aeadAlg = aeadAlg;
		this.hkdfAlg = hkdfAlg;
		this.idContext = idContext;
		this.algSign = algSign;
		this.gmPublicKey = gmPublicKey;
		this.algGroupEnc = algGroupEnc;
		this.algKeyAgreement = algKeyAgreement;
		this.authCredFmt = authCredFmt;

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

		recipientCtx.setCommonIV(deriveCommonIv());

		recipientCtxMap.put(new ByteId(recipientId), recipientCtx);

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
		senderCtx.setCommonIV(deriveCommonIv());
		this.senderCtx = senderCtx;

		this.signatureEncryptionKey = deriveSignatureEncryptionKey();
	}

	//
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
		recipientCtx.setCommonIV(deriveCommonIv());

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
		senderCtx.setCommonIV(deriveCommonIv());
		this.senderCtx = senderCtx;

		this.signatureEncryptionKey = deriveSignatureEncryptionKey();
	}
	//

	/**
	 * Retrieve the public key for the Group Manager associated to this context.
	 * 
	 * @return the public key for the GM for this context
	 */
	public byte[] getGmPublicKey() {
		return gmPublicKey;
	}


	/**
	 * Retrieve the recipient contexts
	 * 
	 * @return the recipient contexts
	 */
	public HashMap<ByteId, GroupRecipientCtx> getRecipientContexts() {
		return recipientCtxMap;
	}

	/**
	 * Retrieve the sender context
	 * 
	 * @return the sender context
	 */

	public GroupSenderCtx getSenderCtx() {
		return senderCtx;
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

	}

	// TODO: Merge with below?
	byte[] deriveSignatureEncryptionKey() {

		String digest = "";
		if (senderCtx.getKdf().toString().contains("SHA_256")) {
			digest = "SHA256";
		} else if (senderCtx.getKdf().toString().contains("SHA_512")) {
			digest = "SHA512";
		}

		CBORObject info = CBORObject.NewArray();
		int keyLength = this.algGroupEnc.getKeySize() / 8;

		// Then derive the signature encryption key
		info = CBORObject.NewArray();
		info.Add(Bytes.EMPTY);
		info.Add(this.idContext);
		// https://datatracker.ietf.org/doc/html/draft-ietf-core-oscore-groupcomm-17#section-2.1.6
		info.Add(this.algGroupEnc.AsCBOR());
		info.Add(CBORObject.FromObject("SEKey"));
		info.Add(keyLength);

		byte[] signatureEncryptionKey = null;
		try {
			signatureEncryptionKey = OSCoreCtx.deriveKey(senderCtx.getMasterSecret(), senderCtx.getSalt(), keyLength,
					digest, info.EncodeToBytes());

		} catch (CoseException e) {
			System.err.println(e.getMessage());
		}

		return signatureEncryptionKey;
	}

	// TODO: Merge with below?
	byte[] derivePairwiseSenderKey(byte[] recipientId, byte[] recipientKey, OneKey recipientPublicKey,
			byte[] recipientPublicKeyRaw) {

		// TODO: Move? See below also
		if (recipientPublicKey == null || senderCtx.getPrivateKey() == null) {
			return null;
		}

		String digest = "";
		if (senderCtx.getKdf().toString().contains("SHA_256")) {
			digest = "SHA256";
		} else if (senderCtx.getKdf().toString().contains("SHA_512")) {
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

		System.out.println("derivePairwiseSenderKey");
		System.out.println("sharedSecret: " + StringUtil.byteArray2HexString(sharedSecret));
		System.out.println("keysConcatenated: " + StringUtil.byteArray2HexString(sharedSecret));
		System.out.println("ikmSender: " + StringUtil.byteArray2HexString(sharedSecret));

		byte[] keysConcatenated = Bytes.concatenate(senderCtx.getPublicKeyRaw(), recipientPublicKeyRaw);
		byte[] ikmSender = Bytes.concatenate(keysConcatenated, sharedSecret);

		byte[] pairwiseSenderKey = null;
		try {
			pairwiseSenderKey = OSCoreCtx.deriveKey(ikmSender, senderCtx.getSenderKey(), keyLength, digest,
					info.EncodeToBytes());

		} catch (CoseException e) {
			System.err.println(e.getMessage());
		}

		System.out.println("pairwiseSenderKey: " + StringUtil.byteArray2HexString(pairwiseSenderKey));

		return pairwiseSenderKey;
	}

	byte[] derivePairwiseRecipientKey(byte[] recipientId, byte[] recipientKey, OneKey recipientPublicKey,
			byte[] recipientPublicKeyRaw) {

		if (recipientPublicKey == null || senderCtx.getPrivateKey() == null) {
			return null;
		}

		String digest = "";
		if (senderCtx.getKdf().toString().contains("SHA_256")) {
			digest = "SHA256";
		} else if (senderCtx.getKdf().toString().contains("SHA_512")) {
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

		System.out.println("derivePairwiseRecipientKey");
		System.out.println("sharedSecret: " + StringUtil.byteArray2HexString(sharedSecret));
		System.out.println("keysConcatenated: " + StringUtil.byteArray2HexString(sharedSecret));
		System.out.println("ikmRecipient: " + StringUtil.byteArray2HexString(sharedSecret));

		byte[] keysConcatenated = Bytes.concatenate(recipientPublicKeyRaw, senderCtx.getPublicKeyRaw());
		byte[] ikmRecipient = Bytes.concatenate(keysConcatenated, sharedSecret);

		try {
			pairwiseRecipientKey = OSCoreCtx.deriveKey(ikmRecipient, recipientKey, keyLength, digest,
					info.EncodeToBytes());

		} catch (CoseException e) {
			System.err.println(e.getMessage());
		}

		System.out.println("pairwiseRecipientKey: " + StringUtil.byteArray2HexString(pairwiseRecipientKey));

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
	 * Get the signature encryption key from the common context (used for making a
	 * keystream to encrypt the signature).
	 * 
	 * @return the signature encryption key
	 */
	public byte[] getSignatureEncryptionKey() {
		return signatureEncryptionKey;
	}

	/**
	 * Derive Common IV with its length being equal to the longest nonce length
	 * of: 1. AEAD Algorithm 2. Group Encryption Algorithm
	 * 
	 * @return the derived Common IV value
	 */
	byte[] deriveCommonIv() throws OSException {

		// Set digest value depending on HKDF
		String digest = null;
		switch (hkdfAlg) {
		case HKDF_HMAC_SHA_256:
			digest = "SHA256";
			break;
		case HKDF_HMAC_SHA_512:
			digest = "SHA512";
			break;
		case HKDF_HMAC_AES_128:
		case HKDF_HMAC_AES_256:
		default:
			throw new OSException("HKDF algorithm not supported");
		}

		// Find length of Common IV to use
		int iv_length;
		if (aeadAlg == null) {
			iv_length = EncryptCommon.ivLength(algGroupEnc);
		} else if (algGroupEnc == null) {
			iv_length = EncryptCommon.ivLength(aeadAlg);
		} else {
			iv_length = (EncryptCommon.ivLength(algGroupEnc) > EncryptCommon.ivLength(aeadAlg))
					? EncryptCommon.ivLength(algGroupEnc)
					: EncryptCommon.ivLength(aeadAlg);
		}

		AlgorithmID ivAlg = null;
		if (algGroupEnc != null) {
			ivAlg = algGroupEnc;
		} else {
			ivAlg = aeadAlg;
		}
		// Derive common_iv
		CBORObject info = CBORObject.NewArray();
		info = CBORObject.NewArray();
		info.Add(Bytes.EMPTY);
		info.Add(idContext);
		info.Add(ivAlg.AsCBOR());
		info.Add(CBORObject.FromObject("IV"));
		info.Add(iv_length);

		byte[] derivedCommonIv = null;
		try {
			derivedCommonIv = OSCoreCtx.deriveKey(masterSecret, masterSalt, iv_length, digest, info.EncodeToBytes());
		} catch (CoseException e) {
			throw new OSException("Failed to derive Common IV");
		}

		return derivedCommonIv;
	}
}
