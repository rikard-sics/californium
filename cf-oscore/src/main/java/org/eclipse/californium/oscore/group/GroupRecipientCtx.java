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

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;

/**
 * Class implementing a Group OSCORE Recipient context.
 *
 */
public class GroupRecipientCtx extends OSCoreCtx {

	private final static int DEFAULT_MAX_UNFRAGMENTED_SIZE = 4096;

	GroupCtx commonCtx;
	OneKey otherEndpointPubKey;
	byte[] otherEndpointPubKeyRaw = Bytes.EMPTY;

	byte[] pairwiseRecipientKey;

	GroupRecipientCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id,
			byte[] recipient_id, AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] contextId,
			OneKey otherEndpointPubKey, byte[] otherEndpointPubKeyRaw, GroupCtx commonCtx) throws OSException {
		// Build OSCORE Context using OSCoreCtx constructor
		super(master_secret, client, alg, sender_id, recipient_id, kdf, replay_size, master_salt, contextId, DEFAULT_MAX_UNFRAGMENTED_SIZE);

		this.commonCtx = commonCtx;
		this.otherEndpointPubKey = otherEndpointPubKey;
		if (otherEndpointPubKeyRaw != null) {
			this.otherEndpointPubKeyRaw = otherEndpointPubKeyRaw;
		}
		
		// Set sender key based on used algSignEnc
		byte[] derivedRecipientKey = deriveRecipientKey();
		this.setRecipientKey(derivedRecipientKey);

	}
	
	/**
	 * Derive Recipient Key based on used algSignEnc
	 * 
	 * @return the Recipient Key
	 * @throws OSException on key derivation failure
	 */
	byte[] deriveRecipientKey() throws OSException {

		// Set digest value depending on HKDF
		String digest = null;
		switch (this.getKdf()) {
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

		int keyLength = commonCtx.algSignEnc.getKeySize() / 8;

		// Derive recipient_key
		CBORObject info = CBORObject.NewArray();
		info.Add(this.getRecipientId());
		info.Add(getIdContext());
		info.Add(getCommonCtx().algSignEnc.AsCBOR());
		info.Add(CBORObject.FromObject("Key"));
		info.Add(keyLength);

		byte[] derivedRecipientKey = null;
		try {
			derivedRecipientKey = deriveKey(getMasterSecret(), getSalt(), keyLength, digest, info.EncodeToBytes());
		} catch (CoseException e) {
			throw new OSException("Failed to derive Recipient Key");
		}
		return derivedRecipientKey;
	}
	
	/**
	 * Get the public key associated to this recipient context, meaning the
	 * public key of the other endpoint.
	 * 
	 * @return the public key of the other endpoint
	 */
	public OneKey getPublicKey() {
		return otherEndpointPubKey;
	}
	
	/**
	 * Get the raw bytes of the public key associated to this recipient context,
	 * meaning the public key of the other endpoint.
	 * 
	 * @return the bytes of the public key of the other endpoint
	 */
	public byte[] getPublicKeyRaw() {
		return otherEndpointPubKeyRaw;
	}

	/**
	 * Get the raw bytes of the public key associated to this recipient context,
	 * meaning the public key of the other endpoint.
	 * 
	 * @return the bytes of the public key of the other endpoint
	 */
	public byte[] getPublicKeyRaw() {
		return otherEndpointPubKeyRaw;
	}

	/**
	 * Get the pairwise recipient key for this context.
	 * 
	 * @return the pairwise recipient key
	 */
	public byte[] getPairwiseRecipientKey() {
		return pairwiseRecipientKey;
	}

	/**
	 * Get the alg sign value.
	 * 
	 * @return the alg sign value
	 */
	public AlgorithmID getAlgSign() {
		return commonCtx.algSign;
	}

	/**
	 * Get the alg sign enc value.
	 * 
	 * @return the alg sign enc value
	 */
	public AlgorithmID getAlgSignEnc() {
		return commonCtx.algSignEnc;
	}

	/**
	 * Get the alg pairwise key agreement value.
	 * 
	 * @return the alg pairwise key agreement value.
	 */
	public AlgorithmID getAlgKeyAgreement() {
		return commonCtx.algKeyAgreement;
	}

	/**
	 * Get the length of the countersignature depending on the countersignature
	 * algorithm currently used.
	 * 
	 * @return the length of the countersiganture
	 */
	public int getCountersignatureLen() {
		return commonCtx.getCountersignatureLen();
	}

	/**
	 * Get the par countersign value for the external aad.
	 * 
	 * @return the par countersign value
	 */
	public int[][] getParCountersign() {
		return commonCtx.parCountersign;
	}

	/**
	 * Get the par countersign key value for the external aad.
	 * 
	 * @return the par countersign key value
	 */
	public int[] getParCountersignKey() {
		return commonCtx.parCountersign[1];
	}

	@Override
	protected GroupSenderCtx getSenderCtx() {
		return commonCtx.senderCtx;
	}

	/**
	 * Derive pairwise recipient key for this recipient context and the
	 * associated sender context
	 */
	void derivePairwiseKey() {

		// If the key has already been generated skip it
		if (this.pairwiseRecipientKey != null) {
			return;
		}

		this.pairwiseRecipientKey = commonCtx.derivePairwiseRecipientKey(this.getRecipientId(), this.getRecipientKey(),
				this.getPublicKey(), this.getPublicKeyRaw());

	}


	// TODO: Change
	@Override
	public byte[] getSenderId() {
		// StackTraceElement[] stackTraceElements =
		// Thread.currentThread().getStackTrace();
		// System.err.println(
		// "Bad call to getSenderId on GroupRecipientCtx (Fixed)" +
		// stackTraceElements[2].toString());
		return getSenderCtx().getSenderId();
		// return sender_id;
	}
	
	/**
	 * Get the common context associated to this GroupSenderCtx.
	 * 
	 * @return the common context associated to this GroupSenderCtx
	 */
	public GroupCtx getCommonCtx() {
		return commonCtx;
	}

	/**
	 * Get the common context associated to this GroupSenderCtx.
	 * 
	 * @return the common context associated to this GroupSenderCtx
	 */
	public GroupCtx getCommonCtx() {
		return commonCtx;
	}

	// ------- TODO: Remove methods below -------

	/**
	 * 
	 * @return the private key
	 */


	/** ------- TODO: Remove methods below ------- */

	/**
	 * 
	 * @return the private key
	 */
	public OneKey getPrivateKey() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getPrivateKey on GroupRecipientCtx" + stackTraceElements[2].toString());
		assert (false);
		return null;
	}

	/**
	 * @return the receiver sequence number
	 */
	@Override
	public synchronized int getSenderSeq() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getSenderSeq on GroupRecipientCtx" + stackTraceElements[2].toString());
		assert (false);
		return sender_seq;
	}

	/**
	 * @return the recipient key
	 */
	@Override
	public byte[] getSenderKey() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getSenderKey on GroupRecipientCtx" + stackTraceElements[2].toString());
		System.out.println("Bad call to getSenderKey");
		assert (false);
		return sender_key;
	}

}
