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

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.junit.Assert;

/**
 * Class implementing a Group OSCORE Recipient context.
 *
 */
public class GroupRecipientCtx extends OSCoreCtx {

	GroupCtx commonCtx;
	OneKey otherEndpointPubKey;
	byte[] otherEndpointPubKeyRaw = Bytes.EMPTY;

	byte[] pairwiseRecipientKey;

	GroupRecipientCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id,
			byte[] recipient_id, AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] contextId,
			OneKey otherEndpointPubKey, byte[] otherEndpointPubKeyRaw, GroupCtx commonCtx) throws OSException {
		super(master_secret, client, alg, sender_id, recipient_id, kdf, replay_size, master_salt, contextId);

		this.commonCtx = commonCtx;
		this.otherEndpointPubKey = otherEndpointPubKey;
		if (otherEndpointPubKeyRaw != null) {
			this.otherEndpointPubKeyRaw = otherEndpointPubKeyRaw;
		}
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
	 * Get the pairwise recipient key for this context.
	 * 
	 * @return the pairwise recipient key
	 */
	public byte[] getPairwiseRecipientKey() {
		return pairwiseRecipientKey;
	}

	/**
	 * Get the alg countersign value.
	 * 
	 * @return the alg countersign value
	 */
	public AlgorithmID getAlgCountersign() {
		return commonCtx.algCountersign;
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

	// ------- TODO: Remove methods below -------

	/**
	 * 
	 * @return the private key
	 */
	public OneKey getPrivateKey() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getPrivateKey on GroupRecipientCtx" + stackTraceElements[2].toString());
		Assert.fail();
		return null;
	}

	/**
	 * @return the receiver sequence number
	 */
	@Override
	public synchronized int getSenderSeq() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getSenderSeq on GroupRecipientCtx" + stackTraceElements[2].toString());
		Assert.fail();
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
		Assert.fail();
		return sender_key;
	}

}
