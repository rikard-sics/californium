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

import java.util.HashMap;
import java.util.Map.Entry;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.ByteId;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.junit.Assert;

public class GroupSenderCtx extends OSCoreCtx {

	GroupCtx commonCtx;
	OneKey ownPrivateKey;

	HashMap<ByteId, byte[]> pairwiseSenderKeys;

	public GroupSenderCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id, byte[] recipient_id,
			AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] contextId, OneKey ownPrivateKey,
			GroupCtx commonCtx) throws OSException {
		super(master_secret, client, alg, sender_id, recipient_id, kdf, replay_size, master_salt, contextId);

		this.commonCtx = commonCtx;
		this.ownPrivateKey = ownPrivateKey;

		pairwiseSenderKeys = new HashMap<ByteId, byte[]>();
	}

	/**
	 * Derive pairwise keys for this sender context and all associated recipient
	 * contexts
	 */
	void derivePairwiseKeys() {

		for (Entry<ByteId, GroupRecipientCtx> entry : commonCtx.recipientCtxMap.entrySet()) {
			GroupRecipientCtx recipientCtx = entry.getValue();

			ByteId rid = new ByteId(recipientCtx.getRecipientId());
			
			// If the key has already been generated skip it
			if (pairwiseSenderKeys.get(rid) != null) {
				continue;
			}

			byte[] pairwiseSenderKey = commonCtx.derivePairwiseSenderKey(recipientCtx.getRecipientId(),
					recipientCtx.getRecipientKey(), recipientCtx.getPublicKey());
			pairwiseSenderKeys.put(rid, pairwiseSenderKey);

		}
	}

	// TODO: Implement elsewhere to avoid cast?
	public boolean getPairwiseModeResponses() {
		return commonCtx.pairwiseModeResponses;
	}

	// TODO: Implement elsewhere to avoid cast?
	@Deprecated
	public boolean getPairwiseModeRequests() {
		return commonCtx.pairwiseModeRequests;
	}

	public byte[] getPairwiseSenderKey(byte[] recipientId) {
		return pairwiseSenderKeys.get(new ByteId(recipientId));
	}

	public AlgorithmID getAlgCountersign() {
		return commonCtx.algCountersign;
	}

	public int getCountersignatureLen() {
		return commonCtx.getCountersignatureLen();
	}

	public int[][] getParCountersign() {
		return commonCtx.parCountersign;
	}

	public int[] getParCountersignKey() {
		return commonCtx.parCountersignKey;
	}

	public OneKey getPrivateKey() {
		return ownPrivateKey;
	}

	@Override
	protected GroupSenderCtx getSenderCtx() {
		return this;
	}

	/** ------- TODO: Remove methods below ------- */

	public OneKey getPublicKey() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getPublicKey on GroupSenderCtx" + stackTraceElements[2].toString());
		return null;
	}

	// Rikard: Generate a key to be used for Countersignatures
	public static void generateCounterSignKey(AlgorithmID alg) throws CoseException {
		OneKey myKey = OneKey.generateKey(alg);

		// Print base64 encoded version with both public & private keys
		byte[] keyObjectBytes = myKey.AsCBOR().EncodeToBytes();
		String base64_encoded = DatatypeConverter.printBase64Binary(keyObjectBytes);
		System.out.println("Public & Private: " + base64_encoded);

		// Print base64 encoded version with only public keys
		keyObjectBytes = myKey.PublicKey().AsCBOR().EncodeToBytes();
		base64_encoded = DatatypeConverter.printBase64Binary(keyObjectBytes);
		System.out.println("Public only: " + base64_encoded);

	}


	/**
	 * @return size of recipient replay window
	 */
	@Override
	public int getRecipientReplaySize() {
		System.out.println("Bad call to getRecipientReplaySize");
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getRecipientReplaySize on GroupSenderCtx" + stackTraceElements[2].toString());
		Assert.fail();
		return recipient_replay_window_size;
	}

	/**
	 * @return recipient replay window
	 */
	@Override
	public int getRecipientReplayWindow() {
		System.out.println("Bad call to getRecipientReplayWindow");
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getRecipientReplayWindow on GroupSenderCtx" + stackTraceElements[2].toString());
		Assert.fail();
		return recipient_replay_window;
	}

	@Override
	public void setRecipientKey(byte[] recipientKey) {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to setRecipientKey on GroupSenderCtx" + stackTraceElements[2].toString());
		Assert.fail();
		Assert.fail();
		super.setRecipientKey(recipientKey);
	}

	/**
	 * @param seq the recipient sequence number to set
	 */
	public synchronized void setReceiverSeq(int seq) {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to setReceiverSeq on GroupSenderCtx" + stackTraceElements[2].toString());
		Assert.fail();
		super.setReceiverSeq(seq);
	}

	public int rollbackRecipientSeq() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to rollbackRecipientSeq on GroupSenderCtx" + stackTraceElements[2].toString());
		Assert.fail();
		return super.rollbackRecipientSeq();
	}

	public int rollbackRecipientReplay() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to rollbackRecipientReplay on GroupSenderCtx" + stackTraceElements[2].toString());
		Assert.fail();
		return super.rollbackRecipientReplay();
	}

	/**
	 * @return the repipient's identifier
	 */
	public byte[] getRecipientId() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		// System.err.println("Bad call to getRecipientId on GroupSenderCtx. " +
		// stackTraceElements[1].toString());
		System.err.println("Bad call to getRecipientId on GroupSenderCtx. " + stackTraceElements[2].toString());
		// System.err.println("Bad call to getRecipientId on GroupSenderCtx. " +
		// stackTraceElements[3].toString());
		Assert.fail();
		return super.getRecipientId();
	}

	/**
	 * @return get the receiver sequence number
	 */
	public synchronized int getReceiverSeq() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getReceiverSeq on GroupSenderCtx" + stackTraceElements[2].toString());
		Assert.fail();
		return super.getReceiverSeq();
	}

	/**
	 * @return get the recipient key
	 */
	public byte[] getRecipientKey() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getRecipientKey on GroupSenderCtx" + stackTraceElements[2].toString());
		Assert.fail();
		return super.getRecipientKey();
	}

}
