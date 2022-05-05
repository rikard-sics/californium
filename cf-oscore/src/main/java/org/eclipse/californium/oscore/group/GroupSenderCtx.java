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

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Base64;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.ByteId;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

/**
 * Class implementing a Group OSCORE sender context.
 *
 */
public class GroupSenderCtx extends OSCoreCtx {

	private final static int DEFAULT_MAX_UNFRAGMENTED_SIZE = 4096;

	GroupCtx commonCtx;
	OneKey ownPrivateKey;
	byte[] ownPublicKeyRaw = Bytes.EMPTY;

	HashMap<ByteId, byte[]> pairwiseSenderKeys;

	GroupSenderCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id, byte[] recipient_id,
			AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] contextId, OneKey ownPrivateKey,
			byte[] ownPublicKeyRaw, GroupCtx commonCtx) throws OSException {
		// Build OSCORE Context using OSCoreCtx constructor
		super(master_secret, client, alg, sender_id, recipient_id, kdf, replay_size, master_salt, contextId,
				DEFAULT_MAX_UNFRAGMENTED_SIZE);

		this.commonCtx = commonCtx;
		this.ownPrivateKey = ownPrivateKey;
		if (ownPublicKeyRaw != null) {
			this.ownPublicKeyRaw = ownPublicKeyRaw;
		}

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
					recipientCtx.getRecipientKey(), recipientCtx.getPublicKey(), recipientCtx.getPublicKeyRaw());
			pairwiseSenderKeys.put(rid, pairwiseSenderKey);

		}
	}

	/**
	 * Get if responses should use pairwise mode. // TODO: Implement elsewhere
	 * to avoid cast?
	 * 
	 * @return if responses should use pairwise mode
	 */
	public boolean getPairwiseModeResponses() {
		return commonCtx.pairwiseModeResponses;
	}

	// TODO: Implement elsewhere to avoid cast?
	@Deprecated
	public boolean getPairwiseModeRequests() {
		return commonCtx.pairwiseModeRequests;
	}

	/**
	 * Get the pairwise sender key for this context for a specific other
	 * recipient.
	 * 
	 * @param recipientId the recipient ID of the other party
	 * @return the pairwise sender key to recipient
	 */
	public byte[] getPairwiseSenderKey(byte[] recipientId) {
		return pairwiseSenderKeys.get(new ByteId(recipientId));
	}

	// Just for interop tests
	public void setAsymmetricSenderKey(OneKey key) {
		ownPrivateKey = key;
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
	 * Get the alg countersign key value for the external aad.
	 * 
	 * @return the alg countersign key value
	 */
	public int[] getParCountersignKey() {
		return commonCtx.parCountersign[1];
	}

	/**
	 * Get the private key associated to this sender context, meaning your own
	 * private key.
	 * 
	 * @return the private key
	 */
	public OneKey getPrivateKey() {
		return ownPrivateKey;
	}

	/**
	 * Get the raw bytes of the public key associated to this sender context,
	 * meaning your own public key.
	 * 
	 * @return the bytes of the public key
	 */
	public byte[] getPublicKeyRaw() {
		return ownPublicKeyRaw;
	}

	@Override
	protected GroupSenderCtx getSenderCtx() {
		return this;
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

	public OneKey getPublicKey() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getPublicKey on GroupSenderCtx" + stackTraceElements[2].toString());
		return null;
	}

	// Rikard: Generate a key to be used for Countersignatures
	public static void generateCounterSignKey(AlgorithmID alg) throws CoseException {
		OneKey myKey = OneKey.generateKey(alg);

		// Print base64 encoded version with both public & private keys
		byte[] keyObjectBytes = myKey.EncodeToBytes();
		String base64_encoded = Base64.encodeBytes(keyObjectBytes);
		System.out.println("Public & Private: " + base64_encoded);

		// Print base64 encoded version with only public keys
		OneKey publicKey = myKey.PublicKey();

		keyObjectBytes = publicKey.EncodeToBytes();
		base64_encoded = Base64.encodeBytes(keyObjectBytes);
		System.out.println("Public only: " + base64_encoded);

	}

	// /**
	// * @return size of recipient replay window
	// */
	// @Override
	// public int getRecipientReplaySize() {
	// System.out.println("Bad call to getRecipientReplaySize");
	// StackTraceElement[] stackTraceElements =
	// Thread.currentThread().getStackTrace();
	// System.err.println("Bad call to getRecipientReplaySize on GroupSenderCtx"
	// + stackTraceElements[2].toString());
	// Assert.fail();
	// return recipient_replay_window_size;
	// }
	//
	// /**
	// * @return recipient replay window
	// */
	// @Override
	// public int getRecipientReplayWindow() {
	// System.out.println("Bad call to getRecipientReplayWindow");
	// StackTraceElement[] stackTraceElements =
	// Thread.currentThread().getStackTrace();
	// System.err.println("Bad call to getRecipientReplayWindow on
	// GroupSenderCtx" + stackTraceElements[2].toString());
	// Assert.fail();
	// return recipient_replay_window;
	// }

	@Override
	public void setRecipientKey(byte[] recipientKey) {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to setRecipientKey on GroupSenderCtx" + stackTraceElements[2].toString());
		assert (false);
		super.setRecipientKey(recipientKey);
	}

	// /**
	// * @param seq the recipient sequence number to set
	// */
	// public synchronized void setReceiverSeq(int seq) {
	// StackTraceElement[] stackTraceElements =
	// Thread.currentThread().getStackTrace();
	// System.err.println("Bad call to setReceiverSeq on GroupSenderCtx" +
	// stackTraceElements[2].toString());
	// Assert.fail();
	// super.setReceiverSeq(seq);
	// }

	// public int rollbackRecipientSeq() {
	// StackTraceElement[] stackTraceElements =
	// Thread.currentThread().getStackTrace();
	// System.err.println("Bad call to rollbackRecipientSeq on GroupSenderCtx" +
	// stackTraceElements[2].toString());
	// Assert.fail();
	// return super.rollbackRecipientSeq();
	// }
	//
	// public int rollbackRecipientReplay() {
	// StackTraceElement[] stackTraceElements =
	// Thread.currentThread().getStackTrace();
	// System.err.println("Bad call to rollbackRecipientReplay on
	// GroupSenderCtx" + stackTraceElements[2].toString());
	// Assert.fail();
	// return super.rollbackRecipientReplay();
	// }

	/**
	 * @return the repipient's identifier
	 */
	@Override
	public byte[] getRecipientId() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		// System.err.println("Bad call to getRecipientId on GroupSenderCtx. " +
		// stackTraceElements[1].toString());
		System.err.println("Bad call to getRecipientId on GroupSenderCtx. " + stackTraceElements[2].toString());
		// System.err.println("Bad call to getRecipientId on GroupSenderCtx. " +
		// stackTraceElements[3].toString());
		assert (false);
		return super.getRecipientId();
	}

	/**
	 * @return get the receiver sequence number
	 */
	public synchronized int getReceiverSeq() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getReceiverSeq on GroupSenderCtx" + stackTraceElements[2].toString());
		assert (false);
		return super.getLowestRecipientSeq();
	}

	/**
	 * @return get the recipient key
	 */
	@Override
	public byte[] getRecipientKey() {
		StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
		System.err.println("Bad call to getRecipientKey on GroupSenderCtx" + stackTraceElements[2].toString());
		assert (false);
		return super.getRecipientKey();
	}

}
