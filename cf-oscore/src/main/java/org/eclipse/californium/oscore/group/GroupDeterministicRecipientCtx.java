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
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.junit.Assert;

/**
 * Class implementing a Group OSCORE Recipient context.
 *
 */
public class GroupDeterministicRecipientCtx extends OSCoreCtx {

	GroupCtx commonCtx;
	String hashAlg;

	GroupDeterministicRecipientCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id,
			byte[] recipient_id, AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] contextId,
			int maxUnfragmentedSize, String hashAlg, GroupCtx commonCtx) throws OSException {
		super(master_secret, client, alg, sender_id, recipient_id, kdf, replay_size, master_salt, contextId, maxUnfragmentedSize);

		this.commonCtx = commonCtx;
		this.hashAlg = hashAlg;

	}

	protected GroupDeterministicRecipientCtx getDeterministicRecipientCtx() {
		return this;
	}
	
	/**
	 * Get the hash algorithm
	 * 
	 * @return the hash algorithm
	 */
	public String getHashAlg() {
		return hashAlg;
	}
	
	/**
	 * Get the size of a hash computed with the used 'hash' algorithm, in bytes
	 * 
	 * @return the size of the hash in bytes
	 */
	public int getHashSize() {
		int hashSize = 0;
		
		switch (this.hashAlg) {
			case "SHA-256":
				hashSize = 32;
		}
		
		return hashSize;
	}
	
	@Override
	public GroupSenderCtx getSenderCtx() {
		return commonCtx.senderCtx;
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

}
