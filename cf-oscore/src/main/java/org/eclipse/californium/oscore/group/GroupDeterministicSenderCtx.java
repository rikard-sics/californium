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

/**
 * Class implementing a Group OSCORE sender context.
 *
 */
public class GroupDeterministicSenderCtx extends OSCoreCtx {

	GroupCtx commonCtx;
	String hashAlg;

	GroupDeterministicSenderCtx(byte[] master_secret, boolean client, AlgorithmID alg, byte[] sender_id, byte[] recipient_id,
			AlgorithmID kdf, Integer replay_size, byte[] master_salt, byte[] contextId, String hashAlg,
			GroupCtx commonCtx) throws OSException {
		super(master_secret, client, alg, sender_id, recipient_id, kdf, replay_size, master_salt, contextId);

		this.commonCtx = commonCtx;
		this.hashAlg = hashAlg;
		
	}

	protected GroupDeterministicSenderCtx getDeterministicSenderCtx() {
		return this;
	}
	
	@Override
	public GroupSenderCtx getSenderCtx() {
		return commonCtx.senderCtx;
	}
	
	/**
	 * Get the hash algorithm
	 * 
	 * @return the hash algorithm
	 */
	public String getHashAlg() {
		return hashAlg;
	}

}
