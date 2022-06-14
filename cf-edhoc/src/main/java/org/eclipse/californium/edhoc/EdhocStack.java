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

import com.upokecenter.cbor.CBORObject;

import java.util.HashMap;
import java.util.Set;

import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.stack.BaseCoapStack;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CongestionControlLayer;
import org.eclipse.californium.core.network.stack.ExchangeCleanupLayer;
import org.eclipse.californium.core.network.stack.Layer;
import org.eclipse.californium.core.network.stack.ObserveLayer;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.ObjectSecurityContextLayer;
import org.eclipse.californium.oscore.ObjectSecurityLayer;

/**
 * 
 * Extends the BaseCoapStack and adds the ObjectSecurityLayer and EdhocLayer.
 *
 */
public class EdhocStack extends BaseCoapStack {

	/**
	 * Creates a new stack for UDP as the transport.
	 * 
	 * @param tag logging tag
	 * @param config The configuration values to use.
	 * @param outbox The adapter for submitting outbound messages to the
	 *            transport.
	 * @param ctxDb context DB.
	 * @param edhocSessions map containing EDHOC sessions
	 * @param peerPublicKeys map containing the EDHOC peer public keys
	 * @param peerCredentials map containing the EDHOC peer credentials
	 * @param usedConnectionIds list containing the used EDHOC connection IDs
	 * @param OSCORE_REPLAY_WINDOW size of the Replay Window to use in an OSCORE Recipient Context
	 * @param MAX_UNFRAGMENTED_SIZE size of MAX_UNFRAGMENTED_SIZE to use in an OSCORE Security Context
	 * 
	 */
	public EdhocStack(String tag, final Configuration config, final Outbox outbox, final OSCoreCtxDB ctxDb,
			HashMap<CBORObject, EdhocSession> edhocSessions, HashMap<CBORObject, OneKey> peerPublicKeys,
			HashMap<CBORObject, CBORObject> peerCredentials, Set<CBORObject> usedConnectionIds,
			int OSCORE_REPLAY_WINDOW, int MAX_UNFRAGMENTED_SIZE) {
		super(outbox);

		Layer layers[] = new Layer[] { new ObjectSecurityContextLayer(ctxDb), new ExchangeCleanupLayer(config),
				new ObserveLayer(config), new BlockwiseLayer(tag, false, config),
				CongestionControlLayer.newImplementation(tag, config), new ObjectSecurityLayer(ctxDb),
				new EdhocLayer(ctxDb, edhocSessions, peerPublicKeys, peerCredentials,
						       usedConnectionIds, OSCORE_REPLAY_WINDOW, MAX_UNFRAGMENTED_SIZE) };
		setLayers(layers);
	}
	
}
