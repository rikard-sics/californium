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

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapStackFactory;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.ObjectSecurityLayer;

import com.upokecenter.cbor.CBORObject;

/**
 * Coap stack factory creating a {@link EdhocStack} including a
 * {@link ObjectSecurityLayer} and {@link EdhocLayer}.
 */
public class EdhocCoapStackFactory implements CoapStackFactory {

	private static AtomicBoolean init = new AtomicBoolean();
	private static volatile OSCoreCtxDB defaultCtxDb;
	private static volatile Map<CBORObject, EdhocSession> edhocSessions;
	private static volatile Map<CBORObject, OneKey> peerPublicKeys;
	private static volatile Map<CBORObject, CBORObject> peerCredentials;
	private static volatile List<Set<Integer>> usedConnectionIds;
	private static volatile int OSCORE_REPLAY_WINDOW;

	@Override
	// TODO: This method may need updating for the custom argument
	// This is only for when useAsDefault is not used
	public CoapStack createCoapStack(String protocol, String tag, NetworkConfig config, Outbox outbox,
			Object customStackArgument) {
		if (CoAP.isTcpProtocol(protocol)) {
			throw new IllegalArgumentException("protocol \"" + protocol + "\" is not supported!");
		}
		OSCoreCtxDB ctxDb = defaultCtxDb;
		if (customStackArgument != null) {
			ctxDb = (OSCoreCtxDB) customStackArgument;
		}
		return new EdhocStack(tag, config, outbox, ctxDb, edhocSessions, peerPublicKeys, peerCredentials,
				              usedConnectionIds, OSCORE_REPLAY_WINDOW);
	}

	/**
	 * Use {@link EdhocStack} as default for {@link CoapEndpoint}.
	 * 
	 * Note: the factory is only applied once with the first call, the
	 * {@link #defaultCtxDb} is update on every call.
	 * 
	 * @param defaultCtxDb default OSCORE context DB. Passed in as default
	 *            argument for {@link EdhocStack}
	 * @param edhocSessions map containing EDHOC sessions. Passed in as default
	 *            argument for {@link EdhocStack}
	 *            
	 * @param peerPublicKeys map containing the EDHOC peer public keys. Passed in as default
	 *            argument for {@link EdhocStack}
	 * @param edhocSessions map containing the EDHOC peer credentials. Passed in as default
	 *            argument for {@link EdhocStack}
	 * @param edhocSessions list containing the used EDHOC connection IDs. Passed in as default
	 *            argument for {@link EdhocStack}
	 * @param OSCORE_REPLAY_WINDOW size of the Replay Window to use in an OSCORE Recipient Context. Passed in as default
	 *            argument for {@link EdhocStack}
	 * 
	 * @see CoapEndpoint#setDefaultCoapStackFactory(CoapStackFactory)
	 */
	public static void useAsDefault(OSCoreCtxDB defaultCtxDb,
									Map<CBORObject, EdhocSession> edhocSessions,
									Map<CBORObject, OneKey> peerPublicKeys,
									Map<CBORObject, CBORObject> peerCredentials,
									List<Set<Integer>> usedConnectionIds,
									int OSCORE_REPLAY_WINDOW) {
		if (init.compareAndSet(false, true)) {
			CoapEndpoint.setDefaultCoapStackFactory(new EdhocCoapStackFactory());
		}
		EdhocCoapStackFactory.defaultCtxDb = defaultCtxDb;
		EdhocCoapStackFactory.edhocSessions = edhocSessions;
		EdhocCoapStackFactory.peerPublicKeys = peerPublicKeys;
		EdhocCoapStackFactory.peerCredentials = peerCredentials;
		EdhocCoapStackFactory.usedConnectionIds = usedConnectionIds;
		EdhocCoapStackFactory.OSCORE_REPLAY_WINDOW = OSCORE_REPLAY_WINDOW;
	}
}
