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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

import java.util.Arrays;
import java.util.Map;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;

/**
 * 
 * Applies EDHOC mechanics at stack layer.
 *
 */
public class EdhocLayer extends AbstractLayer {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(EdhocLayer.class);

	/**
	 * Map of existing EDHOC sessions
	 */
	Map<CBORObject, EdhocSession> edhocSessions;

	/**
	 * The OSCORE context database
	 */
	OSCoreCtxDB ctxDb;

	/**
	 * Build the EdhocLayer
	 * 
	 * @param ctxDb OSCORE context database
	 * @param edhocSessions map of current EDHOC sessions
	 */
	public EdhocLayer(OSCoreCtxDB ctxDb, Map<CBORObject, EdhocSession> edhocSessions) {
		this.ctxDb = ctxDb;
		this.edhocSessions = edhocSessions;

		LOGGER.warn("Initializing EDHOC layer");
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		LOGGER.warn("Sending request through EDHOC layer");

		super.sendRequest(exchange, request);
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {

		LOGGER.warn("Sending response through EDHOC layer");

		super.sendResponse(exchange, response);
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {

		LOGGER.warn("Receiving request through EDHOC layer");

		super.receiveRequest(exchange, request);
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {

		LOGGER.warn("Receiving response through EDHOC layer");

		super.receiveResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.receiveEmptyMessage(exchange, message);
	}

	/**
	 * Returns the OSCORE Context that was used to protect this outgoing
	 * exchange (outgoing request or response).
	 * 
	 * @param e the exchange
	 * @return the OSCORE Context used to protect the exchange (if any)
	 */
	private OSCoreCtx getContextForOutgoing(Exchange e) {
		byte[] rid = e.getCryptographicContextID();
		if (rid == null) {
			return null;
		} else {
			return ctxDb.getContext(rid);
		}
	}

	/**
	 * Retrieve KID value from an OSCORE option.
	 * 
	 * @param oscoreOption the OSCORE option
	 * @return the KID value
	 */
	static byte[] getKid(byte[] oscoreOption) {
		if (oscoreOption.length == 0) {
			return null;
		}

		// Parse the flag byte
		byte flagByte = oscoreOption[0];
		int n = flagByte & 0x07;
		int k = flagByte & 0x08;
		int h = flagByte & 0x10;

		byte[] kid = null;
		int index = 1;

		// Partial IV
		index += n;

		// KID Context
		if (h != 0) {
			int s = oscoreOption[index];
			index += s + 1;
		}

		// KID
		if (k != 0) {
			kid = Arrays.copyOfRange(oscoreOption, index, oscoreOption.length);
		}

		return kid;
	}

}