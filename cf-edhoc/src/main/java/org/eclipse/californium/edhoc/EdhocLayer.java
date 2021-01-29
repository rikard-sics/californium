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

import java.util.Map;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;

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
	 * Build the EdhocLayer taking as input the map of current EDHOC sessions
	 * 
	 * @param edhocSessions map of current EDHOC sessions
	 */
	public EdhocLayer(Map<CBORObject, EdhocSession> edhocSessions) {
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

}
