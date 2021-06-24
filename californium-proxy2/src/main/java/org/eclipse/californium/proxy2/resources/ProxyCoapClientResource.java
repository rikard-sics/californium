/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from org.eclipse.californium.proxy
 ******************************************************************************/

package org.eclipse.californium.proxy2.resources;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.proxy2.ClientEndpoints;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.CoapUriTranslator;
import org.eclipse.californium.proxy2.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resource that forwards a coap request with the proxy-uri, proxy-scheme,
 * URI-host, or URI-port option set to the desired coap server.
 */
public class ProxyCoapClientResource extends ProxyCoapResource {

	static final Logger LOGGER = LoggerFactory.getLogger(ProxyCoapClientResource.class);

	/**
	 * Time to wait for replies to the multicast request
	 * 
	 * RH: FIXME: Take from new option
	 */
	private static final int HANDLER_TIMEOUT = 1000;

	/**
	 * Maps scheme to client endpoints.
	 */
	private Map<String, ClientEndpoints> mapSchemeToEndpoints = new HashMap<>();
	/**
	 * Coap2Coap translator.
	 */
	private Coap2CoapTranslator translator;

	/**
	 * Create proxy resource for outgoing coap-requests.
	 * 
	 * @param name name of the resource
	 * @param visible visibility of the resource
	 * @param accept accept CON request before forwarding the request
	 * @param translator translator for coap2coap messages. {@code null} to use
	 *            default implementation {@link Coap2CoapTranslator}.
	 * @param endpointsList list of client endpoints for outgoing requests
	 */
	public ProxyCoapClientResource(String name, boolean visible, boolean accept, Coap2CoapTranslator translator,
			ClientEndpoints... endpointsList) {
		// set the resource hidden
		super(name, visible, accept);
		getAttributes().setTitle("Forward the requests to a CoAP server.");
		this.translator = translator != null ? translator : new Coap2CoapTranslator();
		for (ClientEndpoints endpoints : endpointsList) {
			this.mapSchemeToEndpoints.put(endpoints.getScheme(), endpoints);
		}
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		Request incomingRequest = exchange.getRequest();
		LOGGER.debug("ProxyCoapClientResource forwards {}", incomingRequest);

		try {
			// create the new request from the original
			InetSocketAddress exposedInterface = translator.getExposedInterface(incomingRequest);
			URI destination = translator.getDestinationURI(incomingRequest, exposedInterface);
			Request outgoingRequest = translator.getRequest(destination, incomingRequest);
			// execute the request
			if (outgoingRequest.getDestinationContext() == null) {
				exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
				throw new NullPointerException("Destination is null");
			}
			CacheKey cacheKey = null;
			CacheResource cache = getCache();
			if (cache != null) {
				cacheKey = new CacheKey(outgoingRequest.getCode(), destination, outgoingRequest.getOptions().getAccept(), outgoingRequest.getPayload());
				Response response = cache.getResponse(cacheKey);
				StatsResource statsResource = getStatsResource();
				if (statsResource != null) {
					statsResource.updateStatistics(destination, response != null);
				}
				if (response != null) {
					LOGGER.info("Cache returned {}", response);
					exchange.sendResponse(response);
					return;
				}
			}
			LOGGER.debug("Sending proxied CoAP request to {}", outgoingRequest.getDestinationContext());
			if (accept) {
				exchange.sendAccept();
			}

			outgoingRequest
					.addMessageObserver(new ProxySendResponseMessageObserver(translator, exchange, cacheKey, cache));

			/* --- RH: Handle multicast requests --- */

			// If destination is multicast use NON
			InetAddress add = null;
			try {
				add = InetAddress.getByName(destination.getHost());
			} catch (UnknownHostException e) {
				System.err.println("Failed to parse request URI into an InetAddress: " + e);
				e.printStackTrace();
			}
			if (add.isMulticastAddress()) {
				outgoingRequest.setType(Type.NON);

				// Send using multicast handler
				CoapClient client = new CoapClient();
				// client.setEndpoint(endpoint); // Needed?
				client.setURI(destination.toString());

				handler.clearResponses();
				client.advanced(handler, outgoingRequest);
				// RH: Needed to use the handler at all? Since it seems to
				// handle responses coming in individually in onResponse
				while (handler.waitOn(HANDLER_TIMEOUT)) {
					// Wait for responses
				}
			}

			/* --- End Handle multicast requests --- */

			if (!add.isMulticastAddress()) {
				ClientEndpoints endpoints = mapSchemeToEndpoints.get(outgoingRequest.getScheme());
				endpoints.sendRequest(outgoingRequest);
			}
		} catch (TranslationException e) {
			LOGGER.debug("Proxy-uri option malformed: {}", e.getMessage());
			Response response = new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED);
			response.setPayload(e.getMessage());
			exchange.sendResponse(response);
		} catch (Exception e) {
			LOGGER.warn("Failed to execute request: {}", e.getMessage(), e);
			exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public CoapUriTranslator getUriTranslater() {
		return translator;
	}

	@Override
	public Set<String> getDestinationSchemes() {
		return Collections.unmodifiableSet(mapSchemeToEndpoints.keySet());
	}

	private static class ProxySendResponseMessageObserver extends MessageObserverAdapter {

		private final Coap2CoapTranslator translator;
		private final Exchange incomingExchange;
		private final CacheKey cacheKey;
		private final CacheResource cache;
		private final ProxyCoapResource baseResource;

		private ProxySendResponseMessageObserver(Coap2CoapTranslator translator, Exchange incomingExchange,
				CacheKey cacheKey, CacheResource cache, ProxyCoapResource baseResource) {
			this.translator = translator;
			this.incomingExchange = incomingExchange;
			this.cacheKey = cacheKey;
			this.cache = cache;
			this.baseResource = baseResource;
		}

		@Override
		public void onResponse(Response incomingResponse) {
			int size = incomingResponse.getPayloadSize();
			if (!baseResource.checkMaxResourceBodySize(size)) {
				incomingResponse = new Response(ResponseCode.BAD_GATEWAY);
				incomingResponse.setPayload("CoAP response of " + size + " bytes exceeds maximum support size of "
						+ baseResource.getMaxResourceBodySize() + " bytes!");
				incomingResponse.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			}
			if (cache != null) {
				cache.cacheResponse(cacheKey, incomingResponse);
			}
			ProxyCoapClientResource.LOGGER.debug("ProxyCoapClientResource received {}", incomingResponse);
			incomingExchange.sendResponse(translator.getResponse(incomingResponse));
		}

		@Override
		public void onReject() {
			fail(ResponseCode.SERVICE_UNAVAILABLE);
			ProxyCoapClientResource.LOGGER.debug("Request rejected");
		}

		@Override
		public void onTimeout() {
			fail(ResponseCode.GATEWAY_TIMEOUT);
			ProxyCoapClientResource.LOGGER.debug("Request timed out.");
		}

		@Override
		public void onCancel() {
			fail(ResponseCode.SERVICE_UNAVAILABLE);
			ProxyCoapClientResource.LOGGER.debug("Request canceled");
		}

		@Override
		public void onSendError(Throwable e) {
			fail(ResponseCode.SERVICE_UNAVAILABLE);
			ProxyCoapClientResource.LOGGER.warn("Send error", e);
		}

		private void fail(ResponseCode response) {
			incomingExchange.sendResponse(new Response(response));
		}
	}

	/*** RH: Multicast handler for sending multicast requests ***/

	private static final MultiCoapHandler handler = new MultiCoapHandler();

	private static class MultiCoapHandler implements CoapHandler {

		List<CoapResponse> responses = new ArrayList<CoapResponse>();

		private boolean on;

		public List<CoapResponse> getResponses() {
			return responses;
		}

		public void clearResponses() {
			responses.clear();
		}

		public synchronized boolean waitOn(long timeout) {
			on = false;
			try {
				wait(timeout);
			} catch (InterruptedException e) {
			}
			return on;
		}

		private synchronized void on() {
			on = true;
			notifyAll();
		}

		/**
		 * Handle and parse incoming responses.
		 */
		@Override
		public void onLoad(CoapResponse response) {
			on();

			// System.out.println("Receiving to: "); //TODO
			System.out.println("Receiving from: " + response.advanced().getSourceContext().getPeerAddress());

			responses.add(response);
			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	}
}
