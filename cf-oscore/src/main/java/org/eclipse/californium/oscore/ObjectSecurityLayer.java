/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;
import org.junit.Assert;

/**
 * 
 * Applies OSCORE mechanics at stack layer.
 *
 */
public class ObjectSecurityLayer extends AbstractLayer {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(ObjectSecurityLayer.class);

	private final OSCoreCtxDB ctxDb;

	public ObjectSecurityLayer(OSCoreCtxDB ctxDb) {
		if (ctxDb == null) {
			throw new NullPointerException("OSCoreCtxDB must be provided!");
		}
		this.ctxDb = ctxDb;
	}

	/**
	 * Encrypt an outgoing request using the OSCore context.
	 * 
	 * @param message the message
	 * @param ctxDb the context database used
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting request
	 */
	public static Request prepareSend(OSCoreCtxDB ctxDb, Request message) throws OSException {
		return RequestEncryptor.encrypt(ctxDb, message);
	}

	/**
	 * Encrypt an outgoing response using the OSCore context.
	 * 
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param newPartialIV boolean to indicate whether to use a new partial IV or not
	 * @param outerBlockwise boolean to indicate whether the block-wise options
	 *            should be encrypted or not
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting response
	 */
	public static Response prepareSend(OSCoreCtxDB ctxDb, Response message, OSCoreCtx ctx, final boolean newPartialIV,
			boolean outerBlockwise) throws OSException {
		return ResponseEncryptor.encrypt(ctxDb, message, ctx, newPartialIV, outerBlockwise);
	}

	/**
	 * Decrypt an incoming request using the right OSCore context
	 *
	 * @param ctxDb the context database used
	 * @param request the incoming request
	 * 
	 * @return the decrypted and verified request
	 * 
	 * @throws CoapOSException error while decrypting request
	 */
	public static Request prepareReceive(OSCoreCtxDB ctxDb, Request request) throws CoapOSException {
		return RequestDecryptor.decrypt(ctxDb, request);
	}

	/**
	 * Decrypt an incoming response using the right OSCore context
	 *
	 * @param ctxDb the context database used
	 * @param response the incoming request
	 * @return the decrypted and verified response
	 * 
	 * @throws OSException error while decrypting response
	 */
	public static Response prepareReceive(OSCoreCtxDB ctxDb, Response response) throws OSException {
		return ResponseDecryptor.decrypt(ctxDb, response);
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		Request req = request;
		if (shouldProtectRequest(request)) {
			try {
				// FIXME: Check


				OSCoreCtx a2 = null;
				if (exchange.getCurrentResponse() != null) {
					a2 = ctxDb.getContextByToken(exchange.getCurrentResponse().getToken());
				}
				boolean outerBlockwise = false;
				// System.out.println("!!!! a1 == null " + (a1 == null));
				// FIXME: Skip OSCORe to proxy all together???
				if (a2 != null && request.getOptions().hasBlock2() && exchange.getCurrentResponse() != null
						&& exchange.getCurrentResponse().getOptions().hasOscore()) {
					// Now this only happens for outer bw tests with FIXME
					System.out.println("Hello123 " + request.getMID());
					System.out.println("Hello123 " + exchange.getRequest().getMID());

					System.out.println("Hello123 " + exchange.getCurrentRequest().getMID());
					System.out.println("Hello123 " + exchange.getCurrentResponse().getMID());
					System.out.println("exchange.getCurrentResponse().getOptions().hasOscore()"
							+ (exchange.getCurrentResponse().getOptions().hasOscore()));
					System.out.println("exchange.getCurrentResponse().getOptions().getOscore().length != 0: "
							+ (exchange.getCurrentResponse().getOptions().getOscore().length != 0));

					System.out.println("Equality: " + exchange.getCurrentRequest().equals(exchange.getRequest()));
					
					System.out.println("Response curr: " + Utils.prettyPrint(exchange.getCurrentResponse()));
					if (exchange.getResponse() != null) {
						System.out.println("Response: " + Utils.prettyPrint(exchange.getResponse()));
					}

					System.out.println("Request curr: " + Utils.prettyPrint(exchange.getCurrentRequest()));
					if (exchange.getRequest() != null) {
						System.out.println("Request: " + Utils.prettyPrint(exchange.getRequest()));
					}
					System.out.println("exchange.getBlock1ToAck();" + exchange.getBlock1ToAck());

					System.out.println("exchange.getCryptographicContextID()"
							+ Utils.toHexString(exchange.getCryptographicContextID()));

					OSCoreCtx ll = ctxDb.getContext(request.getURI());
					System.out.println("ctx.getSenderSeq() " + ll.getSenderSeq());

					// Was originall skipped if no context for this Token
					// has block2 means its a requst with b2 for getting more
					// data. In such caes block2 should be outer!

					// exchange.getCurrentRequest().getToken()) or
					// exchange.getRequest().getToken()) instead?
					OSCoreCtx a1 = ctxDb.getContextByToken(exchange.getCurrentResponse().getToken());
					System.out.println("!!!! a1 == null " + (a1 == null));
					// Assert.fail("alal");

					// Skip except for last response?
					// MAKE SURE LAST RESPONSE IS DECRYPTED BY OSCORE

					// NOW ADD DECRYpTION in ObjectSecurityContxtLayer!

					// Shoud lit really skip protecting here? What if post data?
					// Just put external option?

					exchange.setCryptographicContextID(a1.getRecipientId()); // NEEDED????
					outerBlockwise = true;
					super.sendRequest(exchange, req);
					return;
				}

				String uri = request.getURI();

				if (uri == null) {
					LOGGER.error(ErrorDescriptions.URI_NULL);
					throw new OSException(ErrorDescriptions.URI_NULL);
				}

				OSCoreCtx ctx = ctxDb.getContext(uri);
				if (ctx == null) {
					LOGGER.error(ErrorDescriptions.CTX_NULL);
					throw new OSException(ErrorDescriptions.CTX_NULL);
				}

				// Initiate context re-derivation procedure if flag is set
				if (ctx.getContextRederivationPhase() == PHASE.CLIENT_INITIATE) {
					throw new IllegalStateException("must be handled in ObjectSecurityContextLayer!");
				}

				/*
				 * Sets an operator on the exchange. This operator will in
				 * turn set information about the OSCORE context used in the
				 * endpoint context that will be created after the request is sent.
				 */
				OSCoreEndpointContextInfo.sendingRequest(ctx, exchange);

				exchange.setCryptographicContextID(ctx.getRecipientId());
				final int seqByToken = ctx.getSenderSeq();

				final Request preparedRequest = prepareSend(ctxDb, request);
				final OSCoreCtx finalCtx = ctxDb.getContext(uri);

				preparedRequest.addMessageObserver(0, new MessageObserverAdapter() {

					@Override
					public void onReadyToSend() {
						Token token = preparedRequest.getToken();

						// add at head of message observers to update
						// the token of the original request first,
						// before calling other message observers!
						if (request.getToken() == null) {
							request.setToken(token);
						}

						ctxDb.addContext(token, finalCtx);
						ctxDb.addSeqByToken(token, seqByToken);
					}
				});

				req = preparedRequest;

			} catch (OSException e) {
				LOGGER.error("Error sending request: " + e.getMessage());
				return;
			} catch (IllegalArgumentException e) {
				LOGGER.error("Unable to send request because of illegal argument: " + e.getMessage());
				return;
			}
		}
		LOGGER.info("Request: " + exchange.getRequest().toString());
		super.sendRequest(exchange, req);
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {
		/* If the request contained the Observe option always add a partial IV to the response.
		 * A partial IV will also be added if the responsesIncludePartialIV flag is set in the context. */
		boolean addPartialIV;
		
		/*
		 * If the original request used outer block-wise options so should the
		 * response. (They are not encrypted but external unprotected options.)
		 */
		boolean outerBlockwise;

		if (shouldProtectResponse(exchange)) {
			// If the current block-request still has a non-empty OSCORE option it
			// means it was not unprotected by OSCORE as and individual request.
			// Rather it was not processed by OSCORE until after being re-assembled
			// by the block-wise layer. Thus the response should use outer block options.
			outerBlockwise = exchange.getCurrentRequest().getOptions().hasOscore()
					&& exchange.getCurrentRequest().getOptions().getOscore().length != 0;
			// FIXME: Should it skip protecting the response? (probably not)

			try {
				OSCoreCtx ctx = ctxDb.getContext(exchange.getCryptographicContextID());
				addPartialIV = ctx.getResponsesIncludePartialIV() || exchange.getRequest().getOptions().hasObserve();
				
				response = prepareSend(ctxDb, response, ctx, addPartialIV, outerBlockwise);
				exchange.setResponse(response);
			} catch (OSException e) {
				LOGGER.error("Error sending response: " + e.getMessage());
				return;
			}
			// Debug from server
			if (true) {
				System.out.println("RESPONSE SERVER: " + Utils.prettyPrint(response));
			}
		}

		super.sendResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {

		if (isProtected(request)) {

			// For OSCORE-protected requests with the outer block1-option let
			// them pass through to be re-assembled by the block-wise layer
			if (request.getOptions().hasBlock1()) {
				super.receiveRequest(exchange, request);
				return;
			}

			byte[] rid = null;
			try {
				request = prepareReceive(ctxDb, request);
				rid = request.getOptions().getOscore();
				request.getOptions().setOscore(Bytes.EMPTY);
				exchange.setRequest(request);
			} catch (CoapOSException e) {
				LOGGER.error("Error while receiving OSCore request: " + e.getMessage());
				Response error;
				error = CoapOSExceptionHandler.manageError(e, request);
				if (error != null) {
					super.sendResponse(exchange, error);
				}
				return;
			}
			exchange.setCryptographicContextID(rid);
		}
		super.receiveRequest(exchange, request);
	}

	//Always accepts unprotected responses, which is needed for reception of error messages
	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		Request request = exchange.getCurrentRequest();
		if (request == null) {
			LOGGER.error("No request tied to this response");
			return;
		}
		try {
			//Printing of status information.
			//Warns when expecting OSCORE response but unprotected response is received
			if (!isProtected(response) && responseShouldBeProtected(exchange, response)) {
				LOGGER.warn("Incoming response is NOT OSCORE protected!");
			} else if (isProtected(response)) {
				LOGGER.info("Incoming response is OSCORE protected");
			}

			// For OSCORE-protected response with the outer block2-option let
			// them pass through to be re-assembled by the block-wise layer
			if (response.getOptions().hasBlock2()) {
				// System.out.println("HELLO123213213213");
				// System.out.println(Utils.prettyPrint(response));
				super.receiveResponse(exchange, response);
				return;
			}

			//If response is protected with OSCORE parse it first with prepareReceive
			if (isProtected(response)) {
				response = prepareReceive(ctxDb, response);
			}
		} catch (OSException e) {
			LOGGER.error("Error while receiving OSCore response: " + e.getMessage());
			EmptyMessage error = CoapOSExceptionHandler.manageError(e, response);
			if (error != null) {
				sendEmptyMessage(exchange, error);
			}
			return;
		}
		
		//Remove token if this is a response to a Observe cancellation request
		if (exchange.getRequest().isObserveCancel()) {
			ctxDb.removeToken(response.getToken());
		}
		
		super.receiveResponse(exchange, response);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.receiveEmptyMessage(exchange, message);
	}

	private static boolean shouldProtectResponse(Exchange exchange) {
		return exchange.getCryptographicContextID() != null;
	}

	//Method that checks if a response is expected to be protected with OSCORE
	private boolean responseShouldBeProtected(Exchange exchange, Response response) throws OSException {
		Request request = exchange.getCurrentRequest();
		OptionSet options = request.getOptions();
		if (exchange.getCryptographicContextID() == null) {
			if (response.getOptions().hasObserve() && request.getOptions().hasObserve()) {

				// Since the exchange object has been re-created the
				// cryptographic id doesn't exist
				if (options.hasOscore()) {
					String uri = request.getURI();
					try {
						OSCoreCtx ctx = ctxDb.getContext(uri);
						exchange.setCryptographicContextID(ctx.getRecipientId());
					} catch (OSException e) {
						LOGGER.error("Error when re-creating exchange at OSCORE level");
						throw new OSException("Error when re-creating exchange at OSCORE level");
					}
				}
			}
		}
		return exchange.getCryptographicContextID() != null;
	}

	private static boolean shouldProtectRequest(Request request) {
		OptionSet options = request.getOptions();
		return options.hasOption(OptionNumberRegistry.OSCORE);

	}

	private static boolean isProtected(Message message) {
		return message.getOptions().getOscore() != null;
	}
}
