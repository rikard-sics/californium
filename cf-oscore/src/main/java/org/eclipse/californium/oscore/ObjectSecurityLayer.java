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

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Arrays;
import java.util.Objects;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;
import org.eclipse.californium.oscore.group.InstructionIDRegistry;
import org.eclipse.californium.oscore.group.OptionEncoder;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;


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
		final String uri;
		if (message.getOptions().hasProxyUri()) {
			uri = message.getOptions().getProxyUri();
		} else {
			uri = message.getURI();
		}

		if (uri == null) {
			LOGGER.error(ErrorDescriptions.URI_NULL);
			throw new OSException(ErrorDescriptions.URI_NULL);
		}

		OSCoreCtx ctx = ctxDb.getContext(uri);
		return prepareSend(ctxDb, ctx, message, null);
	}

	/**
	 * Encrypt an outgoing request using the OSCore context.
	 * 
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param ctxDb the context database used
	 * @param instructions instructions to provide additional information for encryption
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting request
	 */
	public static Request prepareSend(OSCoreCtxDB ctxDb, OSCoreCtx ctx, Request message, CBORObject[] instructions) throws OSException {
		return RequestEncryptor.encrypt(ctxDb, ctx, message, instructions);
	}

	/**
	 * Encrypt an outgoing response using the OSCore context.
	 * 
	 * @param ctxDb the OSCore context DB
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param newPartialIV whether to use a new partial IV or not
	 * @param outerBlockwise whether the block-wise options should be encrypted
	 * @param requestSequenceNr sequence number (Partial IV) from the request
	 *            (if encrypting a response)
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting response
	 */
	public static Response prepareSend(OSCoreCtxDB ctxDb, Response message, OSCoreCtx ctx, final boolean newPartialIV,
			boolean outerBlockwise, int requestSequenceNr) throws OSException {
		return prepareSend(ctxDb, message, ctx, newPartialIV, outerBlockwise, requestSequenceNr, null);
	}

	/**
	 * Encrypt an outgoing response using the OSCore context.
	 * 
	 * @param ctxDb the OSCore context DB
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param newPartialIV whether to use a new partial IV or not
	 * @param outerBlockwise whether the block-wise options should be encrypted
	 * @param requestSequenceNr sequence number (Partial IV) from the request
	 *            (if encrypting a response)
	 * @param instructions instructions to provide additional information for encryption
	 * 
	 * @return the encrypted message
	 * 
	 * @throws OSException error while encrypting response
	 */
	public static Response prepareSend(OSCoreCtxDB ctxDb, Response message, OSCoreCtx ctx, final boolean newPartialIV,
			boolean outerBlockwise, int requestSequenceNr, CBORObject[] instructions) throws OSException {
		return ResponseEncryptor.encrypt(ctxDb, message, ctx, newPartialIV, outerBlockwise, requestSequenceNr, instructions);
	}

	/**
	 * Decrypt an incoming request using the right OSCore context
	 *
	 * @param ctxDb the context database used
	 * @param request the incoming request
	 * @param ctx the OSCore context
	 * 
	 * @return the decrypted and verified request
	 * 
	 * @throws CoapOSException error while decrypting request
	 */
	public static Request prepareReceive(OSCoreCtxDB ctxDb, Request request, OSCoreCtx ctx) throws CoapOSException {
		return RequestDecryptor.decrypt(ctxDb, request, ctx);
	}

	/**
	 * Decrypt an incoming response using the right OSCore context
	 *
	 * @param ctxDb the context database used
	 * @param response the incoming request
	 * @param requestSequenceNr sequence number (Partial IV) from the request
	 *            (if decrypting a response)
	 * 
	 * @return the decrypted and verified response
	 * 
	 * @throws OSException error while decrypting response
	 */
	public static Response prepareReceive(OSCoreCtxDB ctxDb, Response response, int requestSequenceNr)
			throws OSException {
		return prepareReceive(ctxDb, response, requestSequenceNr, null);
	}

	/**
	 * Decrypt an incoming response using the right OSCore context
	 *
	 * @param ctxDb the context database used
	 * @param response the incoming request
	 * @param requestSequenceNr sequence number (Partial IV) from the request
	 *            (if decrypting a response)
	 * @param instructions instructions to provide additional information for encryption
	 * 
	 * @return the decrypted and verified response
	 * 
	 * @throws OSException error while decrypting response
	 */
	public static Response prepareReceive(OSCoreCtxDB ctxDb, Response response, int requestSequenceNr, CBORObject[] instructions)
			throws OSException {
		return ResponseDecryptor.decrypt(ctxDb, response, requestSequenceNr, instructions);
	}


	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		Request req = request;
		ctxDb.size();

		if (shouldProtectRequest(request)) {
			try {
				// Handle outgoing requests for more data from a responder that
				// is responding with outer block-wise. These requests should
				// not be processed with OSCORE.
				Response response = exchange.getCurrentResponse();
				if (request.getOptions().hasBlock2() && response != null) {
					final OSCoreCtx ctx = ctxDb.getContextByToken(response.getToken());
					if (ctx != null) {
						request.addMessageObserver(0, new MessageObserverAdapter() {

							@Override
							public void onReadyToSend() {
								ctxDb.addContext(request.getToken(), ctx);
							}
						});
						super.sendRequest(exchange, request);
						return; 
					}
				}

				byte[] OscoreOption = request.getOptions().getOscore();
				CBORObject[] instructions = OptionEncoder.decodeCBORSequence(OscoreOption);

				// are there instructions?
				boolean instructionsExists = Objects.nonNull(instructions);

				OSCoreCtx ctx = ctxDb.getContext(request, instructions);

				if (ctx == null && !instructionsExists) {
					try {
						// check to see if the OSCORE option is a compressed COSE_Encrypt0 object
						new OscoreOptionDecoder(request.getOptions().getOscore());

						// there was a compressed COSE_Encrypt0 object in the OSCORE option in the request.
						request.addMessageObserver(0, new MessageObserverAdapter() {

							//this isn't called until it is ready to send, i.e. super.sendRequest
							//only creates the Token and associates it null
							@Override
							public void onReadyToSend() {
								Token token = request.getToken();

								// add at head of message observers to update
								// the token of the original request first,
								// before calling other message observers!
								if (request.getToken() == null) {
									request.setToken(token);
								}

								if (!request.hasMID() && request.hasMID()) {
									request.setMID(request.getMID());
								}

								ctxDb.addForwarded(token);

							}
						});

						LOGGER.trace("Request: {}", exchange.getRequest());
						super.sendRequest(exchange, request);
						return;
					} catch (CoapOSException e) {
						// there was not a compressed COSE_Encrypt0 object in the OSCORE option in the request.
						LOGGER.error(ErrorDescriptions.CTX_NULL);
						throw new OSException(ErrorDescriptions.CTX_NULL);
					}
				}
				else if (ctx == null) {
					LOGGER.error(ErrorDescriptions.CTX_NULL);
					throw new OSException(ErrorDescriptions.CTX_NULL);
				}

				// Initiate context re-derivation procedure if flag is set
				if (ctx.getContextRederivationPhase() == PHASE.CLIENT_INITIATE) {
					throw new IllegalStateException("must be handled in ObjectSecurityContextLayer!");
				}

				Request preparedRequest = request;

				if (instructionsExists) {

					int index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);
					if (InstructionIDRegistry.StartIndex != index ) {
						throw new RuntimeException("start index is not correct in instructions");
					}

					// initial for forwarding with valid first oscore option that is not empty
					// set correct oscore option value in request for the first encryption
					byte[] oscoreOption = instructions[InstructionIDRegistry.Header.OscoreOptionValue].ToObject(byte[].class);
					preparedRequest.getOptions().setOscore(oscoreOption);

					if (instructions.length - 2 > ctxDb.getLayerLimit()) {
						throw new RuntimeException("there are more layers than allowed on the request");
					}

					boolean instructionsRemaining;

					// This loops until all instructions have been used
					for (int i = InstructionIDRegistry.StartIndex; i < instructions.length; i++) {

						//encryption
						ctx = ctxDb.getContext(request, instructions);

						preparedRequest = prepareSend(ctxDb, ctx, preparedRequest, instructions);

						if (outgoingExceedsMaxUnfragSize(request, false, ctx.getMaxUnfragmentedSize())) {
							throw new IllegalStateException("outgoing request is exceeding the MAX_UNFRAGMENTED_SIZE!");
						}

						// set request sequence number in instructions for decryption
						int requestSequenceNr = new OscoreOptionDecoder(preparedRequest.getOptions().getOscore()).getSequenceNumber();
						instructions[i].set(InstructionIDRegistry.RequestSequenceNumber, CBORObject.FromObject(requestSequenceNr));

						instructionsRemaining = i < (instructions.length - 1);
						// check if there is a next layer of encryption in the instructions
						if (instructionsRemaining) {
							// increment index in instructions
							instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(i + 1);
						}
					}
				}
				else {
					/*
					 * Sets an operator on the exchange. This operator will in
					 * turn set information about the OSCORE context used in the
					 * endpoint context that will be created after the request is sent.
					 */
					OSCoreEndpointContextInfo.sendingRequest(ctx, exchange);

					// no instructions, just encrypt the message once
					preparedRequest = prepareSend(ctxDb, ctx, request, null);

					if (outgoingExceedsMaxUnfragSize(preparedRequest, false, ctx.getMaxUnfragmentedSize())) {
						throw new IllegalStateException("outgoing request is exceeding the MAX_UNFRAGMENTED_SIZE!");
					}
				}

				final Request finalPreparedRequest = preparedRequest;

				// used and set on message observer when sending with instructions
				final CBORObject[] finalInstructions = instructionsExists ? instructions : null;

				// used and set on message observer when sending without instructions
				final OSCoreCtx finalCtx             = instructionsExists ? null : ctxDb.getContext(request, instructions);				

				finalPreparedRequest.addMessageObserver(0, new MessageObserverAdapter() {

					//this isn't called until it is ready to send, i.e. super.sendRequest
					//only creates the Token and associates it with the ctx
					@Override
					public void onReadyToSend() {
						Token token = finalPreparedRequest.getToken();

						// add at head of message observers to update
						// the token of the original request first,
						// before calling other message observers!
						if (request.getToken() == null) {
							request.setToken(token);
						}

						if (!request.hasMID() && finalPreparedRequest.hasMID()) {
							request.setMID(finalPreparedRequest.getMID());
						}

						if (Objects.nonNull(finalInstructions)) {
							ctxDb.addInstructions(token, finalInstructions);
						}
						else {
							ctxDb.addContext(token, finalCtx);
						}
					}
				});

				req = finalPreparedRequest;

				// sets the cryptographic context id on the exchange if there were no instructions
				if (!(Objects.nonNull(finalInstructions))) {
					exchange.setCryptographicContextID(req.getOptions().getOscore());
				}

				LOGGER.trace("Request: {}", exchange.getRequest());

				super.sendRequest(exchange, req);

			} catch (OSException e) {
				LOGGER.error("Error sending request: {}", e.getMessage());
				return;
			} catch (IllegalArgumentException e) {
				LOGGER.error("Unable to send request because of illegal argument: {}", e.getMessage());
				return;
			}
		}
		else {
			LOGGER.trace("Request: {}", exchange.getRequest());
			super.sendRequest(exchange, req);
		}
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
		if (shouldProtectResponse(exchange, ctxDb)) {

			// If the current block-request still has a non-empty OSCORE option it
			// means it was not unprotected by OSCORE as and individual request.
			// Rather it was not processed by OSCORE until after being re-assembled
			// by the block-wise layer. Thus the response should use outer block options.
			outerBlockwise = exchange.getCurrentRequest().getOptions().hasOscore()
					&& exchange.getCurrentRequest().getOptions().getOscore().length != 0;

			try {
				Token token = exchange.getCurrentRequest().getToken();
				OSCoreCtx ctx; 

				CBORObject[] instructions = ctxDb.getInstructions(token);
				boolean instructionsExists = Objects.nonNull(instructions);

				int requestSequenceNumber;

				Response preparedResponse = response;

				// Retrieve the context
				if (instructionsExists) {


					int index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);
					if (instructions.length -1 != index ) {
						throw new RuntimeException("start index is not correct in instructions");
					}

					if (instructions.length - 2 > ctxDb.getLayerLimit()) {
						throw new RuntimeException("there are more layers than allowed on the response");
					}

					boolean instructionsRemaining;

					// This loops until all instructions have been used
					for (int i = instructions.length - 1; (InstructionIDRegistry.StartIndex - 1) < i; i--) {

						// retrieve context
						CBORObject instruction = instructions[index];

						byte[] RID       = instruction.get(InstructionIDRegistry.KID).ToObject(byte[].class);
						byte[] IDCONTEXT = instruction.get(InstructionIDRegistry.IDContext).ToObject(byte[].class);

						ctx = ctxDb.getContext(RID, IDCONTEXT);

						//retrieve request sequence number
						requestSequenceNumber = instruction.get(InstructionIDRegistry.RequestSequenceNumber).ToObject(int.class);

						// should response include the partial IV?
						addPartialIV = (ctx != null && ctx.getResponsesIncludePartialIV()) || exchange.getRequest().getOptions().hasObserve();

						// should there be an inner OSCORE option?
						if (ctxDb != null && !ctxDb.hasBeenForwarded(token)) {
							response.getOptions().removeOscore();
						}

						// encrypt
						preparedResponse = prepareSend(ctxDb, preparedResponse, ctx, addPartialIV, outerBlockwise,
								requestSequenceNumber, instructions);

						if (outgoingExceedsMaxUnfragSize(preparedResponse, outerBlockwise, ctx.getMaxUnfragmentedSize())) {
							Response error = new Response(ResponseCode.INTERNAL_SERVER_ERROR, true);
							error.setDestinationContext(exchange.getCurrentRequest().getSourceContext());
							super.sendResponse(exchange, error);
							throw new IllegalStateException("outgoing response is exceeding the MAX_UNFRAGMENTED_SIZE!");
						}

						instructionsRemaining = (int) instructions[InstructionIDRegistry.Header.Index].ToObject(int.class) 
								> InstructionIDRegistry.StartIndex;
								// check if there is a next layer of encryption in the instructions
								if (instructionsRemaining) {
									// decrement index in instructions
									instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(--index);
								}
					}
				}
				else {
					// retrieve context 
					ctx = ctxDb.getContextByToken(token);

					//retrieve request sequence number
					OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(exchange.getCryptographicContextID());
					requestSequenceNumber = optionDecoder.getSequenceNumber();

					// should response include the partial IV?
					addPartialIV = (ctx != null && ctx.getResponsesIncludePartialIV()) || exchange.getRequest().getOptions().hasObserve();

					// should there be an inner OSCORE option?
					if (ctxDb != null && !ctxDb.hasBeenForwarded(token)) {
						response.getOptions().removeOscore();
					}

					// encrypt
					preparedResponse = prepareSend(ctxDb, response, ctx, addPartialIV, outerBlockwise,
							requestSequenceNumber, instructions);

					if (outgoingExceedsMaxUnfragSize(preparedResponse, outerBlockwise, ctx.getMaxUnfragmentedSize())) {
						Response error = new Response(ResponseCode.INTERNAL_SERVER_ERROR, true);
						error.setDestinationContext(exchange.getCurrentRequest().getSourceContext());
						super.sendResponse(exchange, error);
						throw new IllegalStateException("outgoing response is exceeding the MAX_UNFRAGMENTED_SIZE!");
					}
				}

				response = preparedResponse;
				exchange.setResponse(response);

				if (instructionsExists) {
					// reset instruction index
					instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(instructions.length - 1);
				}
			} catch (OSException e) {
				LOGGER.error("Error sending response: {}", e.getMessage());
				return;
			}
		}

		// Remove token after response is transmitted, unless ongoing Observe.
		if (response.getOptions().hasObserve() == false || exchange.getRequest().isObserveCancel()) {
			ctxDb.removeToken(exchange.getCurrentRequest().getToken());
		}

		super.sendResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {

		System.out.println("received request: " + request);
		// removes any previous instructions that were built while decrypting the request, 
		// because there is no guarantee the request is encrypted the same way as the first time.
		ctxDb.removeInstructions(request.getToken());

		byte[] initialRequestHadOscore = request.getOptions().getOscore();

		Message result = request;

		while (true) {
			boolean hadProxyOption = result.getOptions().hasProxyUri() || result.getOptions().hasProxyScheme(); 

			result = processIfHasProxyRelatedOptions(exchange, (Request) result);

			// error occured, and is handled in processRequestDecryption
			if (result == null) { 
				break;
			}
			boolean isRequest = result instanceof Request;

			// if had proxy uri, but is removed, we receive ourselves
			// if had proxy uri and is kept, we forward
			if (isRequest) {
				if (!result.getOptions().hasOscore() 
						|| ( hadProxyOption && (result.getOptions().hasProxyUri() || result.getOptions().hasProxyScheme()))
						|| ( result.getOptions().hasBlock1())) {

					if (initialRequestHadOscore != null && !result.getOptions().hasOscore()) {
						result.getOptions().setOscore(Bytes.EMPTY);
					}

					if (result.getOptions().hasProxyUri() || result.getOptions().hasProxyScheme()) {
						ctxDb.addForwarded(request.getToken());
					}

					super.receiveRequest(exchange, (Request) result);
					break;
				}
			}
			else {
				// error receiving the request, message is error response
				exchange.sendResponse((Response) result);
				break;
			}
		}
	}

	private Message processIfHasProxyRelatedOptions(Exchange exchange, Request request) { 
		if (OptionJuggle.hasProxyRelatedOptions(request.getOptions())) {
			return processIfForwardOrReverse(exchange, request);
		}
		else {
			return processHasOscoreOption(exchange, request);
		}
	}
	public Message processIfForwardOrReverse(Exchange exchange, Request request) {
		if (OptionJuggle.hasProxyUriOrCriOptions(request.getOptions()) || OptionJuggle.hasProxySchemeAndUri(request.getOptions())) {
			return processIsForwardProxy(exchange, request);
		}
		else {
			return processIsReverseProxy(exchange, request);
		}
	}

	public Message processIsForwardProxy(Exchange exchange, Request request) {
		if (ctxDb.getIfProxyable()) {
			return processIsAcceptableToForward(exchange, request);
		}
		else {
			return new Response(ResponseCode.PROXY_NOT_SUPPORTED);
		}
	}

	private Message processIsAcceptableToForward(Exchange exchange, Request request){
		if (isAcceptableToForward(request)) {
			return consumeProxyRelatedOptions(exchange, request, true);
		}
		else {
			return new Response(ResponseCode.UNAUTHORIZED);

		}
	}

	private Message processIsReverseProxy(Exchange exchange, Request request) {
		/*do Uri path, host or/and port identfify me as a reverse proxy*/
		if (identifiesMe(request)) {
			if(isAcceptableToForward(request)){
				return consumeProxyRelatedOptions(exchange,request, false);	
			}
			else {
				return new Response(ResponseCode.UNAUTHORIZED);
			}
		}
		else {
			return processHasOscoreOption(exchange, request);
		}
	}

	private Message consumeProxyRelatedOptions(Exchange exchange, Request request, boolean shouldProcess){
		Coap2CoapTranslator translator = new Coap2CoapTranslator();
		URI destination = null;
		try {
			InetSocketAddress exposedInterface = translator.getExposedInterface(request);
			destination = translator.getDestinationURI(request, exposedInterface);

			if (shouldProcess) {
				/* does uri port and host identify me?*/
				URI alias1 = new URI("coap", null, "localhost", 5683, null, null, null);
				URI alias2 = new URI("coap", null, "127.0.0.1", 5683, null, null, null);

				// for alias alias : aliases
				// destination.getauthorut.eq alias
				if (destination.getAuthority().equals(exchange.getEndpoint().getUri().getAuthority())
						|| destination.getAuthority().equals(exchange.getEndpoint().getUri().getAuthority())
						|| destination.getAuthority().equals(exchange.getEndpoint().getUri().getAuthority())) {
					// do consumption of proxy related options (using coap translator)
					// it identifies us so we remove proxy-* option
					if (request.getOptions().hasProxyUri()) request.getOptions().removeProxyUri();
					if (request.getOptions().hasProxyScheme()) request.getOptions().removeProxyScheme();
					return request;
				}
				else {
					// forward request
					return request;
				}
			}
			else {
				//forward request
				return request;
			}

		} catch (Exception e) {
			return new Response(ResponseCode.INTERNAL_SERVER_ERROR);
		}


	}

	private Message processHasOscoreOption(Exchange exchange, Request request) {
		if (request.getOptions().hasOscore() ) {
			return processHasURIPathOption(exchange, request);
		}
		else {
			return processIsThereAnApplication(exchange, request);
		}
	}

	private Message processHasURIPathOption(Exchange exchange, Request request){
		if (request.getOptions().getURIPathCount() > 0) {
			return (Response) new Response(ResponseCode.BAD_REQUEST).setPayload("Uri path present");
		}
		else {
			return processIsAcceptableToDecrypt(exchange, request);
		}
	}

	private Message processIsAcceptableToDecrypt(Exchange exchange, Request request){
		if (isAcceptableToDecrypt(request)) {
			return processRequestDecryption(exchange, request);
		}
		else {
			return new Response(ResponseCode.UNAUTHORIZED);
		}
	}

	private Message processIsThereAnApplication(Exchange exchange, Request request){
		if (/* hasApplication() */ true) {
			return request;
		}
		else {
			return new Response(ResponseCode.BAD_REQUEST);
		}
	}

	private Message processRequestDecryption(Exchange exchange, Request request) {
		OSCoreCtx ctx = null;

		try {
			// Retrieve the OSCORE context associated with this RID and ID
			// Context
			OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(request.getOptions().getOscore());
			byte[] rid = optionDecoder.getKid();
			byte[] IDContext = optionDecoder.getIdContext();

			ctx = ctxDb.getContext(rid, IDContext);
		} catch (CoapOSException e) {
			LOGGER.error("Error while receiving OSCore request: {}", e.getMessage());
			Response error;
			error = CoapOSExceptionHandler.manageError(e, request);
			if (error != null) {
				return error;
			}
			return null;
		}		

		// For OSCORE-protected requests with the outer block1-option let
		// them pass through to be re-assembled by the block-wise layer
		if (request.getOptions().hasBlock1()) {
			if (request.getMaxResourceBodySize() == 0) {
				int maxPayloadSize = getIncomingMaxUnfragSize(request, ctx);
				request.setMaxResourceBodySize(maxPayloadSize);
			}

			return request;
		}

		int layerLimit = ctxDb.getLayerLimit();
		int layer;
		// not decrypted yet
		if (exchange.getCryptographicContextID() == null && ctxDb.getInstructions(request.getToken()) == null) {
			layer = 0;
			// decrypted once
		} else if (exchange.getCryptographicContextID() != null) {
			layer = 1;
		}
		// amount of times decrypted is known from size of instruction.
		else {
			CBORObject[] instructions = ctxDb.getInstructions(request.getToken());
			layer = instructions.length - 2; // # of instructions - # of headers
		}

		if (layer == layerLimit) {
			LOGGER.debug("max layer reached when decrypting a request");
			return new Response(ResponseCode.UNAUTHORIZED); 
		}

		byte[] requestOscoreOption;
		try {
			// save outer OSCORE option
			requestOscoreOption = request.getOptions().getOscore();

			ctxDb.size();
			// decrypt
			request = prepareReceive(ctxDb, request, ctx);

			// if the outer OSCORE option is the same as the OSCORE option after decryption, we have decrypted as much as we should
			if (Arrays.equals(request.getOptions().getOscore(), requestOscoreOption)) {
				request.getOptions().removeOscore();
			}

			byte[] cryptographicContextID = exchange.getCryptographicContextID();

			CBORObject[] instructions = null;
			// if previous decryption was the first decryption for the request
			if (cryptographicContextID != null && cryptographicContextID != requestOscoreOption) {
				instructions = new CBORObject[4];

				// create header
				instructions[InstructionIDRegistry.Header.OscoreOptionValue] = CBORObject.FromObject(new byte[0]);
				instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(InstructionIDRegistry.StartIndex);

				// and add previous layer
				OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(cryptographicContextID);
				byte[] rid = optionDecoder.getKid();
				byte[] IDContext = optionDecoder.getIdContext();
				int requestSequenceNr = optionDecoder.getSequenceNumber();
				instructions[2] =  CBORObject.DecodeFromBytes(OptionEncoder.set(rid, IDContext, requestSequenceNr));

				// and remove from cryptographic context id
				exchange.setCryptographicContextID(null);

				// and add initial instruction to ctxDb
				ctxDb.addInstructions(request.getToken(), instructions);
			}
			// else if already exists in ctxDb, retrieve from there
			else if (cryptographicContextID == null && ctxDb.tokenExist(request.getToken())) {
				instructions = ctxDb.getInstructions(request.getToken());
			}

			if (instructions != null) {

				//increment index
				int index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);
				instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(index + 1);

				// append current layer to instructions
				OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(requestOscoreOption);
				byte[] rid = optionDecoder.getKid();
				byte[] IDContext = optionDecoder.getIdContext();
				int requestSequenceNr = optionDecoder.getSequenceNumber();
				instructions[instructions.length - 1] =  CBORObject.DecodeFromBytes(OptionEncoder.set(rid, IDContext, requestSequenceNr));
			}
			else {
				exchange.setCryptographicContextID(requestOscoreOption);
			}

			exchange.setRequest(request);
			return request;
		} catch (CoapOSException e) {
			LOGGER.error("Error while receiving OSCore request: {}", e.getMessage());
			Response error;
			error = CoapOSExceptionHandler.manageError(e, request);
			if (error != null) {
				return error;
			}
			return null;
		}
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
			boolean expectProtectedResponse = responseShouldBeProtected(exchange, response);
			if (!isProtected(response) && expectProtectedResponse) {
				LOGGER.info("Incoming response is NOT OSCORE protected but is expected to be!");
			} else if (isProtected(response) && expectProtectedResponse) {
				LOGGER.debug("Incoming response is OSCORE protected");
			} else if (isProtected(response)) {
				LOGGER.warn("Incoming response is OSCORE protected but it should not be");
			}

			// For OSCORE-protected response with the outer block2-option let
			// them pass through to be re-assembled by the block-wise layer
			if (response.getOptions().hasBlock2()) {

				if (response.getMaxResourceBodySize() == 0) {
					int maxPayloadSize = getIncomingMaxUnfragSize(response, ctxDb);
					response.setMaxResourceBodySize(maxPayloadSize);
				}

				super.receiveResponse(exchange, response);
				return;
			}

			if (ctxDb.hasBeenForwarded(response.getToken())) {
				/* 
				 * the request was not protected by us, but forwarded with 
				 * pre-existing OSCORE layer(s), so OSCORE processing
				 * is skipped and the response is forwarded 
				 */
				super.receiveResponse(exchange, response);
				return;
			}

			if (isProtected(response)) {

				Token token = response.getToken();

				if (token == null) {
					LOGGER.error(ErrorDescriptions.TOKEN_NULL);
					throw new OSException(ErrorDescriptions.TOKEN_NULL);		
				}

				int requestSequenceNumber;
				byte[] oscoreOption;

				CBORObject[] instructions = ctxDb.getInstructions(token);
				boolean instructionsExists = Objects.nonNull(instructions);

				if (instructionsExists) {
					int layerLimit = instructions.length - 2; // # of instructions - # of headers
					int layer = 0;
					int index;

					oscoreOption = null;

					while (response.getOptions().hasOscore()) {

						index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);
						CBORObject instruction = instructions[index];

						requestSequenceNumber = instruction.get(InstructionIDRegistry.RequestSequenceNumber).ToObject(int.class);

						oscoreOption = response.getOptions().getOscore();

						response = prepareReceive(ctxDb, response, requestSequenceNumber, instructions);

						layer++;

						if (layer == layerLimit && response.getOptions().hasOscore()) {
							LOGGER.warn("max layer reached when decrypting a response");
							return; // stop processing
						}

						instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(--index);
					}

					if (layer < layerLimit) {
						LOGGER.info("Received response was not encrypted as many times as the sent request was");
					}

					// this is to reset the instruction index when receiving multiple responses (as may happen when observe is used)
					if (Objects.nonNull(instructions)) {
						instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(instructions.length - 1);
					}

					if (oscoreOption != null) {
						response.getOptions().setOscore(oscoreOption);
					}
				}
				else {
					OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(exchange.getCryptographicContextID());
					requestSequenceNumber = optionDecoder.getSequenceNumber();

					oscoreOption = response.getOptions().getOscore();

					response = prepareReceive(ctxDb, response, requestSequenceNumber, instructions);

					if (response.getOptions().hasOscore() && !ctxDb.getIfProxyable()) {
						LOGGER.warn("max layer reached when decrypting a response");
						return; // stop processing
					}
					response.getOptions().setOscore(oscoreOption);
				}
			}
		} catch (OSException e) {
			LOGGER.error("Error while receiving OSCore response: {}", e.getMessage());
			EmptyMessage error = CoapOSExceptionHandler.manageError(e, response);
			if (error != null) {
				sendEmptyMessage(exchange, error);
			}
			return;
		}

		// Remove token if this is an incoming response to an Observe
		// cancellation request
		if (exchange.getRequest().isObserveCancel()) {
			ctxDb.removeToken(response.getToken());
		}

		super.receiveResponse(exchange, response);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.receiveEmptyMessage(exchange, message);
	}

	// TODO: implement
	private boolean identifiesMe(Request request) {
		return false;
	}

	// TODO: implement
	private boolean isAcceptableToForward(Request request) {
		byte[] oscoreOption = request.getOptions().getOscore();

		return true;
	}

	// TODO: implement
	private boolean isAcceptableToDecrypt(Request request) {

		return true;
	}

	private static boolean shouldProtectResponse(Exchange exchange, OSCoreCtxDB ctxDb) {
		return exchange.getCryptographicContextID() != null 
				|| ctxDb.getInstructions(exchange.getCurrentRequest().getToken()) != null;
	}

	//Method that checks if a response is expected to be protected with OSCORE
	private boolean responseShouldBeProtected(Exchange exchange, Response response) throws OSException {
		Request request = exchange.getCurrentRequest();
		OptionSet options = request.getOptions();

		if (exchange.getCryptographicContextID() == null) {
			if (response.getOptions().hasObserve() && request.getOptions().hasObserve()) {
				// Since the exchange object has been re-created the
				// cryptographic id doesn't exist
				// but this should happen only if there were no instructions
				// which would be stored in the ctxDb
				if (!ctxDb.instructionsExistForToken(response.getToken())) {
					if (options.hasOscore()) {
						exchange.setCryptographicContextID(options.getOscore());
					}
				}
			}
		}

		return exchange.getCryptographicContextID() != null 
				|| ctxDb.getInstructions(response.getToken()) != null
				|| ctxDb.hasBeenForwarded(response.getToken());
	}

	private boolean shouldProtectRequest(Request request) {		
		return request.getOptions().hasOscore();

	}

	private static boolean isProtected(Message message) {
		return message.getOptions().getOscore() != null;
	}

	/**
	 * Check if a message being sent exceeds the MAX_UNFRAGMENTED_SIZE and is
	 * not using inner block-wise. If so it should not be sent.
	 * 
	 * @param message the CoAP message
	 * @param outerBlockwise {@code true}, for outer, {@code false}, for inner blockwise
	 * @param maxUnfragmentedSize the MAX_UNFRAGMENTED_SIZE value
	 * 
	 * @return if the message exceeds the MAX_UNFRAGMENTED_SIZE
	 */
	private boolean outgoingExceedsMaxUnfragSize(Message message, boolean outerBlockwise,
			int maxUnfragmentedSize) {

		boolean usesInnerBlockwise = (message.getOptions().hasBlock1() == true
				|| message.getOptions().hasBlock2() == true) && outerBlockwise == false;

		if (message.getPayloadSize() > maxUnfragmentedSize && usesInnerBlockwise == false) {
			return true;
		} else {
			return false;
		}

	}

	/**
	 * Gets the MAX_UNFRAGMENTED_SIZE size for an incoming block-wise transfer.
	 * If outer block-wise is used this value will be set using
	 * setMaxResourceBodySize on the incoming request or response and enforced
	 * in the BlockwiseLayer. Reception of messages where the cumulative payload
	 * size exceeds this value will be aborted.
	 * 
	 * @param message the CoAP message
	 * @param ctx the context used
	 * 
	 * @return the MAX_UNFRAGMENTED_SIZE value to be used
	 */
	private int getIncomingMaxUnfragSize(Message message, OSCoreCtx ctx) {

		// No limit if no context is found. A null context will be handled later
		if (ctx == null) {
			return 0;
		} else {
			return ctx.getMaxUnfragmentedSize();
		}

	}

	/**
	 * Separate version of method for handling responses.
	 * 
	 * @param message the CoAP message
	 * @param ctxDb the context database used
	 * @return the MAX_UNFRAGMENTED_SIZE value to be used
	 */
	private int getIncomingMaxUnfragSize(Message message, OSCoreCtxDB ctxDb) {
		OSCoreCtx ctx = null;
		if (message instanceof Response) {
			ctx = ctxDb.getContextByToken(message.getToken());
		}

		return getIncomingMaxUnfragSize(message, ctx);
	}

}
