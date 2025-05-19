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

import javax.lang.model.util.Elements;

import org.apache.hc.client5.http.utils.Hex;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.elements.Definition;
import org.eclipse.californium.elements.Definitions;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.Configuration.ModuleDefinitionsProvider;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;
import org.eclipse.californium.oscore.group.InstructionIDRegistry;
import org.eclipse.californium.oscore.group.OptionEncoder;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.TranslationException;


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
	public static Request prepareSend(OSCoreCtxDB ctxDb, Request message, CBORObject[] instructions) throws OSException {
		return RequestEncryptor.encrypt(ctxDb, message, instructions);
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
	public static Response prepareReceive(OSCoreCtxDB ctxDb, Response response, int requestSequenceNr, CBORObject[] instructions)
			throws OSException {
		return ResponseDecryptor.decrypt(ctxDb, response, requestSequenceNr, instructions);
	}


	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		Request req = request;

		System.out.println("SEND REQUEST IN OBJECTSECURITYLAYER");
		System.out.println("request is: " + request);
		System.out.println(shouldProtectRequest(request));
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

				if (instructionsExists) {
					int index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);

					// is this the last instruction?
					boolean lastInstruction = index == (instructions.length - 1);

					CBORObject requestSequenceNumber = instructions[index].get(InstructionIDRegistry.RequestSequenceNumber);

					if (lastInstruction && requestSequenceNumber != null) {
						// remove request sequence number of last instruction
						instructions[index].RemoveAt(InstructionIDRegistry.RequestSequenceNumber);

						// reset index
						instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(InstructionIDRegistry.StartIndex);
					}

				}


				final OSCoreCtx ctx = ctxDb.getContext(request, false);

				if (ctx == null) {
					//this might create trouble with context rederivation if the context is removed or something 
					//perhaps during the rederivation

					if (ctxDb.getIfProxyable()) {
						// if we are a proxy but do not have a security context with the next endpoint we forward the request
						System.out.println("The context was null");
						System.out.println("we are proxy");

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


								System.out.println("SENT FORWARDED REQUEST WITH: " + token.toString());
							}
						});

						LOGGER.trace("Request: {}", exchange.getRequest());
						super.sendRequest(exchange, request);
						return;
					}
					else {
						LOGGER.error(ErrorDescriptions.CTX_NULL);
						throw new OSException(ErrorDescriptions.CTX_NULL);
					}
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

				Request preparedRequest = request;

				if (instructionsExists) {

					int index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);
					if (InstructionIDRegistry.StartIndex != index ) {
						throw new RuntimeException("start index is not correct in instructions");
					}

					// This loops until all instructions have been used
					for (int i = InstructionIDRegistry.StartIndex; i < instructions.length; i++) {
						//encryption
						preparedRequest = prepareSend(ctxDb, preparedRequest, instructions);

						// set request sequence number in instructions for decryption
						int requestSequenceNr = new OscoreOptionDecoder(preparedRequest.getOptions().getOscore()).getSequenceNumber();
						instructions[i].set(InstructionIDRegistry.RequestSequenceNumber, CBORObject.FromObject(requestSequenceNr));

						// this sets the correct values for the next layer of encryption in the instructions
						if (i < (instructions.length - 1)) {
							// increment index in instructions
							instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(i + 1);

							// set correct latest oscore option value in instructions for the next encryption
							byte[] latestOSCOREOptionValue = preparedRequest.getOptions().getOscore();
							instructions[InstructionIDRegistry.Header.OscoreOptionValue] = CBORObject.FromObject(latestOSCOREOptionValue);

							//update instructions and set into oscore option for the next encryption
							byte[] updatedOSCOREOption = OptionEncoder.encodeSequence(instructions);
							preparedRequest.getOptions().setOscore(updatedOSCOREOption);

							// apply OSCORE layer again
						}
					}
				}
				else {
					// no instructions, just encrypt the message once
					preparedRequest = prepareSend(ctxDb, request, instructions);
				}

				final Request finalPreparedRequest = preparedRequest;

				// used and set on message observer when sending with instructions
				final CBORObject[] finalInstructions = instructions;

				// used and set on message observer when sending without instructions
				final OSCoreCtx finalCtx = ctxDb.getContext(request, true);

				if (outgoingExceedsMaxUnfragSize(finalPreparedRequest, false, ctx.getMaxUnfragmentedSize())) {
					throw new IllegalStateException("outgoing request is exceeding the MAX_UNFRAGMENTED_SIZE!");
				}

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

						System.out.println("SENT REQUEST WITH: " + token.toString());
						System.out.println("SENT REQUEST WITH: MID=" + request.getMID());

					}
				});

				req = finalPreparedRequest;

				// sets the cryptographic context id on the exchange if there were no instructions
				if (!(Objects.nonNull(finalInstructions))) {
					exchange.setCryptographicContextID(req.getOptions().getOscore());
				}

				LOGGER.trace("Request: {}", exchange.getRequest());

				System.out.println("Sending request: " + req);
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
		System.out.println("SEND RESPONSE IN OBJECTSECURITYLAYER");
		System.out.println("init response is: " + response);
		System.out.println("request is:  " + exchange.getRequest());

		// AAAAAAAAH
		// Update instruction to be original after having sent the request
		// because subsequent requests will need the original to send correctly

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
				// Retrieve the context
				Token token = exchange.getCurrentRequest().getToken();
				OSCoreCtx ctx = ctxDb.getContextByToken(token);

				CBORObject[] instructions = ctxDb.getInstructions(token);

				boolean instructionsExists = Objects.nonNull(instructions);
				boolean instructionsRemaining = false;
				int requestSequenceNumber = -1;
				int index = -1;

				if (instructionsExists) { 
					index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);

					// get instruction
					CBORObject instruction = instructions[index];

					byte[] RID       = instruction.get(InstructionIDRegistry.KID).ToObject(byte[].class);
					byte[] IDCONTEXT = instruction.get(InstructionIDRegistry.IDContext).ToObject(byte[].class);

					ctx = ctxDb.getContext(RID, IDCONTEXT);

					requestSequenceNumber = instruction.get(InstructionIDRegistry.RequestSequenceNumber).ToObject(int.class);

					instructionsRemaining = (int) instructions[InstructionIDRegistry.Header.Index].ToObject(int.class) 
							> InstructionIDRegistry.StartIndex;
					System.out.println(instructionsRemaining);
				}
				else {
					// Parse the OSCORE option from the corresponding request using the cryptographic context
					OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(exchange.getCryptographicContextID());
					requestSequenceNumber = optionDecoder.getSequenceNumber();
				}

				addPartialIV = (ctx != null && ctx.getResponsesIncludePartialIV()) || exchange.getRequest().getOptions().hasObserve();

				Response preparedResponse = prepareSend(ctxDb, response, ctx, addPartialIV, outerBlockwise,
						requestSequenceNumber, instructions);

				if (outgoingExceedsMaxUnfragSize(preparedResponse, outerBlockwise, ctx.getMaxUnfragmentedSize())) {
					Response error = new Response(ResponseCode.INTERNAL_SERVER_ERROR, true);
					error.setDestinationContext(exchange.getCurrentRequest().getSourceContext());
					super.sendResponse(exchange, error);
					throw new IllegalStateException("outgoing response is exceeding the MAX_UNFRAGMENTED_SIZE!");
				}

				response = preparedResponse;
				exchange.setResponse(response);

				if (instructionsRemaining) {
					System.out.println("calling again");
					instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(--index);
					sendResponse(exchange, response);
					return;
				}
				else {
					if (instructionsExists) {
						// reset instruction index
						System.out.println("Resetting index");
						instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(instructions.length - 1);
					}
					System.out.println("NOT calling again");
				}

			} catch (OSException e) {
				LOGGER.error("Error sending response: {}", e.getMessage());
				return;
			}
		}

		// Remove token after response is transmitted, unless ongoing Observe.
		// Takes token from corresponding request
		if (response.getOptions().hasObserve() == false || exchange.getRequest().isObserveCancel()) {
			ctxDb.removeToken(exchange.getCurrentRequest().getToken());
		}

		System.out.println("Sending response: " + response);
		super.sendResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {
		System.out.println("RECEIVE REQUEST IN OBJECTSECURITYLAYER");
		System.out.println(request);
		
		boolean performOSCoreCheck = false;
		OptionSet options = request.getOptions();

		if (OptionJuggle.hasProxyRelatedOptions(options)) {

			if (OptionJuggle.hasProxyUriOrCriOptions(options) || OptionJuggle.hasSchemeAndUri(options)) {

				if (ctxDb.getIfProxyable()) {
					if (isAcceptableToForward(request)) {

						//consume proxy related options.
						Coap2CoapTranslator translator = new Coap2CoapTranslator();
						URI destination = null;
						try {
							InetSocketAddress exposedInterface = translator.getExposedInterface(request);
							destination = translator.getDestinationURI(request, exposedInterface);

						} catch (Exception e) {
							System.out.println(e.getMessage());
							exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR)); // eller nåt
						}

						// use destination for this checking, and something else
						/* does uri port and host identify me?*/
						// does this work with "unspecified" ipv6 address vs localhost? is unspecified set later?
						if (destination.getAuthority().equals(exchange.getEndpoint().getUri().getAuthority())) {
							// do consumption of proxy related options (using coap translator)
							Request newRequest = null;
							try {
								newRequest = translator.getRequest(destination, request);
							} catch (TranslationException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
								exchange.sendResponse(new Response(ResponseCode.BAD_OPTION)); // correct error?
							}	
							receiveRequest(exchange, newRequest);
						}
						else {
							//no, we forward
							super.receiveRequest(exchange, request);
						}
					}
					else {
						exchange.sendResponse(new Response(ResponseCode.UNAUTHORIZED));
					}
				}
				else {
					exchange.sendResponse(new Response(ResponseCode.PROXY_NOT_SUPPORTED));
				}
			}
			else {

				/*do Uri path, host or/and port identfify me as a reverse proxy*/
				if (ctxDb.getIfProxyable() && identifiesMe(request)) {
					if( false /*isAcceptableToForward()*/ ){
						/* do consumption of proxy related options (as a reverse proxy) */
						// forward the request
						super.receiveRequest(exchange, request);
					}
					else {
						exchange.sendResponse(new Response(ResponseCode.UNAUTHORIZED));
					}
				}
				else {
					performOSCoreCheck = true;
				}
			}
		}
		else { 
			performOSCoreCheck = true; 
		}

		if (performOSCoreCheck) {

			boolean lastOscoreLayer = false;
			if (request.getOptions().hasOscore() && Arrays.equals(request.getOptions().getOscore(), new byte[] {0x01})) {
				//&& Hex.encodeHexString(request.getOptions().getOscore()).equals("01")) {
				lastOscoreLayer = true;
			}

			if (isProtected(request) && !lastOscoreLayer) {
				if (options.hasUriPath()) {
					exchange.sendResponse((Response) new Response(ResponseCode.BAD_REQUEST).setPayload("Uri path present"));
				}
				else {
					if (/*isAcceptableToDecrypt()*/ true) {

						OSCoreCtx ctx = null;

						try {
							// Retrieve the OSCORE context associated with this RID and ID
							// Context
							OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(request.getOptions().getOscore());
							byte[] rid = optionDecoder.getKid();
							byte[] IDContext = optionDecoder.getIdContext();

							// if this ctx has been used to decrypt before, forget the instructions.
							CBORObject[] instructions = ctxDb.getInstructions(request.getToken());
							boolean instructionsExists = Objects.nonNull(instructions);
							if (instructionsExists) {
								for (int i = 2; i < instructions.length; i++) {
									byte[] ridInstruction = instructions[i].get(InstructionIDRegistry.KID).ToObject(byte[].class);
									CBORObject IDContextCBOR = instructions[i].get(InstructionIDRegistry.IDContext);
									byte[] IDContextInstruction = null;
									if (IDContextCBOR != null) {
										IDContextInstruction = IDContextCBOR.ToObject(byte[].class);
									}

									boolean hasBeenUsedBefore = false;
									if (IDContextInstruction != null) {
										hasBeenUsedBefore = Arrays.equals(rid, ridInstruction) 
												&& Arrays.equals(IDContext, IDContextInstruction);
									}
									else {
										hasBeenUsedBefore = Arrays.equals(rid, ridInstruction);
									}

									if (hasBeenUsedBefore) {
										System.out.println("Instruction has been previously used, so it is removed");
										ctxDb.removeInstructions(request.getToken());
									}
								}
							}

							ctx = ctxDb.getContext(rid, IDContext);
						} catch (CoapOSException e) {
							LOGGER.error("Error while receiving OSCore request: {}", e.getMessage());
							Response error;
							error = CoapOSExceptionHandler.manageError(e, request);
							if (error != null) {
								super.sendResponse(exchange, error);
							}
						}						
						Request decryptedRequest = requestDecryption(exchange, request, ctx);
						if (decryptedRequest != null) {
							receiveRequest(exchange, decryptedRequest);
						}
					}
					else {
						exchange.sendResponse(new Response(ResponseCode.UNAUTHORIZED));
					}
				}
			}
			else {
				// is there an application yes
				if (/* hasApplication() */ true) {
					System.out.println("Sending to Application");
					super.receiveRequest(exchange, request);
				}
				else {
					exchange.sendResponse(new Response(ResponseCode.BAD_REQUEST));
				}
			}
		}
		// We need the kid value on layer level
		// request.getOptions().setOscore(rid);
		// then send to upper layer.

		//super.receiveRequest(exchange, request);
	}

	public Request requestDecryption(Exchange exchange, Request request, OSCoreCtx ctx) {


		// For OSCORE-protected requests with the outer block1-option let
		// them pass through to be re-assembled by the block-wise layer
		if (request.getOptions().hasBlock1()) {

			if (request.getMaxResourceBodySize() == 0) {
				int maxPayloadSize = getIncomingMaxUnfragSize(request, ctx);
				request.setMaxResourceBodySize(maxPayloadSize);
			}

			super.receiveRequest(exchange, request);
			return null;
		}

		byte[] requestOscoreOption;
		try {
			requestOscoreOption = request.getOptions().getOscore();


			request = prepareReceive(ctxDb, request, ctx);

			System.out.println("prepared request is: " + request);
			// this could be better
			if (Arrays.equals(request.getOptions().getOscore(), requestOscoreOption)) {
				//request.getOptions().removeOscore();
				request.getOptions().setOscore(new byte[] {0x01});
			}			

			// maybe breaks
			byte[] cryptographicContextID = exchange.getCryptographicContextID();

			CBORObject[] instructions = null;
			// if previous was first, create header
			if (cryptographicContextID != null && cryptographicContextID != requestOscoreOption) {
				instructions = new CBORObject[4];

				instructions[InstructionIDRegistry.Header.OscoreOptionValue] = CBORObject.FromObject(new byte[0]);
				instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(InstructionIDRegistry.StartIndex);

				// and add previous layer
				OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(cryptographicContextID);
				byte[] rid = optionDecoder.getKid();
				byte[] IDContext = optionDecoder.getIdContext();
				int requestSequenceNr = optionDecoder.getSequenceNumber();
				instructions[2] =  CBORObject.DecodeFromBytes(OptionEncoder.set(rid, IDContext, requestSequenceNr));

				// and remove from cryptographiccontextid
				exchange.setCryptographicContextID(null);

				// and add to ctxDb
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
				super.sendResponse(exchange, error);
			}
			return null;
		}
		//exchange.setCryptographicContextID(requestOscoreOption);
	}


	//Always accepts unprotected responses, which is needed for reception of error messages
	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		System.out.println("RECEIVE RESPONSE IN OBJECTSECURITYLAYER");
		System.out.println("Received response: " + response);
		System.out.println("For request:       " + exchange.getCurrentRequest());

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
				System.out.println("Incoming response is NOT OSCORE protected but is expected to be!");

				LOGGER.info("Incoming response is NOT OSCORE protected but is expected to be!");
			} else if (isProtected(response) && expectProtectedResponse) {
				System.out.println("Incoming response is OSCORE protected");

				LOGGER.debug("Incoming response is OSCORE protected");
			} else if (isProtected(response)) {
				System.out.println("Incoming response is OSCORE protected but it should not be");

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

			ctxDb.size();
			if (ctxDb.hasBeenForwarded(response.getToken())) {
				//the request was not protected by us, but forwarded with a pre-existing encryption, so we simply forward it back
				System.out.println("Has been forwarded");

				super.receiveResponse(exchange, response);
				return;
			}

			//If response is protected with OSCORE parse it first with prepareReceive
			if (isProtected(response)) {
				byte[] OSCoreOption = response.getOptions().getOscore();
				int requestSequenceNumber;
				int index = 0;
				Token token = response.getToken();

				if (token == null) {
					LOGGER.error(ErrorDescriptions.TOKEN_NULL);
					throw new OSException(ErrorDescriptions.TOKEN_NULL);		
				}

				byte[] cryptographicContextID = exchange.getCryptographicContextID();
				CBORObject[] instructions = null;

				if (cryptographicContextID != null) {
					OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(exchange.getCryptographicContextID());
					requestSequenceNumber = optionDecoder.getSequenceNumber();
				}
				else {
					instructions = ctxDb.getInstructions(token);

					if (Objects.isNull(instructions)) {
						LOGGER.error(ErrorDescriptions.TOKEN_INVALID);
						throw new OSException(ErrorDescriptions.TOKEN_INVALID);
					}

					index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);

					CBORObject instruction = instructions[index];

					requestSequenceNumber = instruction.get(InstructionIDRegistry.RequestSequenceNumber).ToObject(int.class);
				}

				// need to handle the case where any oscore layer is missing
				response = prepareReceive(ctxDb, response, requestSequenceNumber, instructions);

				if (Objects.nonNull(instructions)) {
					instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(--index);
				}


				// if we are proxy, continue decrypting until instructions say stop 
				if (ctxDb.getIfProxyable() && response.getOptions().hasOscore()) {
					if (index >= InstructionIDRegistry.StartIndex) {
						System.out.println("calling again in receive response");
						receiveResponse(exchange, response);
						return;
					}
				}
				// if we are client, continue decrypting until all layers are stripped
				else if (response.getOptions().hasOscore()) {
					System.out.println("calling again in receive response");
					receiveResponse(exchange, response);
					return;
				}


				// check index if we have more to decrypt
				//if (cryptographicContextID == null && index >= 2) {
				//	System.out.println("calling again in receive response");
				//	receiveResponse(exchange, response);
				//	return;
				//}

				// does this need an oscore option for other layers above?
				// could add, if we save it after isProtected
				response.getOptions().setOscore(OSCoreOption);
			}
		} catch (OSException e) {
			LOGGER.error("Error while receiving OSCore response: {}", e.getMessage());
			EmptyMessage error = CoapOSExceptionHandler.manageError(e, response);
			if (error != null) {
				sendEmptyMessage(exchange, error);
			}
			return;
		}


		//Remove token after response is received, unless it has Observe
		//If it has Observe it will be removed after cancellation elsewhere
		if (response.getOptions().hasObserve() == false
				|| exchange.getRequest().isObserveCancel()) {
			System.out.println("Removing token");
			ctxDb.removeToken(response.getToken());
		}
		else {
			System.out.println("Not removing token, ");
			System.out.println("resetting index");
			CBORObject[] instructions = ctxDb.getInstructions(response.getToken());
			// this is to reset the instruction index when receiving multiple responses (as may happen when observe is used)
			if (Objects.nonNull(instructions)) {
				instructions[InstructionIDRegistry.Header.Index] = CBORObject.FromObject(instructions.length - 1);
			}
		}

		// Remove token if this is an incoming response to an Observe
		// cancellation request
		//if (exchange.getRequest().isObserveCancel()) {
		//	ctxDb.removeToken(response.getToken());
		//}

		super.receiveResponse(exchange, response);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.receiveEmptyMessage(exchange, message);
	}

	private boolean identifiesMe(Request request) {
		return false;
	}
	private boolean isAcceptableToForward(Request request) {
		byte[] oscoreOption = request.getOptions().getOscore();
		/*
		try {
			OscoreOptionDecoder oscoreOptionDecoder = new OscoreOptionDecoder(oscoreOption);
			// do some list or array, in ctxDB? (add flag for who can forward and who is forwardeable to?)
			if (oscoreOptionDecoder.getKid().equals(new byte[] {0x01} )) {
				System.out.println("forwarding: 0x01");
				return true;
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println("invalid oscore option decoder");
			if (oscoreOption != null) {
				System.out.println("oscore option was: " + Hex.encodeHexString(oscoreOption));
			}
		}*/
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

		// maybe this needs changing
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
		OptionSet options = request.getOptions();

		if (options.hasOscore()) {
			try {
				OSCoreCtx ctx = ctxDb.getContext(request, false);
			} catch (OSException e) {
				// no context was found for the destination
			}

		}
		return options.hasOscore();

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
