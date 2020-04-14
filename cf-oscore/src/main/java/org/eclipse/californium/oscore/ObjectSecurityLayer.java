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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.UdpEndpointContext;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;

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
				// Handle outgoing requests for more data from a responder that
				// is responding with outer block-wise. These requests should
				// not be processed with OSCORE.
				boolean outerBlockwise = request.getOptions().hasBlock2() && exchange.getCurrentResponse() != null
						&& ctxDb.getContextByToken(exchange.getCurrentResponse().getToken()) != null;
				if (outerBlockwise) {
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

				if (outgoingExceedsMaxUnfragSize(request, outerBlockwise, ctx.getMaxUnfragmentedSize())) {
					throw new IllegalStateException("outgoing request is exceeding the MAX_UNFRAGMENTED_SIZE!");
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

			try {
				OSCoreCtx ctx = ctxDb.getContext(exchange.getCryptographicContextID());
				addPartialIV = ctx.getResponsesIncludePartialIV() || exchange.getRequest().getOptions().hasObserve();
				
				if (outgoingExceedsMaxUnfragSize(response, outerBlockwise, ctx.getMaxUnfragmentedSize())) {
					super.sendResponse(exchange,
							Response.createResponse(exchange.getCurrentRequest(), ResponseCode.INTERNAL_SERVER_ERROR));
					throw new IllegalStateException("outgoing response is exceeding the MAX_UNFRAGMENTED_SIZE!");
				}

				response = prepareSend(ctxDb, response, ctx, addPartialIV, outerBlockwise);
				exchange.setResponse(response);
			} catch (OSException e) {
				LOGGER.error("Error sending response: " + e.getMessage());
				return;
			}
		}
		super.sendResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.sendEmptyMessage(exchange, message);
	}

	/**
	 * Add values and keys to a list if the value provided is not null.
	 *
	 * @param attributes the list to add values and keys to
	 * @param key the key to add
	 * @param value the value to add
	 */
	private static void add(List<String> attributes, String key, String value) {
		if (value != null) {
			attributes.add(key);
			attributes.add(value);
		}
	}

	@Override
	public void receiveRequest(final Exchange exchange, final Request request) {
		if (isProtected(request)) {

			// For OSCORE-protected requests with the outer block1-option let
			// them pass through to be re-assembled by the block-wise layer
			if (request.getOptions().hasBlock1()) {
				//
				// if (exchange.getRequest() != null) {
				// System.out.println("a getRequest not null " +
				// exchange.getRequest().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getRequest()));
				//
				// }
				//
				// if (exchange.getCurrentRequest() != null) {
				// System.out.println(
				// "b getCurrentRequest not null " +
				// exchange.getCurrentRequest().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getCurrentRequest()));
				//
				// }
				//
				// if (exchange.getResponse() != null) {
				// System.out.println("c getResponse not null " +
				// exchange.getResponse().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getResponse()));
				//
				// }
				//
				// if (exchange.getCurrentResponse() != null) {
				// System.out.println(
				// "d getCurrentResponse not null " +
				// exchange.getCurrentResponse().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getCurrentResponse()));
				// }
				//
				// int totalSize = 0;
				//
				// totalSize = request.getOptions().getBlock1().getSize()
				// * (request.getOptions().getBlock1().getNum() + 1);
				//
				// System.out.println("Total size: " + totalSize);
				// System.out.println("Total size2: " +
				// request.getOptions().getBlock1().getOffset());
				// // request.getOptions().getBlock2().
				//
				// if (request.getOptions().getBlock1().isM() == false) {
				// totalSize += request.getPayloadSize() -
				// request.getOptions().getBlock1().getSize();
				// }
				// System.out.println("Total size3: " + totalSize);
				//
				// if (exchange.getEndpointContext() != null) {
				// System.out.println("CONT: " +
				// exchange.getEndpointContext().toString());
				// }
				// System.out.println("HASH: " + exchange.hashCode());

				// test

				if (exchange.getEndpointContext() != null) {
					System.out.println("ENDP con (pre) :" + exchange.getEndpointContext() + " "
							+ exchange.getEndpointContext().hashCode());
				}

				// FIXME: Try but outside observer!!!
				request.addMessageObserver(new MessageObserverAdapter() {

					@Override
					public void onAcknowledgement() {
						System.out.println("yeet onAcknowledgement");
						//
						// if (exchange.getEndpointContext() != null) {
						// System.out.println("ENDP con :" +
						// exchange.getEndpointContext() + " "
						// + exchange.getEndpointContext().hashCode() + " "
						// + exchange.getEndpointContext().getClass());
						//
						// List<String> attributes = new ArrayList<String>();
						// add(attributes, Integer.toString(rand.nextInt(2000) +"PAYLOAD"),
						// Integer.toString(rand.nextInt(1000)));
						// MapBasedEndpointContext test =
						// (MapBasedEndpointContext)
						// exchange.getEndpointContext();
						//
						// //
						// ((UdpEndpointContext)exchange.getEndpointContext()).addEntries(exchange.getEndpointContext(),
						// // attributes);
						// test =
						// MapBasedEndpointContext.addEntries(exchange.getEndpointContext(),
						// attributes.toArray(new String[attributes.size()]));
						// exchange.setEndpointContext(test);
						//
						// Map<String, String> aaa =
						// exchange.getEndpointContext().entries();
						// for (Entry<String, String> e : aaa.entrySet()) {
						// System.out.println("A " + e.getKey() + " " +
						// e.getValue());
						// }
						// }

						if (exchange.getRequest() != null) {
							System.out.println("getRequest not null " + exchange.getRequest().getPayloadSize());
							System.out.println(Utils.prettyPrint(exchange.getRequest()));

						}

						if (exchange.getCurrentRequest() != null) {
							System.out.println(
									"getCurrentRequest not null " + exchange.getCurrentRequest().getPayloadSize());
							System.out.println(Utils.prettyPrint(exchange.getCurrentRequest()));

						}

						if (exchange.getResponse() != null) {
							System.out.println("getResponse not null " + exchange.getResponse().getPayloadSize());
							System.out.println(Utils.prettyPrint(exchange.getResponse()));

						}

						if (exchange.getCurrentResponse() != null) {
							System.out.println(
									"getCurrentResponse not null " + exchange.getCurrentResponse().getPayloadSize());
							System.out.println(Utils.prettyPrint(exchange.getCurrentResponse()));

						}
					}

					Random rand = new Random();

					@Override
					public void onContextEstablished(EndpointContext endpointContext) {
						System.out.println("yeet onContextEstablished");

						if (exchange.getEndpointContext() != null) {
							System.out.println("ENDP con :" + exchange.getEndpointContext() + " "
									+ exchange.getEndpointContext().hashCode() + " "
									+ exchange.getEndpointContext().getClass());

							List<String> attributes = new ArrayList<String>();
							add(attributes, Integer.toString(rand.nextInt(101)), Integer.toString(rand.nextInt(1001)));
							add(attributes, Integer.toString(rand.nextInt(2000)) + "PAYLOAD",
									Integer.toString(request.getPayloadSize()));
							MapBasedEndpointContext test;

							// ((UdpEndpointContext)exchange.getEndpointContext()).addEntries(exchange.getEndpointContext(),
							// attributes);
							test = MapBasedEndpointContext.addEntries(exchange.getEndpointContext(),
									attributes.toArray(new String[attributes.size()]));
							exchange.setEndpointContext(test);

							Map<String, String> aaa = exchange.getEndpointContext().entries();
							for (Entry<String, String> e : aaa.entrySet()) {
								System.out.println("A " + e.getKey() + " " + e.getValue());
							}
						}

						if (exchange.getRequest().getDestinationContext() != null) {
							System.out.println("ENDP con :" + exchange.getRequest().getDestinationContext() + " "
									+ exchange.getRequest().getDestinationContext().hashCode() + " "
									+ exchange.getRequest().getDestinationContext().getClass());

							List<String> attributes = new ArrayList<String>();
							add(attributes, Integer.toString(rand.nextInt(101)), Integer.toString(rand.nextInt(1001)));
							add(attributes, Integer.toString(rand.nextInt(2000)) + "PAYLOAD",
									Integer.toString(request.getPayloadSize()));
							MapBasedEndpointContext test;

							// ((UdpEndpointContext)exchange.getRequest().getDestinationContext()).addEntries(exchange.getRequest().getDestinationContext(),
							// attributes);
							test = MapBasedEndpointContext.addEntries(exchange.getRequest().getDestinationContext(),
									attributes.toArray(new String[attributes.size()]));
							exchange.getRequest().setDestinationContext(test);

							Map<String, String> aaa = exchange.getRequest().getDestinationContext().entries();
							for (Entry<String, String> e : aaa.entrySet()) {
								System.out.println("B " + e.getKey() + " " + e.getValue());
							}
						}

						if (exchange.getRequest().getSourceContext() != null) {
							System.out.println("ENDP con :" + exchange.getRequest().getSourceContext() + " "
									+ exchange.getRequest().getSourceContext().hashCode() + " "
									+ exchange.getRequest().getSourceContext().getClass());

							List<String> attributes = new ArrayList<String>();
							add(attributes, Integer.toString(rand.nextInt(101)), Integer.toString(rand.nextInt(1001)));
							add(attributes, Integer.toString(rand.nextInt(2000)) + "PAYLOAD",
									Integer.toString(request.getPayloadSize()));
							MapBasedEndpointContext test;

							// ((UdpEndpointContext)exchange.getRequest().getSourceContext()).addEntries(exchange.getRequest().getSourceContext(),
							// attributes);
							test = MapBasedEndpointContext.addEntries(exchange.getRequest().getSourceContext(),
									attributes.toArray(new String[attributes.size()]));
							exchange.getRequest().setSourceContext(test);

							Map<String, String> aaa = exchange.getRequest().getSourceContext().entries();
							for (Entry<String, String> e : aaa.entrySet()) {
								System.out.println("C " + e.getKey() + " " + e.getValue());
							}
						}

						//

						if (exchange.getCurrentRequest().getDestinationContext() != null) {
							System.out.println("ENDP con :" + exchange.getCurrentRequest().getDestinationContext() + " "
									+ exchange.getCurrentRequest().getDestinationContext().hashCode() + " "
									+ exchange.getCurrentRequest().getDestinationContext().getClass());

							List<String> attributes = new ArrayList<String>();
							add(attributes, Integer.toString(rand.nextInt(101)), Integer.toString(rand.nextInt(1001)));
							add(attributes, Integer.toString(rand.nextInt(2000)) + "PAYLOAD",
									Integer.toString(request.getPayloadSize()));
							MapBasedEndpointContext test;

							// ((UdpEndpointContext)exchange.getCurrentRequest().getDestinationContext()).addEntries(exchange.getCurrentRequest().getDestinationContext(),
							// attributes);
							test = MapBasedEndpointContext.addEntries(
									exchange.getCurrentRequest().getDestinationContext(),
									attributes.toArray(new String[attributes.size()]));
							exchange.getCurrentRequest().setDestinationContext(test);

							Map<String, String> aaa = exchange.getCurrentRequest().getDestinationContext().entries();
							for (Entry<String, String> e : aaa.entrySet()) {
								System.out.println("D " + e.getKey() + " " + e.getValue());
							}
						}

						if (exchange.getCurrentRequest().getSourceContext() != null) {
							System.out.println("ENDP con :" + exchange.getCurrentRequest().getSourceContext() + " "
									+ exchange.getCurrentRequest().getSourceContext().hashCode() + " "
									+ exchange.getCurrentRequest().getSourceContext().getClass());

							List<String> attributes = new ArrayList<String>();
							add(attributes, Integer.toString(rand.nextInt(101)), Integer.toString(rand.nextInt(1001)));
							add(attributes, Integer.toString(rand.nextInt(2000)) + "PAYLOAD",
									Integer.toString(request.getPayloadSize()));
							MapBasedEndpointContext test;

							// ((UdpEndpointContext)exchange.getCurrentRequest().getSourceContext()).addEntries(exchange.getCurrentRequest().getSourceContext(),
							// attributes);
							test = MapBasedEndpointContext.addEntries(exchange.getCurrentRequest().getSourceContext(),
									attributes.toArray(new String[attributes.size()]));
							exchange.getCurrentRequest().setSourceContext(test);

							Map<String, String> aaa = exchange.getCurrentRequest().getSourceContext().entries();
							for (Entry<String, String> e : aaa.entrySet()) {
								System.out.println("E " + e.getKey() + " " + e.getValue());
							}
						}

						//

						if (exchange.getResponse() != null && exchange.getResponse().getDestinationContext() != null) {
							System.out.println("ENDP con :" + exchange.getResponse().getDestinationContext() + " "
									+ exchange.getResponse().getDestinationContext().hashCode() + " "
									+ exchange.getResponse().getDestinationContext().getClass());

							List<String> attributes = new ArrayList<String>();
							add(attributes, Integer.toString(rand.nextInt(101)), Integer.toString(rand.nextInt(1001)));
							add(attributes, Integer.toString(rand.nextInt(2000)) + "PAYLOAD",
									Integer.toString(request.getPayloadSize()));
							MapBasedEndpointContext test;

							// ((UdpEndpointContext)exchange.getResponse().getDestinationContext()).addEntries(exchange.getResponse().getDestinationContext(),
							// attributes);
							test = MapBasedEndpointContext.addEntries(exchange.getResponse().getDestinationContext(),
									attributes.toArray(new String[attributes.size()]));
							exchange.getResponse().setDestinationContext(test);

							Map<String, String> aaa = exchange.getResponse().getDestinationContext().entries();
							for (Entry<String, String> e : aaa.entrySet()) {
								System.out.println("F " + e.getKey() + " " + e.getValue());
							}
						}

						if (exchange.getResponse() != null && exchange.getResponse().getSourceContext() != null) {
							System.out.println("ENDP con :" + exchange.getResponse().getSourceContext() + " "
									+ exchange.getResponse().getSourceContext().hashCode() + " "
									+ exchange.getResponse().getSourceContext().getClass());

							List<String> attributes = new ArrayList<String>();
							add(attributes, Integer.toString(rand.nextInt(101)), Integer.toString(rand.nextInt(1001)));
							add(attributes, Integer.toString(rand.nextInt(2000)) + "PAYLOAD",
									Integer.toString(request.getPayloadSize()));
							MapBasedEndpointContext test;

							// ((UdpEndpointContext)exchange.getResponse().getSourceContext()).addEntries(exchange.getResponse().getSourceContext(),
							// attributes);
							test = MapBasedEndpointContext.addEntries(exchange.getResponse().getSourceContext(),
									attributes.toArray(new String[attributes.size()]));
							exchange.getResponse().setSourceContext(test);

							Map<String, String> aaa = exchange.getResponse().getSourceContext().entries();
							for (Entry<String, String> e : aaa.entrySet()) {
								System.out.println("G " + e.getKey() + " " + e.getValue());
							}
						}

						//

						if (exchange.getCurrentResponse().getDestinationContext() != null) {
							System.out.println("ENDP con :" + exchange.getCurrentResponse().getDestinationContext()
									+ " " + exchange.getCurrentResponse().getDestinationContext().hashCode() + " "
									+ exchange.getCurrentResponse().getDestinationContext().getClass());

							List<String> attributes = new ArrayList<String>();
							add(attributes, Integer.toString(rand.nextInt(101)), Integer.toString(rand.nextInt(1001)));
							add(attributes, Integer.toString(rand.nextInt(2000)) + "PAYLOAD",
									Integer.toString(request.getPayloadSize()));
							MapBasedEndpointContext test;

							// ((UdpEndpointContext)exchange.getCurrentResponse().getDestinationContext()).addEntries(exchange.getCurrentResponse().getDestinationContext(),
							// attributes);
							test = MapBasedEndpointContext.addEntries(
									exchange.getCurrentResponse().getDestinationContext(),
									attributes.toArray(new String[attributes.size()]));
							exchange.getCurrentResponse().setDestinationContext(test);

							Map<String, String> aaa = exchange.getCurrentResponse().getDestinationContext().entries();
							for (Entry<String, String> e : aaa.entrySet()) {
								System.out.println("H " + e.getKey() + " " + e.getValue());
							}
						}

						if (exchange.getCurrentResponse().getSourceContext() != null) {
							System.out.println("ENDP con :" + exchange.getCurrentResponse().getSourceContext() + " "
									+ exchange.getCurrentResponse().getSourceContext().hashCode() + " "
									+ exchange.getCurrentResponse().getSourceContext().getClass());

							List<String> attributes = new ArrayList<String>();
							add(attributes, Integer.toString(rand.nextInt(101)), Integer.toString(rand.nextInt(1001)));
							add(attributes, Integer.toString(rand.nextInt(2000)) + "PAYLOAD",
									Integer.toString(request.getPayloadSize()));
							MapBasedEndpointContext test;

							// ((UdpEndpointContext)exchange.getCurrentResponse().getSourceContext()).addEntries(exchange.getCurrentResponse().getSourceContext(),
							// attributes);
							test = MapBasedEndpointContext.addEntries(exchange.getCurrentResponse().getSourceContext(),
									attributes.toArray(new String[attributes.size()]));
							exchange.getCurrentResponse().setSourceContext(test);

							Map<String, String> aaa = exchange.getCurrentResponse().getSourceContext().entries();
							for (Entry<String, String> e : aaa.entrySet()) {
								System.out.println("I " + e.getKey() + " " + e.getValue());
							}
						}

						//


						if (exchange.getRequest() != null) {
							System.out.println("getRequest not null " + exchange.getRequest().getPayloadSize());
							System.out.println(Utils.prettyPrint(exchange.getRequest()));


						}

						if (exchange.getCurrentRequest() != null) {
							System.out.println(
									"getCurrentRequest not null " + exchange.getCurrentRequest().getPayloadSize());
							System.out.println(Utils.prettyPrint(exchange.getCurrentRequest()));

						}

						if (exchange.getResponse() != null) {
							System.out.println("getResponse not null " + exchange.getResponse().getPayloadSize());
							System.out.println(Utils.prettyPrint(exchange.getResponse()));

						}

						if (exchange.getCurrentResponse() != null) {
							System.out.println(
									"getCurrentResponse not null " + exchange.getCurrentResponse().getPayloadSize());
							System.out.println(Utils.prettyPrint(exchange.getCurrentResponse()));

						}
					}

					//

					@Override
					public void onReadyToSend() {
						System.out.println("yeet onReadyToSend");

						if (exchange.getRequest() != null) {
							System.out.println("not null");
						}
					}

					@Override
					public void onRetransmission() {
						System.out.println("yeet onRetransmission");
						if (exchange.getRequest() != null) {
							System.out.println("not null");
						}
					}

					@Override
					public void onResponse(Response response) {
						System.out.println("yeet onResponse");
						if (exchange.getRequest() != null) {
							System.out.println("not null");
						}
					}

					@Override
					public void onReject() {
						System.out.println("yeet onReject");
						if (exchange.getRequest() != null) {
							System.out.println("not null");
						}
					}

					@Override
					public void onCancel() {
						System.out.println("yeet onCancel");
						if (exchange.getRequest() != null) {
							System.out.println("not null");
						}
					}

					@Override
					public void onTimeout() {
						System.out.println("yeet onTimeout");
						if (exchange.getRequest() != null) {
							System.out.println("not null");
						}
					}

					@Override
					public void onSent(boolean retransmission) {
						System.out.println("yeet onSent");
						if (exchange.getRequest() != null) {
							System.out.println("not null");
						}
					}

					@Override
					public void onSendError(Throwable error) {
						System.out.println("yeet onSendError");
						if (exchange.getRequest() != null) {
							System.out.println("not null");
						}
					}

					@Override
					public void onComplete() {
						System.out.println("yeet onComplete");
						if (exchange.getRequest() != null) {
							System.out.println("not null");
						}
					}
				});

				// test

				super.receiveRequest(exchange, request);
				return;
			}

			byte[] rid = null;
			try {
				Request requestX = prepareReceive(ctxDb, request);
				rid = requestX.getOptions().getOscore();
				requestX.getOptions().setOscore(Bytes.EMPTY);
				exchange.setRequest(requestX);
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
	public void receiveResponse(final Exchange exchange, Response response) {
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
				// System.out.println("A " +
				// exchange.getCurrentResponse().getPayloadSize());
				// System.out.println("B " + FIXME
				// exchange.getResponse().getPayloadSize());
				// .
				// response.getDestinationContext();
				System.out.println("C " + response.getPayloadSize());
				System.out.println("D " + Utils.prettyPrint(exchange.getCurrentRequest()));

				// test
				//
				// request.addMessageObserver(new MessageObserverAdapter() {
				//
				// @Override
				// public void onAcknowledgement() {
				// System.out.println("yeet onAcknowledgement");
				//
				// if (exchange.getRequest() != null) {
				// System.out.println("getRequest not null " +
				// exchange.getRequest().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getRequest()));
				//
				// }
				//
				// if (exchange.getCurrentRequest() != null) {
				// System.out.println(
				// "getCurrentRequest not null " +
				// exchange.getCurrentRequest().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getCurrentRequest()));
				//
				// }
				//
				// if (exchange.getResponse() != null) {
				// System.out.println("getResponse not null " +
				// exchange.getResponse().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getResponse()));
				//
				// }
				//
				// if (exchange.getCurrentResponse() != null) {
				// System.out.println(
				// "getCurrentResponse not null " +
				// exchange.getCurrentResponse().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getCurrentResponse()));
				//
				// }
				// }
				//
				// @Override
				// public void onContextEstablished(EndpointContext
				// endpointContext) {
				// System.out.println("yeet onContextEstablished");
				//
				// if (exchange.getRequest() != null) {
				// System.out.println("getRequest not null " +
				// exchange.getRequest().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getRequest()));
				//
				// }
				//
				// if (exchange.getCurrentRequest() != null) {
				// System.out.println(
				// "getCurrentRequest not null " +
				// exchange.getCurrentRequest().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getCurrentRequest()));
				//
				// }
				//
				// if (exchange.getResponse() != null) {
				// System.out.println("getResponse not null " +
				// exchange.getResponse().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getResponse()));
				//
				// }
				//
				// if (exchange.getCurrentResponse() != null) {
				// System.out.println(
				// "getCurrentResponse not null " +
				// exchange.getCurrentResponse().getPayloadSize());
				// System.out.println(Utils.prettyPrint(exchange.getCurrentResponse()));
				//
				// }
				// }
				//
				// //
				//
				// @Override
				// public void onReadyToSend() {
				// System.out.println("yeet onReadyToSend");
				//
				// if (exchange.getRequest() != null) {
				// System.out.println("not null");
				// }
				// }
				//
				// @Override
				// public void onRetransmission() {
				// System.out.println("yeet onRetransmission");
				// if (exchange.getRequest() != null) {
				// System.out.println("not null");
				// }
				// }
				//
				// @Override
				// public void onResponse(Response response) {
				// System.out.println("yeet onResponse");
				// if (exchange.getRequest() != null) {
				// System.out.println("not null");
				// }
				// }
				//
				// @Override
				// public void onReject() {
				// System.out.println("yeet onReject");
				// if (exchange.getRequest() != null) {
				// System.out.println("not null");
				// }
				// }
				//
				// @Override
				// public void onCancel() {
				// System.out.println("yeet onCancel");
				// if (exchange.getRequest() != null) {
				// System.out.println("not null");
				// }
				// }
				//
				// @Override
				// public void onTimeout() {
				// System.out.println("yeet onTimeout");
				// if (exchange.getRequest() != null) {
				// System.out.println("not null");
				// }
				// }
				//
				// @Override
				// public void onSent(boolean retransmission) {
				// System.out.println("yeet onSent");
				// if (exchange.getRequest() != null) {
				// System.out.println("not null");
				// }
				// }
				//
				// @Override
				// public void onSendError(Throwable error) {
				// System.out.println("yeet onSendError");
				// if (exchange.getRequest() != null) {
				// System.out.println("not null");
				// }
				// }
				//
				// @Override
				// public void onComplete() {
				// System.out.println("yeet onComplete");
				// if (exchange.getRequest() != null) {
				// System.out.println("not null");
				// }
				// }
				// });

				// test

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

	/**
	 * Check if a message exceeds the MAX_UNFRAGMENTED_SIZE and is not using
	 * inner block-wise. If so it should not be sent.
	 * 
	 * @param ctx the OSCORE context used
	 * @param message the CoAP message
	 * @return if the message exceeds the MAX_UNFRAGMENTED_SIZE
	 */
	private static boolean outgoingExceedsMaxUnfragSize(Message message, boolean outerBlockwise,
			int maxUnfragmentedSize) {

		boolean usesInnerBlockwise = (message.getOptions().hasBlock1() == true
				|| message.getOptions().hasBlock2() == true) && outerBlockwise == false;

		if (message.getPayloadSize() > maxUnfragmentedSize && usesInnerBlockwise == false) {
			return true;
		} else {
			return false;
		}

	}
}
