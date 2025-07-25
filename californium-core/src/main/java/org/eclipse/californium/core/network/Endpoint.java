/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;
import java.util.function.BiConsumer;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.auth.ApplicationAuthorizer;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ProtocolScheduledExecutorService;

/**
 * A communication endpoint multiplexing CoAP message exchanges between
 * (potentially multiple) clients and servers.
 * <p>
 * An Endpoint is bound to a particular IP address and port. Clients use an
 * Endpoint to send a request to a server. Servers bind resources to one or more
 * Endpoints in order for them to be requested over the network by clients.
 */
public interface Endpoint {

	/**
	 * Start this endpoint and all its components. The starts its connector. If
	 * no executor has been set yet, the endpoint uses a single-threaded
	 * executor.
	 * 
	 * @throws IOException if the endpoint could not be started, e.g. because
	 *             the endpoint's port is already in use.
	 */
	void start() throws IOException;

	/**
	 * Stop this endpoint and all its components, e.g., the connector. A stopped
	 * endpoint can be started again.
	 */
	void stop();

	/**
	 * Destroys this endpoint and all its components. A destroyed endpoint
	 * cannot be started again.
	 */
	void destroy();

	/**
	 * Clears this endpoint's internal registries for tracking message
	 * exchanges.
	 * <p>
	 * Needed for tests to remove duplicates.
	 */
	void clear();

	/**
	 * Checks, if this endpoint has started.
	 *
	 * @return {@code true} if this endpoint is running.
	 */
	boolean isStarted();

	/**
	 * Sets executor for this endpoint and all its components.
	 * <p>
	 * Executor is not managed by the endpoint, it must be shutdown externally,
	 * if the resource should be freed.
	 *
	 * @param executor executor for endpoint
	 * @throws NullPointerException if executor is {@code null}
	 * @throws IllegalStateException if the endpoint is already started and a
	 *             new executor is provided.
	 */
	void setExecutor(ProtocolScheduledExecutorService executor);

	/**
	 * Gets executor for this endpoint.
	 * 
	 * @return executor for endpoint. May be {@code null}, if no executor was
	 *         provided and the endpoint hasn't been started.
	 * @since 4.0
	 */
	ProtocolScheduledExecutorService getExecutor();

	/**
	 * Adds the observer to the list of observers. This is not related with CoAP
	 * observe relations.
	 * <p>
	 * If the endpoint {@link #isStarted()}, calls
	 * {@link EndpointObserver#started(Endpoint)}.
	 * <p>
	 * <b>Note:</b> This has nothing to do with CoAP observe relations.
	 * 
	 * @param obs the observer
	 * @since 3.1 (calls {@link EndpointObserver#started(Endpoint)}, if already
	 *        {@link #isStarted()})
	 */
	void addObserver(EndpointObserver obs);

	/**
	 * Removes the endpoint observer. This is not related with CoAP observe
	 * relations.
	 *
	 * @param obs the observer
	 */
	void removeObserver(EndpointObserver obs);

	/**
	 * Adds a listener for observe notification. This is related to CoAP
	 * observe.
	 * 
	 * @param listener the listener
	 */
	void addNotificationListener(BiConsumer<Request, Response> listener);

	/**
	 * Removes a listener for observe notification. This is related to CoAP
	 * observe.
	 * 
	 * @param listener the listener
	 */
	void removeNotificationListener(BiConsumer<Request, Response> listener);

	/**
	 * Adds a message interceptor to this endpoint to be called, when messages
	 * are passed between the {@link Connector} and this endpoint. When messages
	 * arrive from the connector, the corresponding receive-method is called.
	 * When a message is about to be sent over a connector, the corresponding
	 * send method is called. The interceptor can be thought of being placed
	 * inside an {@code CoapEndpoint} just between the message
	 * {@code Serializer} and the {@code Matcher}.
	 * <p>
	 * A {@code MessageInterceptor} registered here can cancel a message to stop
	 * it. If it is an outgoing message that traversed down through the
	 * {@code CoapStack} to the {@code Matcher} and is now intercepted and
	 * canceled, will not reach the {@code Connector}. If it is an incoming
	 * message coming from the {@code Connector} to the {@code DataParser} and
	 * is now intercepted and canceled, will not reach the {@code Matcher}.
	 *
	 * @param interceptor the interceptor
	 */
	void addInterceptor(MessageInterceptor interceptor);

	/**
	 * Removes the interceptor.
	 *
	 * @param interceptor the interceptor
	 */
	void removeInterceptor(MessageInterceptor interceptor);

	/**
	 * Gets all registered message interceptors.
	 *
	 * @return an immutable list of the registered interceptors.
	 */
	List<MessageInterceptor> getInterceptors();

	/**
	 * Adds a message interceptor to this endpoint to be called, when messages
	 * are fully processed. The send methods are called, when a {@link Message}
	 * was successful sent by the {@link Connector}, or the sending failed. The
	 * receive methods are called, when the message, received by the
	 * {@link Connector}, was fully processed by the {@link Matcher} and the
	 * {@link CoapStack}.
	 * <p>
	 * A {@code MessageInterceptor} registered here must not cancel the message.
	 * </p>
	 *
	 * @param interceptor the interceptor
	 */
	void addPostProcessInterceptor(MessageInterceptor interceptor);

	/**
	 * Removes the interceptor.
	 *
	 * @param interceptor the interceptor
	 */
	void removePostProcessInterceptor(MessageInterceptor interceptor);

	/**
	 * Gets all registered message post process interceptor.
	 *
	 * @return an immutable list of the registered message post process
	 *         interceptors.
	 */
	List<MessageInterceptor> getPostProcessInterceptors();

	/**
	 * Send the specified request.
	 * <p>
	 * Failures are reported with {@link Request#setSendError(Throwable)}.
	 * <p>
	 * <b>Note:</b> since 3.5 sending a request instance twice causes a send
	 * error.
	 *
	 * @param request the request
	 */
	void sendRequest(Request request);

	/**
	 * Send the specified response.
	 * <p>
	 * <b>Note:</b> since 3.5 sending a response instance twice causes a send
	 * error.
	 * 
	 * @param exchange the exchange
	 * @param response the response
	 */
	void sendResponse(Exchange exchange, Response response);

	/**
	 * Send the specified empty message.
	 * <p>
	 * <b>Note:</b> since 3.5 sending a empty message instance twice causes a
	 * send error.
	 * 
	 * @param exchange the exchange
	 * @param message the message
	 */
	void sendEmptyMessage(Exchange exchange, EmptyMessage message);

	/**
	 * Sets the message deliverer.
	 *
	 * @param deliverer the new message deliverer
	 */
	void setMessageDeliverer(MessageDeliverer deliverer);

	/**
	 * Gets the address this endpoint is associated with.
	 *
	 * @return the address
	 */
	InetSocketAddress getAddress();

	/**
	 * Gets the URI for accessing this endpoint.
	 * <p>
	 * The URI will be built using this endpoint's supported <em>scheme</em>
	 * (e.g. {@code coap} or {@code coaps}) and the host name or IP address and
	 * port this endpoint is bound to.
	 * 
	 * @return The URI.
	 */
	URI getUri();

	/**
	 * Gets this endpoint's configuration.
	 *
	 * @return the configuration
	 * @since 3.0 (changed return type to Configuration)
	 */
	Configuration getConfig();

	/**
	 * Cancel observation for this request.
	 * 
	 * @param token the token of the original request which establishes the
	 *            observe relation to cancel. The token must have none
	 *            client-local scope.
	 * @throws IllegalArgumentException if the token has client-local scope.
	 */
	void cancelObservation(Token token);

	/**
	 * Gets application authorizer.
	 * 
	 * @return application authorizer, or {@code null}, if not supported by this
	 *         endpoint.
	 * @since 4.0
	 */
	ApplicationAuthorizer getApplicationAuthorizer();
}
