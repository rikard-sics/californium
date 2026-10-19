/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add nextObserveNumber 
 *                                                    (for use by subclasses)
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace nextObserveNumber
 *                                                    by ObserveRelationFilter
 *                                                    (for use by subclasses)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - don't add canceled
 *                                                    observation-relations again.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add iPATCH
 *                                                    cleanup source according 
 *                                                    coding guidelines
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.io.FileWriter;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.observe.GroupObservationsInfo;
import org.eclipse.californium.core.observe.ObservationInfo;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MulticastObservableResource extends OSCoreResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(MulticastObservableResource.class);

	private volatile Integer content = 0;
	private Timer timer = new Timer();
	private volatile boolean cancelling = false;

	private final boolean isGroupObservable;
	private final OSCoreCtxDB ctxDb;
	private final InetSocketAddress multicastAdress;

	private static final int CSV_WRITE_THRESHOLD = 20;
	private static final String CSV_FILE = "timing_results.csv";
	private final List<long[]> timingRecords = new ArrayList<>();
	
	/**
	 * OSCORE protected resource
	 * uses OSCORE if there is a OSCoreCtxDB provided
	 */
	public MulticastObservableResource(String uri, boolean groupObservable, OSCoreCtxDB ctxDb, InetSocketAddress multicastAdress) {
		super(uri, true);
		this.ctxDb = ctxDb;
		getAttributes().setTitle("Multicast Observable Resource");
		setObservable(true);
		setObserveType(Type.NON);
		this.isGroupObservable = groupObservable;
		this.multicastAdress = multicastAdress;
		timer.schedule(new UpdateTask(), 20000, 10000);
	}
	
	/**
	 * Non-OSCORE protected resource
	 */
	public MulticastObservableResource(String uri, boolean groupObservable, InetSocketAddress multicastAdress) {
		super(uri, false);
		this.ctxDb = null;
		getAttributes().setTitle("Multicast Observable Resource");
		setObservable(true);
		setObserveType(Type.NON);
		this.isGroupObservable = groupObservable;
		this.multicastAdress = multicastAdress;
		timer.schedule(new UpdateTask(), 10000, 10000);
	}
	

	@Override
	public void handleGET(CoapExchange exchange) {
		GroupObservationsInfo groupObservationsInfo = GroupObservationsInfo.getInstance();
		String uriPath = this.getURI();

		if (exchange.getRequestOptions().hasObserve() && exchange.getRequestOptions().getObserve() == 0) {
			if (exchange.advanced().isPhantomRequest()) {
				handlePhantomRequest(exchange);
			} else if (groupObservationsInfo.isOngoingGroupObservation(uriPath)) {
				// Group observation already active, send informative response
				ObservationInfo obsInfo = groupObservationsInfo.getGroupObservationInfo(uriPath);
				groupObservationsInfo.incrementObserverCount(uriPath);
				sendInformativeResponse(exchange, obsInfo);
			} else if (shouldGroupObservationStart()) {
				groupObservationsInfo.addPendingClient(this.getURI(), exchange);
				setUpGroupObservation(exchange);
			}
		} else {
			// set new last_notif
			exchange.respond(ResponseCode.CONTENT, this.content.toString());
		}
	}
  
	/**
	 * Send informative response (5.03 Service Unavailable) with tp_info to a client.
	 * Per draft-ietf-core-observe-multicast-notifications Section 4.2.
	 */
	private void sendInformativeResponse(CoapExchange clientExchange, ObservationInfo obsInfo) {
		clientExchange.accept();

		// Section 4.2: Informative response MUST NOT have link-local source or destination addresses
		InetSocketAddress clientAddress = clientExchange.advanced().getRequest().getSourceContext().getPeerAddress();
		if (clientAddress.getAddress().isLinkLocalAddress()) {
			LOGGER.warn("Refusing to send informative response: client address {} is link-local (Section 4.2)", clientAddress);
			return;
		}
		InetSocketAddress localAddress = clientExchange.advanced().getEndpoint().getAddress();
		if (localAddress.getAddress() != null && localAddress.getAddress().isLinkLocalAddress()) {
			LOGGER.warn("Refusing to send informative response: server address {} is link-local (Section 4.2)", localAddress);
			return;
		}

		Response response = new Response(ResponseCode.SERVICE_UNAVAILABLE);
		response.setType(Type.CON);
		response.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_INFORMATIVE_RESPONSE_CBOR);
		response.setPayload(obsInfo.toCbor());
		response.setDestinationContext(clientExchange.advanced().getRequest().getSourceContext());
		response.setToken(clientExchange.advanced().getRequest().getToken());
		LOGGER.debug("Informative response payload: {}", obsInfo.toString());
		LOGGER.debug("Sending informative response (5.03) to client {} with token {}",
				clientExchange.advanced().getRequest().getSourceContext().getPeerAddress(),
				clientExchange.advanced().getRequest().getToken());

		clientExchange.advanced().getRequest().getOptions().removeObserve();
		clientExchange.respond(response);
	}
  
	/**
	 * Send informative responses to all pending clients waiting for group observation setup.
	 */
	private void sendInformativeResponsesToClients(String uriPath) {
		GroupObservationsInfo groupInfo = GroupObservationsInfo.getInstance();
		List<CoapExchange> pendingClients = groupInfo.removePendingClients(uriPath);

		LOGGER.debug("Sending informative responses to {} pending clients for {}", pendingClients.size(), uriPath);

		for (CoapExchange clientExchange : pendingClients) {
			groupInfo.incrementObserverCount(uriPath);
			sendInformativeResponse(clientExchange, groupInfo.getGroupObservationInfo(uriPath));
		}
	}
  
	@Override
	public void changed() {
		long serverTime = NtpUtil.now();
		timingRecords.add(new long[]{ content, serverTime });
		LOGGER.info("[TIMING] state={} serverTime={}", content, serverTime);

		if (content >= CSV_WRITE_THRESHOLD) {
			writeTimingCsv();
		}

		LOGGER.debug("Observer count at change: {}", this.getObserverCount());
		super.changed();
	}

	private void writeTimingCsv() {
		try (FileWriter writer = new FileWriter(CSV_FILE)) {
			writer.write("state,server_time,client_1,client_2,client_3\n");
			for (long[] record : timingRecords) {
				writer.write(record[0] + "," + record[1] + ",,,\n");
			}
			LOGGER.info("[TIMING] Wrote {} records to {}", timingRecords.size(), CSV_FILE);
		} catch (IOException e) {
			LOGGER.error("[TIMING] Failed to write CSV: {}", e.getMessage());
		}
	}

	@Override
	public void removeObserveRelation(ObserveRelation relation) {
		super.removeObserveRelation(relation);
	}

	public boolean isGroupObservable() {
		return isGroupObservable;
	}

	/**
	 * Cancel the group observation per draft Section 4.5.
	 * Sends a multicast 5.03 with Token T (no payload, no Observe option),
	 * then cleans up all group observation state.
	 */
	public void cancelGroupObservation() {
		String uriPath = this.getURI();
		GroupObservationsInfo groupInfo = GroupObservationsInfo.getInstance();

		if (!groupInfo.isOngoingGroupObservation(uriPath)) {
			LOGGER.debug("No ongoing group observation to cancel for {}", uriPath);
			return;
		}

		LOGGER.info("Cancelling group observation for {}", uriPath);
		cancelling = true;
		changed();
		groupInfo.removeGroupObservation(uriPath);
		cancelling = false;
	}
	/**
	 * Serializes a Request to transport-independent format (Section 4.2.2):
	 * code byte + serialized options + optional (0xFF + payload).
	 */
	private byte[] serializeRequestTransportIndependent(Request request) {
		DatagramWriter writer = new DatagramWriter();
		writer.writeByte((byte) request.getRawCode());
		DataSerializer.serializeOptionsAndPayload(writer, request.getOptions(), request.getPayload());
		return writer.toByteArray();
	}
	private void handlePhantomRequest(CoapExchange exchange) {
		String uriPath = this.getURI();
		GroupObservationsInfo groupObservationsInfo = GroupObservationsInfo.getInstance();
		Token exchangeToken = exchange.advanced().getRequest().getToken();
		Token pendingToken = groupObservationsInfo.getPendingToken(uriPath);

		// a pending group observation
		if (exchangeToken.equals(pendingToken)) {
			// First phantom request — establish the group observation
			exchange.advanced().setSuppressResponse(true);

			InetSocketAddress localAddress = exchange.advanced().getEndpoint().getAddress();
			InetSocketAddress multicastAddress = groupObservationsInfo.getMulticastAdressByToken(exchangeToken);
			ObservationInfo observationInfo = new ObservationInfo(localAddress, multicastAddress, exchangeToken);

			groupObservationsInfo.startGroupObservation(uriPath, observationInfo);
			groupObservationsInfo.setGroupObservationSetupInProgress(uriPath, false);
			
			// Store transport-independent serialization of the phantom request (Section 4.2.2)
			//if it is OSCORE protected
			byte[] phReqBytes;
			if (this.isProtected()){
				// getProtectedRequest() holds the full UDP datagram (ObjectSecurityLayer);
				// convert to the transport-independent form required by Section 4.2.2.
				phReqBytes = ObservationInfo.extractTransportIndependent(exchange.advanced().getProtectedRequest());
			}else {
				//if it is not oscore protected request
				phReqBytes = serializeRequestTransportIndependent(exchange.advanced().getRequest());

			}
			// store the phantom request 
			observationInfo.setPhReq(phReqBytes);

			
			if (this.isProtected()){
				byte[] reqOscoreOption = exchange.advanced().getCryptographicContextID();
				observationInfo.setRequestOscoreOption(reqOscoreOption);
				// Store the phantom request's OSCORE option parameters for encrypting last_notif
				try {
					OscoreOptionDecoder decoder = new OscoreOptionDecoder(reqOscoreOption);
					observationInfo.setRequestSequenceNumber(decoder.getSequenceNumber());
				} catch (CoapOSException e) {
					LOGGER.error("Failed to parse phantom OSCORE option: {}", e.getMessage());
				}
			}

			// Respond to establish the observe relation (response will be suppressed)
			exchange.respond(ResponseCode.CONTENT, this.content.toString());
			LOGGER.debug("Phantom request established for {} with content: {}", uriPath, this.content);

			// Section 4.1 Step 6 + Section 9.2: Build INIT_NOTIF and encrypt
			// INIT_NOTIF is formatted as a multicast notification (Section 4.3):
			// includes Observe option and current resource representation.
			Response initNotif = new Response(ResponseCode.CONTENT);
			initNotif.setPayload(this.content.toString());
			initNotif.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			initNotif.getOptions().setObserve(0);
			
			// with Group OSCORE before storing as last_notif. INIT_NOTIF is never
			// sent, so this is its only protection (one Sender Sequence Number).
			if(this.isProtected()) {
				byte[] lastNotif;
				lastNotif = protectInitNotif(initNotif, observationInfo);
				
				observationInfo.setLastNotifBytes(lastNotif);
				LOGGER.debug("Stored OSCORE-protected INIT_NOTIF as last_notif ({} bytes)", lastNotif.length);
			}else {
				LOGGER.warn("Storing plaintext last_notif");
				observationInfo.setLastNotif(initNotif);
			}
			sendInformativeResponsesToClients(uriPath);
		}else {
			handlePhantomGET(exchange);
		}
	}
	private void handlePhantomGET(CoapExchange exchange) {
		String uriPath = this.getURI();
		
		GroupObservationsInfo groupObservationsInfo = GroupObservationsInfo.getInstance();
		
		// Section 4.5: If cancelling, send 5.03 with no payload and no Observe option
		if (cancelling) {
			LOGGER.info("Sending cancellation 5.03 for group observation on {}", uriPath);
			exchange.respond(new Response(ResponseCode.SERVICE_UNAVAILABLE));
			return;
		}

		// Subsequent notification for established phantom exchange
		LOGGER.debug("Sending multicast notification for {} with content: {}", uriPath, this.content);

		Response notification = new Response(ResponseCode.CONTENT);
		notification.setPayload(this.content.toString());
		notification.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

		// draft-15 §4.3: the stored latest multicast notification must be what that notification
		// had when it was sent on the wire, so that a client registering later is served the same
		// last_notif (Section 4.2). Set the Observe Option here, from the same counter
		// ObserveRelation would have used: ObserveRelation.onResponse() only fills the option in
		// when it is absent (Response.isNotification() reports whether it is already set), and the
		// send is queued on the exchange's executor, so a copy taken afterwards would still be
		// missing it. Setting it up front makes the stored and the sent message identical.
		notification.getOptions().setObserve(getNotificationSequenceNumber());

		// With Group OSCORE, the notification is protected once when sent and
		// ObjectSecurityLayer stores that protected message as last_notif (Section 9.2.2)
		if (ctxDb == null) {
			ObservationInfo observationInfo = groupObservationsInfo.getGroupObservationInfo(uriPath);
			observationInfo.setLastNotif(notification);
		}
		exchange.respond(notification);
	}
	
	@Override
	public void handleRequest(final Exchange exchange) {
		GroupObservationsInfo groupObservationsInfo = GroupObservationsInfo.getInstance();
		if (groupObservationsInfo.isOngoingGroupObservation(this.getURI())) {
			exchange.getRequest().getOptions().setOscore(Bytes.EMPTY);
		}
		super.handleRequest(exchange);
	}

	
	private boolean shouldGroupObservationStart() {
		return this.getObserverCount() >= 0;
	}

	
	private void setUpGroupObservation(CoapExchange exchange) {
		String resourceUri = this.getURI();
		GroupObservationsInfo groupObservationsInfo = GroupObservationsInfo.getInstance();

		LOGGER.debug("Group observation for {} starting", resourceUri);
		
		synchronized (groupObservationsInfo) {
			if (groupObservationsInfo.isGroupObservationSetupInProgress(resourceUri)) {
				if (exchange.advanced().isPhantomRequest()) {
					LOGGER.debug("Phantom request for {} - allowing delivery during setup", resourceUri);
				} else {
					groupObservationsInfo.addPendingClient(resourceUri, exchange);
					LOGGER.debug("Setup in progress for {}, added client as pending", resourceUri);
					return;
				}
			} else {
				groupObservationsInfo.setGroupObservationSetupInProgress(resourceUri, true);
			}
		}


		// Allocate multicast token T and create phantom request
		Token multicastToken = groupObservationsInfo.allocateMulticastToken(resourceUri);
		LOGGER.debug("Allocated multicast token {} for {}", multicastToken, resourceUri);

		
		//using token, set up multicast address
		groupObservationsInfo.setMulticastAdressByToken(multicastToken, multicastAdress);
		
		final Request phantomRequest = groupObservationsInfo.createPhantomRequest(this, multicastToken, exchange, true);
		
		// Deliver phantom request through the CoAP stack so ObserveLayer
		// can detect it and establish the observe relation
		LOGGER.debug("Injecting phantom request for {} with token {}", resourceUri, multicastToken);
		CoapEndpoint endpoint = (CoapEndpoint) exchange.advanced().getEndpoint();
		endpoint.sendRequest(phantomRequest);
	}
	
	/**	
	 * Protects INIT_NOTIF using Group OSCORE and returns its transport-independent
	 * serialization for use as the first {@code last_notif} (Section 4.1 step 6,
	 * Section 9.2.2). INIT_NOTIF is never sent, so this consumes its one Sender
	 * Sequence Number; sent notifications are stored by ObjectSecurityLayer.
	 *
	 * @param response the plaintext INIT_NOTIF to protect
	 * @param obsInfo the observation info containing the phantom request's OSCORE parameters
	 * @return the transport-independent bytes of the protected response, or {@code null} on failure
	 */
	private byte[] protectInitNotif(Response response, ObservationInfo obsInfo) {
		try {
			byte[] requestOption = obsInfo.getRequestOscoreOption();
			int requestSeqNr = obsInfo.getRequestSequenceNumber();
			Token token = obsInfo.getToken();

			OSCoreCtx ctx = ctxDb.getContextByToken(token);
			if (ctx == null) {
				LOGGER.error("No OSCORE context found for token {} when encrypting last_notif", token);
				return null;
			}

			// Clone the response so the original is not modified by encryption
			Response toEncrypt = new Response(response.getCode());
			toEncrypt.setPayload(response.getPayload());
			toEncrypt.setOptions(new OptionSet(response.getOptions()));
			toEncrypt.setToken(token);

			// Encrypt using Group OSCORE with new partial IV (observe response)
			Response encrypted = ObjectSecurityLayer.prepareSend(
					ctxDb, toEncrypt, ctx, true, false, requestSeqNr, requestOption);

			return ObservationInfo.serializeTransportIndependent(encrypted);
		} catch (OSException e) {
			LOGGER.error("Failed to encrypt last_notif: {}", e.getMessage());
			return null;
		}
	}

	
	class UpdateTask extends TimerTask {
		@Override
		public void run() {
			content++;
			changed();
			
		}
	}
}

