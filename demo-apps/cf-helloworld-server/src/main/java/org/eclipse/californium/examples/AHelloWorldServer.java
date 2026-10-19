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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add endpoints for all IP addresses
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP parameter
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.observe.GroupObservationsInfo;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.ProtocolScheduledExecutorService;
import org.eclipse.californium.oscore.MulticastObservableResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AHelloWorldServer extends CoapServer {

	private static final Logger LOGGER = LoggerFactory.getLogger(AHelloWorldServer.class);

	static {
		CoapConfig.register();
		UdpConfig.register();
		TcpConfig.register();
	}

	/**
	 * Application entry point.
	 *
	 * Usage: AHelloWorldServer [bindAddress]
	 *
	 * @param args optional address to bind the physical interface endpoint
	 *            to. Defaults to the IPv4 address of the multicast interface.
	 */
	public static void main(String[] args) {
		try {
			String bindAddress = args.length > 0 ? args[0] : null;
			AHelloWorldServer server = new AHelloWorldServer();
			server.addEndpoint(bindAddress);
			server.start();
			try {
				Thread.currentThread().join();
			} catch (InterruptedException e) {
				LOGGER.warn("Main thread interrupted", e);
			}
		} catch (SocketException | UnknownHostException e) {
			LOGGER.error("Failed to initialize server: {}", e.getMessage());
		}
	}

	/**
	 * Add endpoints listening on the default CoAP port.
	 *
	 * @param bindAddress address of the physical interface endpoint, or
	 *            {@code null} to use the IPv4 address of the multicast
	 *            interface
	 * @throws UnknownHostException if the bind address can't be resolved
	 */
	private void addEndpoint(String bindAddress) throws UnknownHostException {
		Configuration config = Configuration.getStandard();
		int port = config.get(CoapConfig.COAP_PORT);

		// Loopback endpoint for local unicast
		InetAddress loopbackAddr = InetAddress.getLoopbackAddress();
		InetSocketAddress loopbackSocket = new InetSocketAddress(loopbackAddr, port);
		CoapEndpoint.Builder loopbackBuilder = new CoapEndpoint.Builder();
		loopbackBuilder.setInetSocketAddress(loopbackSocket);
		loopbackBuilder.setConfiguration(config);
		addEndpoint(loopbackBuilder.build());

		final ProtocolScheduledExecutorService executorService = ExecutorsUtil
				.newSingleThreadedProtocolExecutor(new DaemonThreadFactory(":CoapEndpoint")); //$NON-NLS-1$
		this.setExecutor(executorService, isRunning());

		// Physical interface endpoint for multicast support
		InetAddress physicalAddr = bindAddress != null ? InetAddress.getByName(bindAddress)
				: NetworkInterfacesUtil.getMulticastInterfaceIpv4();
		if (physicalAddr != null) {
			InetSocketAddress physicalSocket = new InetSocketAddress(physicalAddr, port);
			CoapEndpoint.Builder physicalBuilder = new CoapEndpoint.Builder();
			physicalBuilder.setInetSocketAddress(physicalSocket);
			physicalBuilder.setConfiguration(config);
			addEndpoint(physicalBuilder.build());
			LOGGER.info("Added physical interface endpoint: {}", physicalSocket);
		}
	}

	/**
	 * Constructor for the Hello-World server. Initializes resources.
	 */
	public AHelloWorldServer() throws SocketException {
		GroupObservationsInfo.init();
		add(new HelloWorldResource());
		add(new ObservableResource());
		add(new MulticastObservableResource("mult", true, new InetSocketAddress("224.0.1.187", 56830)));
	}

	/**
	 * Simple GET resource that supports POST to update its content.
	 */
	static class HelloWorldResource extends CoapResource {

		private String content;

		public HelloWorldResource() {
			super("get");
			getAttributes().setTitle("pasta Resource");
			this.content = "spaghetti";
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(content);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {
			String requestText = exchange.getRequestText();
			String old = this.content;
			this.content = requestText;
			String responsePayload = old + " ->" + content;
			exchange.respond(ResponseCode.CHANGED, responsePayload);
			changed();
		}
	}

	/**
	 * Observable resource that supports publish-subscribe style notifications.
	 */
	static class ObservableResource extends CoapResource {

		private volatile String content;

		public ObservableResource() {
			super("obs");
			getAttributes().setTitle("pub-sub Resource");
			setObservable(true);
			setObserveType(null);
			this.content = "1";
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, this.content);
		}

		@Override
		public void changed() {
			super.changed();
		}

		@Override
		public void removeObserveRelation(ObserveRelation relation) {
			super.removeObserveRelation(relation);
			LOGGER.info("Observe relation removed by client");
		}
	}
}
