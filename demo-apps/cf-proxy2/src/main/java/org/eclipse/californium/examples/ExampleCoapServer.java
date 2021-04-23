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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreEndpointContextInfo;
import org.eclipse.californium.oscore.OSException;

/**
 * Example CoAP server for proxy demonstration.
 * 
 * {@link coap://localhost:5683/coap-target}
 */
public class ExampleCoapServer {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[] { 0x01 };
	private final static byte[] rid = new byte[0];

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumDemo.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Proxy Demo-Server";

	public static final String RESOURCE = "/coap-target";

	public static final int DEFAULT_COAP_PORT = 5685;

	/**
	 * Special network configuration defaults handler.
	 */
	private static final NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.COAP_PORT, DEFAULT_COAP_PORT);
		}
	};

	private CoapServer coapServer;

	public ExampleCoapServer(NetworkConfig config, final int port) throws IOException {

		try {
			OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, null);
			db.addContext(uriLocal, ctx);
			OSCoreCoapStackFactory.useAsDefault(db);
		} catch (OSException e) {
			System.err.println("Failed to add OSCORE context: " + e);
			e.printStackTrace();
		}

		String path = RESOURCE;
		if (path.startsWith("/")) {
			path = path.substring(1);
		}
		// Create CoAP Server on PORT with a target resource
		coapServer = new CoapServer(config, port);
		coapServer.add(new CoapResource(path) {

			private final AtomicInteger counter = new AtomicInteger();

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("=== Receiving incoming request ===");

				System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
				System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());
				System.out.println("Request URI: " + exchange.advanced().getCurrentRequest().getURI());

				MapBasedEndpointContext mapCtx = (MapBasedEndpointContext) exchange.advanced().getRequest()
						.getSourceContext();
				String reqKid = mapCtx.getString(OSCoreEndpointContextInfo.OSCORE_RECIPIENT_ID);
				System.out.print("Incoming request uses OSCORE: ");
				if(reqKid != null) {
					System.out.println("true");
				} else {
					System.out.println("false");
				}

				System.out.println("=== End Receiving incoming request ===");

				exchange.setMaxAge(15);
				exchange.respond(ResponseCode.CONTENT,
						"Hi! I am the coap server on port " + port + ". Request " + counter.incrementAndGet() + ".",
						MediaTypeRegistry.TEXT_PLAIN);
			}

		});
		coapServer.start();
		System.out.println("Started CoAP server on port " + port);
		System.out.println("Request: coap://localhost:" + port + RESOURCE);
	}

	public static NetworkConfig init() {
		return NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
	}

	public static void main(String arg[]) throws IOException {
		NetworkConfig config = init();
		int port;
		if (arg.length > 0) {
			port = Integer.parseInt(arg[0]);
		} else {
			port = config.getInt(NetworkConfig.Keys.COAP_PORT);
		}
		new ExampleCoapServer(config, port);
	}
}
