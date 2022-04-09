/*******************************************************************************
 * Copyright (c) 2022 RISE and others.
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
 * This test class is based on org.eclipse.californium.integration.test.SecureBlockwiseTest
 * 
 * Contributors: 
 *    Rikard Höglund (RISE) - testing OSCORE over proxy servers
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URI;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

/**
 * Class for testing OSCORE transported via a proxy server. The test class
 * contains a server, client and OSCORE-unaware proxy.
 * 
 * It tests both usage of the Proxy-Uri option, and usage of the Uri-* options
 * together with the Proxy-Scheme option. See the following section in the
 * OSCORE RFC: https://datatracker.ietf.org/doc/html/rfc8613#section-10
 * 
 * One thing to note is that when Proxy-Uri is present the client must remove
 * the Path and Query components from it. The Path and Query will instead be set
 * as Uri-Path and Uri-Query which will be encrypted and transmitted in the
 * payload. See: https://datatracker.ietf.org/doc/html/rfc8613#section-4.1.3.3
 * 
 */
public class OSCoreProxyTest {

	/**
	 * Set network rule for the test
	 */
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	/**
	 * Set thread cleanup rule
	 */
	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	/**
	 * Set test logger rule
	 */
	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	static final String TARGET = "resource";

	// OSCORE context information shared between server and client
	private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static HashMapCtxDB dbServer = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static int MAX_UNFRAGMENTED_SIZE = Configuration.getStandard().get(CoapConfig.MAX_RESOURCE_BODY_SIZE);

	private MyResource resource;

	private String serverUri;
	private String proxyUri;
	private String payload;

	/**
	 * Creates and initializes a simple server supporting OSCORE.
	 */
	public void startupServer() {
		payload = "Correct payload in response from server";
		createOscoreServer();
		resource.setPayload(payload);
	}

	/**
	 * Creates and initializes a coap2coap proxy
	 */
	public void startupProxy() {
		createSimpleProxy();
	}

	/**
	 * Perform GET request via proxy using the Proxy-Uri option to indicate the
	 * server URI. (During later processing, when used with OSCORE, the
	 * Proxy-Uri option will be decomposed into Uri-* and Proxy-Scheme options).
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testProxyUri() throws Exception {
		startupServer();
		startupProxy();
		setClientContext(serverUri);

		Request request = Request.newGet().setURI(proxyUri);
		request.getOptions().setProxyUri(serverUri);
		request.getOptions().setOscore(Bytes.EMPTY);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);

		CoapResponse response = client.advanced(request);
		System.out.println(Utils.prettyPrint(response));

		assertNotNull("Response was null", response);
		assertEquals("Response payload was incorrect", payload, response.getResponseText());
		assertEquals("Response had incorrect code", CoAP.ResponseCode.CONTENT, response.getCode());
		client.shutdown();
	}

	/**
	 * Perform GET request via proxy using the Proxy-Scheme and the Uri-*
	 * options to indicate the server URI. The proxy address and port is set
	 * using an AddressEndpointContext.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testProxyScheme() throws Exception {
		startupServer();
		startupProxy();
		setClientContext(serverUri);

		String proxyAddress = URI.create(proxyUri).getHost();
		int proxyPort = URI.create(proxyUri).getPort();
		AddressEndpointContext proxy = new AddressEndpointContext(proxyAddress, proxyPort);

		Request request = Request.newGet();
		request.setDestinationContext(proxy);
		request.setURI(serverUri);
		request.setProxyScheme("coap");
		request.getOptions().setOscore(Bytes.EMPTY);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbClient);
		CoapEndpoint clientEndpoint = builder.build();

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		cleanup.add(clientEndpoint);
		CoapResponse response = client.advanced(request);
		System.out.println(Utils.prettyPrint(response));

		assertNotNull("Response was null", response);
		assertEquals("Response payload was incorrect", payload, response.getResponseText());
		assertEquals("Response had incorrect code", CoAP.ResponseCode.CONTENT, response.getCode());
		client.shutdown();
	}

	/**
	 * Set up OSCORE context information for request (client)
	 * 
	 * @param serverUri the URI the server resource is located at
	 */
	public void setClientContext(String serverUri) {
		byte[] sid = Bytes.EMPTY;
		byte[] rid = new byte[] { 0x01 };

		try {
			OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null,
					MAX_UNFRAGMENTED_SIZE);
			dbClient.addContext(serverUri, ctx);
		} catch (OSException e) {
			System.err.println("Failed to set client OSCORE Context information!");
		}
	}

	/**
	 * Set up OSCORE context information for response (server)
	 */
	public void setServerContext() {
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = Bytes.EMPTY;

		try {
			OSCoreCtx ctx_B = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, null,
					MAX_UNFRAGMENTED_SIZE);
			dbServer.addContext(ctx_B);
		} catch (OSException e) {
			System.err.println("Failed to set server OSCORE Context information!");
		}
	}

	/**
	 * Create a simple OSCORE server.
	 * 
	 * @param serverResponseBlockwise the server responds with block-wise
	 */
	private void createOscoreServer() {

		setServerContext();

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(dbServer);
		CoapEndpoint serverEndpoint = builder.build();

		CoapServer server = new CoapServer();
		cleanup.add(server);
		server.addEndpoint(serverEndpoint);
		resource = new MyResource(TARGET);
		server.add(resource);
		server.start();

		serverUri = TestTools.getUri(serverEndpoint, TARGET);
	}

	private static class MyResource extends OSCoreResource {

		private volatile String currentPayload;

		public MyResource(String name) {
			super(name, true);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(currentPayload);
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			exchange.respond(response);
		}

		public void setPayload(String payload) {
			currentPayload = payload;
		}
	}

	/**
	 * Create simple non-OSCORE proxy.
	 */
	private void createSimpleProxy() {

		final Coap2CoapTranslator coapTranslator = new Coap2CoapTranslator();

		// Create endpoint for proxy server side
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCoapStackFactory(CoapEndpoint.STANDARD_COAP_STACK_FACTORY);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);

		CoapEndpoint proxyServerEndpoint = builder.build();

		// Create proxy
		CoapServer proxy = new CoapServer();
		cleanup.add(proxy);
		proxy.addEndpoint(proxyServerEndpoint);
		proxy.setMessageDeliverer(new MessageDeliverer() {

			@Override
			public void deliverRequest(Exchange exchange) {

				Response outgoingResponse = null;
				try {
					// Create and send request to the server based on the
					// incoming request from the client
					Request incomingRequest = exchange.getRequest();

					boolean hasProxyUri = incomingRequest.getOptions().hasProxyUri();

					// The Proxy-Uri (if included) should only have Scheme,
					// Host and Port
					if (hasProxyUri) {
						URI proxyUri = URI.create(incomingRequest.getOptions().getProxyUri());

						if (proxyUri.getPath() != null && !proxyUri.getPath().isEmpty()
								|| proxyUri.getQuery() != null && !proxyUri.getQuery().isEmpty()) {
							Response resp = Response.createResponse(incomingRequest, ResponseCode.BAD_REQUEST);
							resp.setPayload("Bad request: Request Proxy-Uri contained Path or Query");
							exchange.sendResponse(resp);
							return;
						}
					}

					// Should only contain Proxy-Uri OR Proxy-Scheme
					if (incomingRequest.getOptions().hasProxyScheme() && hasProxyUri) {
						Response resp = Response.createResponse(incomingRequest, ResponseCode.BAD_REQUEST);
						resp.setPayload("Bad request: Request contained both Proxy-Scheme and Proxy-Uri options");
						exchange.sendResponse(resp);
						return;
					}

					boolean hasUriPath = incomingRequest.getOptions().getUriPath().size() != 0;
					boolean hasUriQuery = incomingRequest.getOptions().getUriQuery().size() != 0;

					// Request should never have visible Uri-Query or Uri-Path
					if (hasUriQuery || hasUriPath) {
						Response resp = Response.createResponse(incomingRequest, ResponseCode.BAD_REQUEST);
						resp.setPayload("Bad request: Request contained Uri-Path or Uri-Query options");
						exchange.sendResponse(resp);
						return;
					}

					// Request with Proxy-Uri should never have the Uri-*
					// options
					if (hasProxyUri && (incomingRequest.getOptions().hasUriHost()
							|| incomingRequest.getOptions().hasUriPort() || hasUriQuery || hasUriPath)) {
						Response resp = Response.createResponse(incomingRequest, ResponseCode.BAD_REQUEST);
						resp.setPayload("Bad request: Request with Proxy-Uri contained Uri-* options");
						exchange.sendResponse(resp);
						return;
					}

					URI finalDestinationUri = coapTranslator.getDestinationURI(incomingRequest,
							coapTranslator.getExposedInterface(incomingRequest));
					Request outgoingRequest = coapTranslator.getRequest(finalDestinationUri, incomingRequest);

					CoapClient proxyClient = new CoapClient();

					// Create endpoint for proxy client side
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setCoapStackFactory(CoapEndpoint.STANDARD_COAP_STACK_FACTORY);
					CoapEndpoint proxyClientEndpoint = builder.build();
					proxyClient.setEndpoint(proxyClientEndpoint);
					cleanup.add(proxyClientEndpoint);

					// Now receive the response from the server and prepare the
					// final response to the client
					CoapResponse incomingResponse = proxyClient.advanced(outgoingRequest);
					outgoingResponse = coapTranslator.getResponse(incomingResponse.advanced());
				} catch (org.eclipse.californium.proxy2.TranslationException | ConnectorException | IOException e) {
					System.err.println("Processing on proxy failed.");
					e.printStackTrace();
					fail();
				}

				// Send response to client
				exchange.sendResponse(outgoingResponse);
			}

			@Override
			public void deliverResponse(Exchange exchange, Response response) {
				System.out.println("Proxy: Deliver response called.");
			}
		});

		proxy.start();
		proxyUri = TestTools.getUri(proxyServerEndpoint, "/");
	}

}
