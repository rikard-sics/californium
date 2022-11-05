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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.examples.util.CoapResponsePrinter;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.proxy2.resources.ResponseForwardingOption;

/**
 * Class ExampleProxyCoapClient.
 * 
 * Example CoAP client which sends a request to Proxy Coap server with a
 * {@link ProxyHttpClientResource} to get the response from HttpServer.
 * 
 * For testing Coap2Http:
 * 
 * <pre>
 * Destination: localhost:5683 (proxy's address)
 * Coap Uri: {@code coap://localhost:8000/http-target}
 * Proxy Scheme: {@code http}
 * </pre>
 * 
 * or
 * 
 * <pre>
 * Destination: localhost:5683 (proxy's address)
 * Proxy Uri: {@code http://user@localhost:8000/http-target}
 * </pre>
 * 
 * For testing Coap2coap:
 * 
 * <pre>
 * Destination: localhost:5683 (proxy's address)
 * Coap Uri: {@code coap://localhost:5685/coap-target}
 * </pre>
 * 
 * Deprecated modes:
 * 
 * <pre>
 * Uri: {@code coap://localhost:8000/coap2http}
 * Proxy Uri: {@code http://localhost:8000/http-target}
 * </pre>
 * 
 * For testing Coap2coap:
 * 
 * <pre>
 * Uri: {@code coap://localhost:5683/coap2coap}
 * Proxy Uri: {@code coap://localhost:5685/coap-target}
 * </pre>
 */
public class ExampleProxy2CoapClient {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	// private final static String uriLocal = "coap://localhost";
	// private final static String hello1 = "/hello/1";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	/**
	 * Time to wait for replies to the multicast request
	 */
	private static final int HANDLER_TIMEOUT = 5000;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };

	static {
		CoapConfig.register();
		UdpConfig.register();
		TcpConfig.register();
	}

	private static void request(CoapClient client, Request request) {
		try {
			CoapResponse response = client.advanced(request);
			System.out.println("Received response from proxy:");

			// https://datatracker.ietf.org/doc/html/draft-tiloca-core-groupcomm-proxy-07#section-3
			ResponseForwardingOption responseForwarding = new ResponseForwardingOption(ResponseForwardingOption.NUMBER);
			responseForwarding
					.setValue(response.getOptions().getOthers(ResponseForwardingOption.NUMBER).get(0).getValue());
			System.out.println("Response-Forwarding: " + "tp_id: " + responseForwarding.getTpId() + ", srv_host: "
					+ responseForwarding.getSrvHost() + ", srv_port: " + responseForwarding.getSrvPort());

			CoapResponsePrinter.printResponse(response);
		} catch (ConnectorException | IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws InterruptedException {

		URI proxyUri = null;
		try {
			OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null,
					MAX_UNFRAGMENTED_SIZE);
			db.addContext("coap://localhost", ctx);
			OSCoreCoapStackFactory.useAsDefault(db);
			proxyUri = new URI("coap", "localhost", null, null);
		} catch (OSException | URISyntaxException e) {
			System.err.println("Failed to add OSCORE context: " + e);
			e.printStackTrace();
		}

		CoapClient client = new CoapClient();
		// // deprecated proxy request - use CoAP and Proxy URI together
		Request request = Request.newGet();
		// request.setURI("coap://localhost:" + PROXY_PORT + "/coap2http");
		// // set proxy URI in option set to bypass the CoAP/proxy URI exclusion
		// request.getOptions().setProxyUri("http://localhost:8000/http-target");
		// System.out.println("Proxy-URI: " +
		// request.getOptions().getProxyUri());
		// request(client, request);
		//
		// // deprecated proxy request - use CoAP and Proxy URI together
		// request = Request.newGet();
		// request.setURI("coap://localhost:" + PROXY_PORT + "/coap2coap");
		// // set proxy URI in option set to bypass the CoAP/proxy URI exclusion
		// request.getOptions().setProxyUri("coap://localhost:5685/coap-target");
		// System.out.println("Proxy-URI: " +
		// request.getOptions().getProxyUri());
		// request(client, request);
		//
		// AddressEndpointContext proxy = new
		// AddressEndpointContext("localhost", PROXY_PORT);
		// // RFC7252 proxy request - use CoAP-URI, proxy scheme, and
		// destination
		// // to proxy
		// request = Request.newGet();
		// request.setDestinationContext(proxy);
		// // using a proxy-destination, a literal-ip address
		// // (e.g. 127.0.0.1) as final destination is not recommended!
		// request.setURI("coap://localhost:8000/http-target");
		// request.setProxyScheme("http");
		// System.out.println("Proxy-Scheme: " +
		// request.getOptions().getProxyScheme() + ": " + request.getURI());
		// request(client, request);
		//
		// // RFC7252 proxy request - use CoAP-URI, and destination to proxy
		// request = Request.newGet();
		// request.setDestinationContext(proxy);
		// // using a proxy-destination, a literal-ip address
		// // (e.g. 127.0.0.1) as final destination is not recommended!
		// request.setURI("coap://localhost:5685/coap-target");
		// System.out.println("Proxy: " + request.getURI());
		// request(client, request);
		//
		// request = Request.newGet();
		// request.setDestinationContext(proxy);
		// // using a proxy-destination, a literal-ip address
		// // (e.g. 127.0.0.1) as final destination is not recommended!
		// // May result in error response
		// request.setURI("coap://127.0.0.1:5685/coap-target");
		// System.out.println("Proxy: " + request.getURI());
		// request(client, request);
		//
		// request = Request.newGet();
		// request.setDestinationContext(proxy);
		// // if using a proxy-destination, and a literal-ip address
		// // (e.g. 127.0.0.1) as final destination is required,
		// // please add the URI host explicitly!
		// request.setURI("coap://127.0.0.1:5685/coap-target");
		// request.getOptions().setUriHost("127.0.0.1");
		// System.out.println("Proxy: " + request.getURI());
		// request(client, request);
		//
		// // RFC7252 proxy request - use Proxy-URI, and destination to proxy
		// request = Request.newGet();
		// request.setDestinationContext(proxy);
		// request.setProxyUri("http://user@localhost:8000/http-target");
		// request.setType(Type.NON);
		// System.out.println("Proxy-URI: " +
		// request.getOptions().getProxyUri());
		// request(client, request);
		//
		// // RFC7252 proxy request - use CoAP-URI, and destination to proxy
		// // => 4.04 NOT FOUND, the proxy itself has no resource "coap-target"
		// request = Request.newGet();
		// request.setDestinationContext(proxy);
		// // using a proxy-destination and a literal-ip address
		// // (e.g. 127.0.0.1) as final destination is not recommended!
		// request.setURI("coap://localhost:5683/coap-target");
		// System.out.println("Proxy: " + request.getURI() + " =>
		// 4.04/NOT_FOUND");
		// request(client, request);
		//
		// // RFC7252 reverse proxy request
		// request = Request.newGet();
		// request.setURI("coap://localhost:5683/targets/destination1");
		// System.out.println("Reverse-Proxy: " + request.getURI());
		// request(client, request);
		//
		// request = Request.newGet();
		// request.setURI("coap://localhost:5683/targets/destination2");
		// System.out.println("Reverse-Proxy: " + request.getURI());
		// request(client, request);
		//
		// System.out.println("CoapClient using Proxy:");
		// request = Request.newPost();
		// // Request: first destination, then URI
		// request.setDestinationContext(proxy);
		// // using a proxy-destination and a literal-ip address
		// // (e.g. 127.0.0.1) as final destination is not recommended!
		// request.setURI("coap://localhost:8000/http-target");
		// request.setProxyScheme("http");
		// request.setPayload("coap-client");
		// try {
		// CoapResponse response = client.advanced(request);
		// CoapResponsePrinter.printResponse(response);
		// } catch (ConnectorException e) {
		// e.printStackTrace();
		// } catch (IOException e) {
		// e.printStackTrace();
		// }
		//
		// // using CoapClient with proxy
		// client.enableProxy(true);
		// client.setDestinationContext(proxy);
		// // using a proxy-destination and a literal-ip address
		// // (e.g. 127.0.0.1) as final destination is not recommended!
		// client.setURI("coap://localhost:5685/coap-target");
		// try {
		// CoapResponse response = client.post("coap-client",
		// MediaTypeRegistry.TEXT_PLAIN);
		// CoapResponsePrinter.printResponse(response);
		// } catch (ConnectorException e) {
		// e.printStackTrace();
		// } catch (IOException e) {
		// e.printStackTrace();
		// }
		// client.setProxyScheme("http");
		// // using a proxy-destination and a literal-ip address
		// // (e.g. 127.0.0.1) as final destination is not recommended!
		// client.setURI("coap://localhost:8000/http-target");
		// try {
		// CoapResponse response = client.post("coap-client",
		// MediaTypeRegistry.TEXT_PLAIN);
		// CoapResponsePrinter.printResponse(response);
		// } catch (ConnectorException e) {
		// e.printStackTrace();
		// } catch (IOException e) {
		// e.printStackTrace();
		// }
		// client.setProxyScheme(null);
		// // using a proxy-destination and a literal-ip address
		// // (e.g. 127.0.0.1) as final destination is not recommended!
		// client.setURI("http://localhost:8000/http-target");
		// try {
		// CoapResponse response = client.post("coap-client",
		// MediaTypeRegistry.TEXT_PLAIN);
		// CoapResponsePrinter.printResponse(response);
		// } catch (ConnectorException e) {
		// e.printStackTrace();
		// } catch (IOException e) {
		// e.printStackTrace();
		// }
		//
		// //
		//
		// // OSCORE proxy request - use Proxy-URI, and destination to proxy
		// request = Request.newGet();
		// request.getOptions().setOscore(Bytes.EMPTY);
		// // request.setDestinationContext(proxy); // Doesn't work for OSCORE
		// request.setURI(proxyUri.toString());
		// request.getOptions().setProxyUri("coap://localhost:5685/coap-target");
		// System.out.println("Proxy-URI: " +
		// request.getOptions().getProxyUri());
		// request(client, request);
		//
		// // CoAP proxy request - use Proxy-URI, and destination to proxy
		// // (Same as above without OSCORE)
		// request = Request.newGet();
		// // request.setDestinationContext(proxy); // Doesn't work for OSCORE
		// request.setURI(proxyUri.toString());
		// request.getOptions().setProxyUri("coap://localhost:5685/coap-target");
		// System.out.println("Proxy-URI: " +
		// request.getOptions().getProxyUri());
		// request(client, request);
		//
		// // CoAP proxy request - use Proxy-URI, and destination to proxy
		// // (Same as above)
		// request = Request.newGet();
		// // request.setDestinationContext(proxy); // Doesn't work for OSCORE
		// request.setURI(proxyUri.toString());
		// request.getOptions().setProxyUri("coap://localhost:5685/coap-target");
		// System.out.println("Proxy-URI: " +
		// request.getOptions().getProxyUri());
		// request(client, request);

		// == Groupcomm-proxy testing below

		// // CoAP proxy request - use Proxy-URI, and destination to proxy
		// // (Same as above without OSCORE)
		// request = Request.newGet();
		// // request.setDestinationContext(proxy); // Doesn't work for OSCORE
		// request.setURI(proxyUri.toString());
		// request.getOptions().setProxyUri("coap://224.0.1.187:5685/coap-target");
		// System.out.println("Proxy-URI: " +
		// request.getOptions().getProxyUri());
		// request(client, request);

		// Try sending request with multicast handler
		// (To allow multiple responses)
		// sends a multicast request
		request = Request.newGet();
		// request.setDestinationContext(proxy); // Doesn't work for OSCORE
		request.setURI(proxyUri.toString());
		request.getOptions().setProxyUri("coap://224.0.1.187:5685/coap-target");
		request.getOptions().setObserve(0);
		System.out.println("Proxy-URI: " + request.getOptions().getProxyUri());

		request.setMultiResponse(true);
		client.advanced(handler, request);
		while (handler.waitOn(HANDLER_TIMEOUT)) {
			// Wait for responses
		}

		client.shutdown();
	}

	// == Multicast handler below

	private static final MultiCoapHandler handler = new MultiCoapHandler();

	private static class MultiCoapHandler implements CoapHandler {

		private boolean on;

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

			// https://datatracker.ietf.org/doc/html/draft-tiloca-core-groupcomm-proxy-07#section-3
			ResponseForwardingOption responseForwarding = new ResponseForwardingOption(ResponseForwardingOption.NUMBER);
			responseForwarding
					.setValue(response.getOptions().getOthers(ResponseForwardingOption.NUMBER).get(0).getValue());
			System.out.println("Response-Forwarding: " + "tp_id: " + responseForwarding.getTpId() + ", srv_host: "
					+ responseForwarding.getSrvHost() + ", srv_port: " + responseForwarding.getSrvPort());

			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	}

	// Handler for Observe responses (unused)
	static class ObserveHandler implements CoapHandler {

		int count = 1;
		int abort = 0;

		// Triggered when a Observe response is received
		@Override
		public void onLoad(CoapResponse response) {
			abort++;

			String content = response.getResponseText();
			System.out.println("NOTIFICATION (#" + count + "): " + content);

			count++;
		}

		@Override
		public void onError() {
			System.err.println("Observing failed");
		}
	}
}
