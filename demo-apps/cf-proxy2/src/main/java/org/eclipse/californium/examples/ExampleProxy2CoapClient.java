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
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.examples.util.CoapResponsePrinter;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.proxy2.resources.ProxyHttpClientResource;

/**
 * Class ExampleProxyCoapClient.
 * 
 * Example CoAP client which sends a request to Proxy Coap server with a
 * {@link ProxyHttpClientResource} to get the response from HttpServer.
 * 
 * For testing Coap2Http:
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
 * <pre>
 * Destination: localhost:5683 (proxy's address)
 * Coap Uri: {@code coap://localhost:5685/coap-target}
 * </pre>
 * 
 * Deprecated modes:
 * <pre>
 * Uri: {@code coap://localhost:8000/coap2http}
 * Proxy Uri: {@code http://localhost:8000/http-target}
 * </pre>
 * 
 * For testing Coap2coap:
 * <pre>
 * Uri: {@code coap://localhost:5683/coap2coap}
 * Proxy Uri: {@code coap://localhost:5685/coap-target}
 * </pre>
 */
public class ExampleProxy2CoapClient {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
	private final static String hello1 = "/hello/1";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };

	// M.T.
	// private static final int PROXY_PORT = 5683;
	private static final int PROXY_PORT = 5685;
	private static final int PROXY_HTTP_PORT = 8000;
	private static final int SERVER_COAP_PORT = 5683;
	private static final int SERVER_HTTP_PORT = 8080;

	static {
		CoapConfig.register();
		UdpConfig.register();
		TcpConfig.register();
	}

	private static void request(CoapClient client, Request request) {

		try {
			CoapResponse response = client.advanced(request);
			CoapResponsePrinter.printResponse(response);
		} catch (ConnectorException | IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {

		URI proxyUri = null;
		try {
			OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null, MAX_UNFRAGMENTED_SIZE);
			db.addContext(uriLocal, ctx);
			OSCoreCoapStackFactory.useAsDefault(db);
			
			// M.T.
			// proxyUri = new URI("coap", "localhost", null, null);
			proxyUri = new URI("coap", null, "localhost", PROXY_PORT, "/coap2coap", null, null); // coap://localhost:5685/coap2coap
			
		} catch (OSException | URISyntaxException e) {
			System.err.println("Failed to add OSCORE context: " + e);
			e.printStackTrace();
		}
		
		CoapClient client = new CoapClient();
		// deprecated proxy request - use CoAP and Proxy URI together
		Request request = Request.newGet();
		request.setURI("coap://localhost:" + PROXY_PORT + "/coap2http");
		// set proxy URI in option set to bypass the CoAP/proxy URI exclusion
		request.getOptions().setProxyUri("http://localhost:" + SERVER_HTTP_PORT + "/http-target"); // M.T.
		System.out.println("Proxy-URI: " + request.getOptions().getProxyUri());
		request(client, request);

		// deprecated proxy request - use CoAP and Proxy URI together
		request = Request.newGet();
		request.setURI("coap://localhost:" + PROXY_PORT + "/coap2coap");
		// set proxy URI in option set to bypass the CoAP/proxy URI exclusion
		request.getOptions().setProxyUri("coap://localhost:" + SERVER_COAP_PORT + "/coap-target"); // M.T.
		System.out.println("Proxy-URI: " + request.getOptions().getProxyUri());
		request(client, request);

		AddressEndpointContext proxy = new AddressEndpointContext("localhost", PROXY_PORT);
		// RFC7252 proxy request - use CoAP-URI, proxy scheme, and destination
		// to proxy
		request = Request.newGet();
		request.setDestinationContext(proxy);
		// using a proxy-destination, a literal-ip address
		// (e.g. 127.0.0.1) as final destination is not recommended!
		request.setURI("coap://localhost:8000/http-target");
		request.setProxyScheme("http");
		System.out.println("Proxy-Scheme: " + request.getOptions().getProxyScheme() + ": " + request.getURI());
		request(client, request);

		// RFC7252 proxy request - use CoAP-URI, and destination to proxy
		request = Request.newGet();
		request.setDestinationContext(proxy);
		// using a proxy-destination, a literal-ip address
		// (e.g. 127.0.0.1) as final destination is not recommended!
		request.setURI("coap://localhost:5685/coap-target");
		System.out.println("Proxy: " + request.getURI());
		request(client, request);

		request = Request.newGet();
		request.setDestinationContext(proxy);
		// using a proxy-destination, a literal-ip address
		// (e.g. 127.0.0.1) as final destination is not recommended!
		// May result in error response
		request.setURI("coap://127.0.0.1:5685/coap-target");
		System.out.println("Proxy: " + request.getURI());
		request(client, request);

		request = Request.newGet();
		request.setDestinationContext(proxy);
		// if using a proxy-destination, and a literal-ip address
		// (e.g. 127.0.0.1) as final destination is required,
		// please add the URI host explicitly!
		request.setURI("coap://127.0.0.1:5685/coap-target");
		request.getOptions().setUriHost("127.0.0.1");
		System.out.println("Proxy: " + request.getURI());
		request(client, request);

		// RFC7252 proxy request - use Proxy-URI, and destination to proxy
		request = Request.newGet();
		request.setDestinationContext(proxy);
		request.setProxyUri("http://user@localhost:" + SERVER_HTTP_PORT + "/http-target"); // M.T.
		request.setType(Type.NON);
		System.out.println("Proxy-URI: " + request.getOptions().getProxyUri());
		request(client, request);

		// RFC7252 proxy request - use CoAP-URI, and destination to proxy
		// => 4.04 NOT FOUND, the proxy itself has no resource "coap-target"
		request = Request.newGet();
		request.setDestinationContext(proxy);
		// using a proxy-destination and a literal-ip address
		// (e.g. 127.0.0.1) as final destination is not recommended!
		request.setURI("coap://localhost:5683/coap-target");
		System.out.println("Proxy: " + request.getURI() + " => 4.04/NOT_FOUND");
		request(client, request);

		// RFC7252 reverse proxy request
		request = Request.newGet();
		request.setURI("coap://localhost:" + PROXY_PORT + "/targets/destination1"); // M.T.
		System.out.println("Reverse-Proxy: " + request.getURI());
		request(client, request);

		request = Request.newGet();
		request.setURI("coap://localhost:" + PROXY_PORT + "/targets/destination2"); // M.T.
		System.out.println("Reverse-Proxy: " + request.getURI());
		request(client, request);

		System.out.println("CoapClient using Proxy:");
		request = Request.newPost();
		// Request: first destination, then URI
		request.setDestinationContext(proxy);
		// using a proxy-destination and a literal-ip address
		// (e.g. 127.0.0.1) as final destination is not recommended!
		request.setURI("coap://localhost:8000/http-target");
		request.setProxyScheme("http");
		request.setPayload("coap-client");
		try {
			CoapResponse response = client.advanced(request);
			CoapResponsePrinter.printResponse(response);
		} catch (ConnectorException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// using CoapClient with proxy
		client.enableProxy(true);
		client.setDestinationContext(proxy);
		// using a proxy-destination and a literal-ip address
		// (e.g. 127.0.0.1) as final destination is not recommended!
		client.setURI("coap://localhost:5685/coap-target");
		try {
			CoapResponse response = client.post("coap-client", MediaTypeRegistry.TEXT_PLAIN);
			CoapResponsePrinter.printResponse(response);
		} catch (ConnectorException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		client.setProxyScheme("http");
		// using a proxy-destination and a literal-ip address
		// (e.g. 127.0.0.1) as final destination is not recommended!
		client.setURI("coap://localhost:8000/http-target");
		try {
			CoapResponse response = client.post("coap-client", MediaTypeRegistry.TEXT_PLAIN);
			CoapResponsePrinter.printResponse(response);
		} catch (ConnectorException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		client.setProxyScheme(null);
		// using a proxy-destination and a literal-ip address
		// (e.g. 127.0.0.1) as final destination is not recommended!
		client.setURI("http://localhost:8000/http-target");
		try {
			CoapResponse response = client.post("coap-client", MediaTypeRegistry.TEXT_PLAIN);
			CoapResponsePrinter.printResponse(response);
		} catch (ConnectorException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Newly added tests below
		
		// RH: Newly added tests below

		System.out.println("");
		System.out.println("*** New tests below ***");
		System.out.println("");

		// OSCORE proxy request - use Proxy-URI, and destination to proxy
		System.out.println("Request A");
		request = Request.newGet();
		request.getOptions().setOscore(Bytes.EMPTY);
		
		// M.T.
		/*
		// request.setDestinationContext(proxy); // Doesn't work for OSCORE
		request.setURI(proxyUri.toString());
		request.getOptions().setProxyUri("coap://localhost:" + SERVER_COAP_PORT + "/coap-target"); // M.T.
		System.out.println("Proxy-URI: " + request.getOptions().getProxyUri());
		*/
		
		// Using proxy-scheme instead (which works just the same)
		request.setDestinationContext(proxy); // Doesn't work for OSCORE
		request.setURI("coap://localhost:" + SERVER_COAP_PORT + "/coap-target");
		System.out.println("Request proxied to: " + request.getURI());
		
		request(client, request);

		
		// CoAP proxy request - use Proxy-URI, and destination to proxy
		// (Same as above without OSCORE)
		System.out.println("Request B");
		request = Request.newGet();
		request.setURI(proxyUri.toString());
		request.getOptions().setProxyUri("coap://localhost:" + SERVER_COAP_PORT + "/coap-target"); // M.T.
		System.out.println("Proxy-URI: " + request.getOptions().getProxyUri());
		request(client, request);

		// CoAP proxy request - use Proxy-Scheme
		// Uri-Host is a unicast address
		System.out.println("Request C");
		request = Request.newGet();
		request.setDestinationContext(proxy);
		request.setURI("coap://localhost:" + SERVER_COAP_PORT + "/coap-target"); // M.T.
		request.setProxyScheme("coap");
		System.out.println("Proxy-Scheme: " + request.getOptions().getProxyScheme());
		System.out.println("Uri: " + request.getURI());
		request(client, request);

		// CoAP proxy request - use Proxy-URI, and destination to proxy
		// Proxy-Uri is a multicast address
		System.out.println("Request D");
		request = Request.newGet();
		request.setURI(proxyUri.toString());
		request.getOptions().setProxyUri("coap://224.0.1.187:" + SERVER_COAP_PORT + "/coap-target"); // M.T.
		System.out.println("Proxy-URI: " + request.getOptions().getProxyUri());
		request(client, request);

		// CoAP proxy request - use Proxy-Scheme
		// Uri-Host is a multicast address
		System.out.println("Request E");
		request = Request.newGet();
		request.setDestinationContext(proxy);
		request.setURI("coap://224.0.1.187:" + SERVER_COAP_PORT + "/coap-target"); // M.T.
		request.setProxyScheme("coap");
		System.out.println("Proxy-Scheme: " + request.getOptions().getProxyScheme());
		System.out.println("Uri: " + request.getURI());
		request(client, request);
		
		client.shutdown();
	}
}

