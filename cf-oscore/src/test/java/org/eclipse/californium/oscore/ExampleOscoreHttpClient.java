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

// USE WITH ExampleCrossProxy2 !!!!!!!!!!!!!!
// and HelloWorldServer (OSCORE)

// TAKEN FROM org.eclipse.californium.examples.ExampleProxy2HttpClient

package org.eclipse.californium.oscore;

import java.io.IOException;
import java.net.URI;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.StatusLine;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.proxy2.TranslationException;
import org.eclipse.californium.proxy2.http.Coap2HttpTranslator;
import org.eclipse.californium.proxy2.http.CrossProtocolTranslator;
import org.eclipse.californium.proxy2.http.MappingProperties;
import org.eclipse.californium.proxy2.http.ProxyRequestProducer;
import org.eclipse.californium.proxy2.http.server.ProxyHttpServer;

/**
 * Class ExampleProxyHttpClient.<br/>
 * 
 * Example proxy Http client which sends a request via {@link ProxyHttpServer}
 * to a coap-server.<br/>
 * 
 * Http2Coap Uri:<br/>
 * <a href=
 * "http://localhost:8080/proxy/coap://localhost:5685/coap-target">http://localhost:8080/proxy/coap://localhost:5685/coap-target</a>.
 */
public class ExampleOscoreHttpClient {

	// Client OSCORE context information
	// TODO: Reorder as in hello world client
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = StringUtil.hex2ByteArray("0102030405060708090A0B0C0D0E0F10");
	private final static byte[] master_salt = StringUtil.hex2ByteArray("9e7ca92223786340");
	private final static byte[] sid = Bytes.EMPTY;
	private final static byte[] rid = StringUtil.hex2ByteArray("01");
	private final static int MAX_UNFRAGMENTED_SIZE = Configuration.getStandard().get(CoapConfig.MAX_RESOURCE_BODY_SIZE);
	private final static String serverResourceUri = "coap://localhost:5685/hello/1";

	static private final String OSCORE_HTTP_HEADER = "oscore";
	private static Coap2HttpTranslator translator;

	public static void init() {
		MappingProperties defaultMappings = new MappingProperties();
		CrossProtocolTranslator crossTranslator = new CrossProtocolTranslator(defaultMappings);
		translator = new Coap2HttpTranslator(crossTranslator, new CrossProtocolTranslator.HttpServerEtagTranslator());
	}


	private static void request(HttpClient client, String uriXXX, boolean useOscore)
			throws OSException, TranslationException {
		try {
			System.out.println("=== " + uriXXX + " ===");
			HttpGet request = new HttpGet(uriXXX);

			if (useOscore) {
				// Create CoAP request first
				Request coapRequest = Request.newGet();
				coapRequest.setProxyUri(serverResourceUri);

				// Protect it with OSCORE
				Request oscoreRequest = RequestEncryptor.encrypt(db, coapRequest);

				// Now translate it to HTTP
				URI uri = translator.getDestinationURI(oscoreRequest, null);
				ProxyRequestProducer translatedRequest = translator.getHttpRequest(uri, oscoreRequest);
				HttpRequest httpRequest = translatedRequest.getHttpRequest();
				HttpResponse response = client.execute(request);
				System.out.println(new StatusLine(response));
				Header[] headers = response.getHeaders();
				for (Header header : headers) {
					System.out.println(header.getName() + ": " + header.getValue());
				}
				if (response instanceof ClassicHttpResponse) {
					HttpEntity entity = ((ClassicHttpResponse) response).getEntity();
					System.out.println(EntityUtils.toString(entity));
				}
				return;

			}

			HttpResponse response = client.execute(request);
			System.out.println(new StatusLine(response));
			Header[] headers = response.getHeaders();
			for (Header header : headers) {
				System.out.println(header.getName() + ": " + header.getValue());
			}
			if (response instanceof ClassicHttpResponse) {
				HttpEntity entity = ((ClassicHttpResponse) response).getEntity();
				System.out.println(EntityUtils.toString(entity));
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws OSException, TranslationException {
		HttpClient client = HttpClientBuilder.create().build();

		init();

		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null,
				MAX_UNFRAGMENTED_SIZE);
		db.addContext(serverResourceUri, ctx);
		OSCoreCoapStackFactory.useAsDefault(db);

		// // simple request to proxy as httpp-server (no proxy function)
		// request(client, "http://localhost:8080");
		//
		// request(client,
		// "http://localhost:8080/proxy/coap://localhost:5685/coap-target");
		// // keep the "coap://" after normalize the URI requires to use %2f%2f
		// // instead of //
		// request(client,
		// "http://localhost:8080/proxy/coap:%2f%2flocalhost:5685/coap-target");

		// HTTP request via proxy, without OSCORE
		request(client, "http://localhost:8080/proxy?target_uri=" + serverResourceUri, false);

		// HTTP request via proxy, with OSCORE
		request(client, "http://localhost:8080/proxy?target_uri=" + serverResourceUri, true);

		// // not really intended, http2http
		// request(client,
		// "http://localhost:8080/proxy/http:%2f%2flocalhost:8000/http-target");
		//
		// // request to local (in same process) coap-server
		// request(client, "http://localhost:8080/local/target");
		//
		// // http-request via proxy
		// HttpHost proxy = new HttpHost("http", "localhost", 8080);
		// client = HttpClientBuilder.create().setProxy(proxy).build();
		// request(client, "http://localhost:5685/coap-target/coap:");
		//
		// request(client,
		// "http://californium.eclipseprojects.io:5683/test/coap:");

	}
}
