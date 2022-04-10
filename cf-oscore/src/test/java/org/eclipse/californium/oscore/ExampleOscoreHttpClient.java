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
import java.net.URISyntaxException;

import org.apache.hc.client5.http.async.methods.SimpleBody;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpEntityContainer;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.StatusLine;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.proxy2.TranslationException;
import org.eclipse.californium.proxy2.http.Coap2HttpTranslator;
import org.eclipse.californium.proxy2.http.ContentTypedEntity;
import org.eclipse.californium.proxy2.http.CrossProtocolTranslator;
import org.eclipse.californium.proxy2.http.MappingProperties;
import org.eclipse.californium.proxy2.http.ProxyRequestProducer;
import org.eclipse.californium.proxy2.http.server.ProxyHttpServer;

/**
 * USE HttpPost or ClassicHttpRequest???
 * 
 * 
 * 
 * // USE WITH ExampleCrossProxy2 !!!!!!!!!!!!!! // and HelloWorldServer
 * (OSCORE)
 * 
 * // TAKEN FROM org.eclipse.californium.examples.ExampleProxy2HttpClient
 * 
 * 
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
	// TODO: Use StringUtil
	private final static HashMapCtxDB db = new HashMapCtxDB();
	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] rid = new byte[] { 0x01 };
	private final static byte[] sid = new byte[0];
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;
	private final static String serverResourceUri = "coap://localhost:5685/hello/1";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	static private final String OSCORE_HTTP_HEADER = "oscore";
	private static Coap2HttpTranslator translator;
	static CrossProtocolTranslator crossTranslator;

	public static void init() {
		MappingProperties defaultMappings = new MappingProperties();
		crossTranslator = new CrossProtocolTranslator(defaultMappings);
		translator = new Coap2HttpTranslator(crossTranslator, new CrossProtocolTranslator.HttpServerEtagTranslator());
	}

	private static HttpPost convert(HttpRequest httpRequest, ContentTypedEntity httpBodyData)
			throws URISyntaxException {
		HttpPost classicRequest = new HttpPost("");

		System.out.println("httpRequest.getUri() " + httpRequest.getUri());
		classicRequest.setUri(httpRequest.getUri());
		classicRequest.setScheme(httpRequest.getScheme());

		Header[] headers = httpRequest.getHeaders();
		for (int i = 0; i < headers.length; i++) {
			classicRequest.setHeader(headers[i]);
		}
		
		HttpEntity entityBody = new ByteArrayEntity(httpBodyData.getContent(), httpBodyData.getContentType());
		// RequestEntity entityData = new RequestEntity();
		// org.apache.hc.client5.http.impl.classic.
		// HttpEntityContainer bodyData = new HttpEntityContainer("");
		// classicRequest.set
		;

		classicRequest.setEntity(entityBody);

		// httpRequest.g
		
		// HttpEntity entity;
		// SimpleBody body = httpRequest.getBody();
		// if(body != null){
		// if (body.isBytes()){
		// entity = new ByteArrayEntity(body.getBodyBytes(),
		// body.getContentType());
		// } else{
		// entity = new StringEntity(body.getBodyText(),
		// body.getContentType());
		// }
		// classicRequest.setEntity(entity);

		return classicRequest;
	}

	private static void request(HttpClient client, String uriXXX, boolean useOscore)
			throws OSException, TranslationException, URISyntaxException {
		try {
			System.out.println("=== " + uriXXX + " ===");
			HttpGet requestW = new HttpGet(uriXXX);

			if (useOscore) {
				// Create CoAP request first
				Request coapRequest = Request.newGet();
				coapRequest.setProxyUri(serverResourceUri);

				// Protect it with OSCORE
				Request oscoreRequest = RequestEncryptor.encrypt(db, coapRequest);

				System.out.println("OSCORE protected request: " + Utils.prettyPrint(oscoreRequest));

				// Now translate it to HTTP
				URI uri = translator.getDestinationURI(oscoreRequest, null);
				ProxyRequestProducer translatedRequest = translator.getHttpRequest(uri, oscoreRequest);


				ContentTypedEntity httpBodyData = crossTranslator.getHttpEntity(oscoreRequest);
				System.out.println("HTTP Data: " + Utils.toHexString(httpBodyData.getContent()));
				// TestRequestChannel channel = new TestRequestChannel();
				// translatedRequest.sendRequest(channel, null);

				HttpRequest httpRequest = translatedRequest.getHttpRequest();

				// Set the URI
				URI theUri = URI.create("http://localhost:8080/proxy?target_uri=" + serverResourceUri);
				httpRequest.setUri(theUri);

				// And send it
				// System.out.println("HTTP request before conversion: " +
				// httpRequest.);
				HttpPost classicRequest = convert(httpRequest, httpBodyData);
				HttpResponse response = client.execute(classicRequest);
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

			HttpResponse response = client.execute(requestW);
			System.out.println(new StatusLine(response));
			Header[] headers = response.getHeaders();
			for (Header header : headers) {
				System.out.println(header.getName() + ": " + header.getValue());
			}
			if (response instanceof ClassicHttpResponse) {
				HttpEntity entity = ((ClassicHttpResponse) response).getEntity();
				System.out.println("Entity true class: " + (((ClassicHttpResponse) response).getEntity()).getClass());
				System.out.println(EntityUtils.toString(entity));
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws OSException, TranslationException, URISyntaxException {
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
		// request(client, "http://localhost:8080/proxy?target_uri=" +
		// serverResourceUri, false);

		// HTTP request via proxy, with OSCORE
		ctx.setSenderSeq(1);
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
