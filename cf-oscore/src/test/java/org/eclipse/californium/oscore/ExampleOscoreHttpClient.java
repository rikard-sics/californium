package org.eclipse.californium.oscore;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Random;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.StatusLine;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
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

/**
 * Notes/TODO: Use HttpPost or ClassicHttpRequest as objects? Use with
 * ExampleCrossProxy2 and HelloWorldServer (OSCORE) (on port 5685)
 * 
 * This code was taken from
 * org.eclipse.californium.examples.ExampleProxy2HttpClient
 * 
 * TODO: The sending HTTP endpoint uses [RFC8075] to translate the HTTP message
 * into a CoAP message. The CoAP message is then processed with OSCORE as
 * defined in this document. The OSCORE message is then mapped to HTTP as
 * described in Section 11.2 and sent in compliance with the rules in Section
 * 11.1.
 * 
 */
public class ExampleOscoreHttpClient {

	// Client OSCORE context information
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost:5685";
	private final static String hello1 = "/hello/1";
	private final static String serverResourceUri = uriLocal + hello1;
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	private final static byte[] master_secret = StringUtil.hex2ByteArray("0102030405060708090A0B0C0D0E0F10");
	private final static byte[] master_salt = StringUtil.hex2ByteArray("9e7ca92223786340");
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = StringUtil.hex2ByteArray("01");
	private final static int MAX_UNFRAGMENTED_SIZE = Configuration.getStandard().get(CoapConfig.MAX_RESOURCE_BODY_SIZE);

	private static Coap2HttpTranslator translator;
	private static CrossProtocolTranslator crossTranslator;
	private static OSCoreCtx ctx;

	private static Random rand;

	private static void initTranslator() {
		MappingProperties defaultMappings = new MappingProperties();
		
		// FIXME: Move? Improve?
		// Maps CoAP 2.04 to HTTP 200 instead of 204 which is No Content
		defaultMappings.setProperty("coap.response.code." + "2.04", String.valueOf(200));

		crossTranslator = new CrossProtocolTranslator(defaultMappings);

		// FIXME: Move? Improve?
		// Maps CoAP 2.04 to HTTP 200 instead of 204 which is No Content
		defaultMappings.setProperty("coap.response.code." + "2.04", String.valueOf(200));

		translator = new Coap2HttpTranslator(crossTranslator, new CrossProtocolTranslator.HttpServerEtagTranslator());
	}

	/**
	 * Convert between "HttpRequest" and "ClassicHttpRequest" (Not about CoAP to
	 * HTTP translation, just internal HTTP stuff)
	 * 
	 * @param httpRequest the input httpRequest
	 * @param httpEntity the desired payload of the new request
	 * @return a new request of type ClassicHttpRequest
	 * 
	 * @throws URISyntaxException on failure
	 * @throws IOException on failure
	 */
	private static HttpPost convertRequest(HttpRequest httpRequest, ContentTypedEntity httpEntity)
			throws URISyntaxException, IOException {

		// Copy over Uri & Scheme
		HttpPost classicRequest = new HttpPost("");
		classicRequest.setUri(httpRequest.getUri());
		classicRequest.setScheme(httpRequest.getScheme());

		// Copy over Headers
		Header[] headers = httpRequest.getHeaders();
		for (int i = 0; i < headers.length; i++) {
			classicRequest.setHeader(headers[i]);
		}

		// Set the "entity" (payload)
		if (httpEntity != null) {
			try (HttpEntity newEntity = new ByteArrayEntity(httpEntity.getContent(), httpEntity.getContentType());) {
				classicRequest.setEntity(newEntity);
				newEntity.close();
			}
		}

		return classicRequest;
	}

	private static void request(HttpClient client, String httpReqUri, boolean useOscore)
			throws OSException, TranslationException, URISyntaxException {
		try {
			System.out.println("=== " + httpReqUri + " ===");

			// Create CoAP request
			Request coapRequest = Request.newGet();
			coapRequest.setToken(Bytes.createBytes(rand, 4));
			coapRequest.setProxyUri(serverResourceUri);

			// Protect it with OSCORE
			Request oscoreRequest;
			if (useOscore) {
				oscoreRequest = RequestEncryptor.encrypt(db, coapRequest);
				System.out.println("OSCORE protected CoAP request: " + Utils.prettyPrint(oscoreRequest));
			} else {
				oscoreRequest = coapRequest;
			}

			// Now translate it to HTTP
			URI uri = translator.getDestinationURI(oscoreRequest, null);
			ProxyRequestProducer translatedRequest = translator.getHttpRequest(uri, oscoreRequest);
			ContentTypedEntity httpBodyData = crossTranslator.getHttpEntity(oscoreRequest);
			HttpRequest httpRequest = translatedRequest.getHttpRequest();

			// Set the URI (do in CoAP request?)
			URI theUri = URI.create(httpReqUri);
			httpRequest.setUri(theUri);

			// Convert it to "ClassicHttpRequest"
			HttpPost classicRequest = convertRequest(httpRequest, httpBodyData);

			// Send the HTTP request
			HttpResponse response = client.execute(classicRequest);

			// Print HTTP response
			System.out.println(new StatusLine(response));
			Header[] headers = response.getHeaders();
			for (Header header : headers) {
				System.out.println(header.getName() + ": " + header.getValue());
			}

			// if (response instanceof ClassicHttpResponse) {
			// try (HttpEntity entity = ((ClassicHttpResponse)
			// response).getEntity();) {
			//
			// System.out.println(EntityUtils.toString(entity));
			// }
			// }

			// Set up conversion from HTTP response to CoAP
			uri = translator.getDestinationURI(oscoreRequest, null);
			ContentType responseContentType = ContentType.APPLICATION_OCTET_STREAM; // FIXME:
			// String contentTypeHeader =
			// response.getHeader("content-type").getValue();
			// System.out.println("contentTypeHeader " + contentTypeHeader);

			byte[] payload = EntityUtils.toByteArray(((ClassicHttpResponse) response).getEntity());
			ContentTypedEntity responseEntity = new ContentTypedEntity(responseContentType, payload);
			Message<HttpResponse, ContentTypedEntity> msg = new Message<HttpResponse, ContentTypedEntity>(response,
					responseEntity);
			
			// Actually convert from HTTP response to CoAP
			Response coapResponse = translator.getCoapResponse(msg, oscoreRequest);
			System.out.println("CoAP Response: " + Utils.prettyPrint(coapResponse));
			System.out.println("Payload: " + coapResponse.getPayloadString());
			System.out.println("Payload (bytes): " + Utils.toHexString(coapResponse.getPayload()));

			// Unprotect the CoAP response
			if (coapResponse.getOptions().hasOscore()) {
				db.addContext(coapRequest.getToken(), ctx);
				System.out.println(" ctx.getSenderSeq() " + ctx.getSenderSeq());
				coapResponse.setToken(coapRequest.getTokenBytes());
				Response decrypted = ResponseDecryptor.decrypt(db, coapResponse, ctx.getSenderSeq() - 1); // FIXME
				System.out.println("Unprotected CoAP Response: " + Utils.prettyPrint(decrypted));
				System.out.println("Payload: " + decrypted.getPayloadString());
			}

			return;

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args)
			throws OSException, TranslationException, URISyntaxException, IOException {
		ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null,
				MAX_UNFRAGMENTED_SIZE);
		db.addContext(serverResourceUri, ctx);
		OSCoreCoapStackFactory.useAsDefault(db);

		initTranslator();

		rand = new Random();

		try (CloseableHttpClient client = HttpClientBuilder.create().build();) {

			// HTTP request via proxy, not using OSCORE
			System.out.println("\n=== Sending NON OSCORE HTTP Request ===");
			request(client, "http://localhost:8080/proxy?target_uri=" + serverResourceUri, false);

			// Using OSCORE #1
			System.out.println("\n=== Sending OSCORE HTTP Request #1 ===");
			request(client, "http://localhost:8080/proxy?target_uri=" + serverResourceUri, true);

			// Using OSCORE #2
			System.out.println("\n=== Sending OSCORE HTTP Request #2 ==="); 
			request(client, "http://localhost:8080/proxy?target_uri=" + serverResourceUri, true);
		}

		//
		//
		//
		//
		//
		//
		//
		//
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
