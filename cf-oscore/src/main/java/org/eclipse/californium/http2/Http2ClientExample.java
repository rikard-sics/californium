package org.eclipse.californium.http2;

import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.api.Request.Content;
import org.eclipse.jetty.client.util.BytesContentProvider;
import org.eclipse.jetty.client.util.StringContentProvider;
import org.eclipse.jetty.http.HttpField;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.http.HttpClientTransportOverHTTP2;
import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory.Client.SniProvider;

public class Http2ClientExample {

	static final boolean USE_TLS = false;
	static String scheme;
	static int port;

	public static void main(String[] args) throws Exception {

		if (USE_TLS) {
			scheme = "https";
			port = 8443;
		} else {
			scheme = "http";
			port = 8080;
		}

		ClientConnector connector = new ClientConnector();

		SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
		sslContextFactory.setTrustAll(true);
		sslContextFactory.setSNIProvider(SniProvider.NON_DOMAIN_SNI_PROVIDER);
		if (USE_TLS) {
			connector.setSslContextFactory(sslContextFactory);
		}

		// Low-level HTTP/2 engine
		HTTP2Client http2Client = new HTTP2Client(connector);

		// Transport that speaks HTTP/2
		HttpClientTransportOverHTTP2 transport = new HttpClientTransportOverHTTP2(http2Client);

		// Create and start the Jetty HttpClient
		HttpClient httpClient = new HttpClient(transport);

		httpClient.getContentDecoderFactories().clear(); // No gzip?

		httpClient.start();
		try {
			// Perform a GET request over HTTP/2
			httpClient.setUserAgentField(new HttpField(HttpHeader.USER_AGENT, "grpc-java-netty/1.69.1"));

			Request req = httpClient.POST(scheme + "://localhost:" + port + "/helloworld.Greeter/SayHello");
			req.header("content-type", "application/grpc");
			req.header("grpc-accept-encoding", "gzip");
			req.header("te", "trailers");

			String payload = "{\"message\":\"Hello, World!\"}";
			// StringContentProvider myCont = new
			// StringContentProvider(payload);
			BytesContentProvider myCont = new BytesContentProvider(
					new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07, (byte) 0x0a,
							(byte) 0x05, (byte) 0x77, (byte) 0x6f, (byte) 0x72, (byte) 0x6c, (byte) 0x64 });
			req.content(myCont);

			ContentResponse response = req.send();

			System.out.println("Status: " + response.getStatus());
			System.out.println("Response: " + response.getContentAsString());
		} finally {
			// Clean up
			httpClient.stop();
		}
	}
}
