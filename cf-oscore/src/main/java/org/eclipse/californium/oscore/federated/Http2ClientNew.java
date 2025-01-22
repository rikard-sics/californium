package org.eclipse.californium.oscore.federated;

import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.http.HttpClientTransportOverHTTP2;
import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory.Client.SniProvider;

public class Http2ClientNew {

	public static void main(String[] args) throws Exception {

		ClientConnector connector = new ClientConnector();

		SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
		sslContextFactory.setTrustAll(true);
		sslContextFactory.setSNIProvider(SniProvider.NON_DOMAIN_SNI_PROVIDER);
		connector.setSslContextFactory(sslContextFactory);

		// Low-level HTTP/2 engine
		HTTP2Client http2Client = new HTTP2Client(connector);

		// Transport that speaks HTTP/2
		HttpClientTransportOverHTTP2 transport = new HttpClientTransportOverHTTP2(http2Client);

		// Create and start the Jetty HttpClient
		HttpClient httpClient = new HttpClient(transport);

		httpClient.start();
		try {
			// Perform a GET request over HTTP/2
			ContentResponse response = httpClient.GET("https://localhost:8443/model");
			System.out.println("Status: " + response.getStatus());
			System.out.println("Response: " + response.getContentAsString());
		} finally {
			// Clean up
			httpClient.stop();
		}
	}
}
