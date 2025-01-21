package org.eclipse.californium.oscore.federated;

import org.eclipse.jetty.client.ContentResponse;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.transport.HttpClientConnectionFactory;
import org.eclipse.jetty.client.transport.HttpClientTransportDynamic;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.transport.ClientConnectionFactoryOverHTTP2;
import org.eclipse.jetty.io.ClientConnectionFactory;
import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory.Client.SniProvider;

public class Http2ClientNew {

	public static void main(String[] args) throws Exception

	{
		SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();

		ClientConnector connector = new ClientConnector();
		connector.setSslContextFactory(sslContextFactory);

		connector.getSslContextFactory().setTrustAll(true);
		connector.getSslContextFactory().setSNIProvider(SniProvider.NON_DOMAIN_SNI_PROVIDER);

		ClientConnectionFactory.Info http1 = HttpClientConnectionFactory.HTTP11;

		HTTP2Client http2Client = new HTTP2Client(connector);
		ClientConnectionFactoryOverHTTP2.HTTP2 http2 = new ClientConnectionFactoryOverHTTP2.HTTP2(http2Client);


		// The order of the protocols indicates the client's preference.
		// The first is the most preferred, the last is the least preferred, but
		// the protocol version to use can be explicitly specified in the
		// request.
		HttpClientTransportDynamic transport = new HttpClientTransportDynamic(connector, http2, http1);

		HttpClient client = new HttpClient(transport);
		client.start();

		ContentResponse http2Response = client.newRequest("https://myhost:8443/model")
				// Specify the version explicitly.
				.version(HttpVersion.HTTP_2).send();

		System.out.println("Response content: " + http2Response.getContentAsString());
	}

}
