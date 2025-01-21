package org.eclipse.californium.oscore.federated;

import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;

public class Http2ServerTest {

	public static void main(String[] args) throws Exception {

		Server server = new Server();

		// The HTTP configuration object.
		HttpConfiguration httpConfig = new HttpConfiguration();
		// Add the SecureRequestCustomizer because TLS is used.
		httpConfig.addCustomizer(new SecureRequestCustomizer());

		// The ConnectionFactory for HTTP/1.1.
		HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfig);

		// The ConnectionFactory for HTTP/2.
		HTTP2ServerConnectionFactory h2 = new HTTP2ServerConnectionFactory(httpConfig);

		// The ALPN ConnectionFactory.
		ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory();
		// The default protocol to use in case there is no negotiation.
		alpn.setDefaultProtocol(http11.getProtocol());

		// Configure the SslContextFactory with the keyStore information.
		SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
		sslContextFactory.setKeyStorePath("keystore.jks");
		sslContextFactory.setKeyStorePassword("secret");

		// The ConnectionFactory for TLS.
		SslConnectionFactory tls = new SslConnectionFactory(sslContextFactory, alpn.getProtocol());

		// The ServerConnector instance.
		ServerConnector connector = new ServerConnector(server, tls, alpn, h2, http11);
		connector.setPort(8443);

		server.addConnector(connector);
		server.start();
	}
}
