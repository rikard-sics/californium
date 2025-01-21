package org.eclipse.californium.oscore.federated;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;


public class Http2ServerTest {

	public static void main(String[] args) throws Exception {

		Server server = new Server();

		// The HTTP configuration object.
		HttpConfiguration httpConfig = new HttpConfiguration();
		// Add the SecureRequestCustomizer because TLS is used.
		SecureRequestCustomizer src = new SecureRequestCustomizer();
		src.setSniHostCheck(false);
		httpConfig.addCustomizer(src);

		// The ConnectionFactory for HTTP/1.1.
		HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfig);

		// The ConnectionFactory for HTTP/2.
		HTTP2ServerConnectionFactory h2 = new HTTP2ServerConnectionFactory(httpConfig);

		// The ALPN ConnectionFactory.
		ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory();
		// The default protocol to use in case there is no negotiation.
		alpn.setDefaultProtocol(h2.getProtocol()); // Changed

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

		Handler myHandler = new Handler.Abstract()
		{

			public boolean handleOld(Request request, Response response, Callback callback) throws Exception {
				// TODO Auto-generated method stub
				System.out.println("Request received");
				callback.succeeded();

				ByteBuffer res = ByteBuffer.wrap(new byte[] { 0x61, 0x73, 0x64 });
				response.write(true, res, callback);
				return true;
			}

			@Override
			public boolean handle(Request request, Response response, Callback callback) {
				// Set the response status code.
				response.setStatus(HttpStatus.OK_200);
				// Set the response headers.
				response.getHeaders().put(HttpHeader.CONTENT_TYPE, "text/plain");

				String hello = "HELLO";

				// Commit the response with a "flush" write.
				Callback.Completable.with(flush -> response.write(false, null, flush))
						// When the flush is finished, send the content and
						// complete the callback.
						.whenComplete((ignored, failure) -> {
							if (failure == null)
								response.write(true, null, callback);
							else
								callback.failed(failure);
						});

				// Return true because the callback will eventually be
				// completed.
				return true;
			}

		};

		server.setHandler(myHandler);

		server.start();

	}
}
