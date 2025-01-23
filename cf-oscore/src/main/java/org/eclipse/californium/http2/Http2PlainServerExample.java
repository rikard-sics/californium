package org.eclipse.californium.http2;

import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

public class Http2PlainServerExample {

	public static void main(String[] args) throws Exception {

		Server server = new Server();

		HttpConfiguration httpConfig = new HttpConfiguration();

		// For HTTP/1.1 cleartext:
		HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfig);

		// For HTTP/2 cleartext (h2c):
		HTTP2CServerConnectionFactory h2c = new HTTP2CServerConnectionFactory(httpConfig);

		// Create a cleartext ServerConnector on port 8080.
		ServerConnector connector = new ServerConnector(server, http11, h2c);
		connector.setPort(8080);

		// Add the connector to the server.
		server.addConnector(connector);

		// Jetty setup of handlers, servlets, etc.
		ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath("/");
		server.setHandler(context);

		context.addServlet(new ServletHolder(new ResourceServlet()), "/helloworld.Greeter/SayHello");

		server.start();
	}
}
