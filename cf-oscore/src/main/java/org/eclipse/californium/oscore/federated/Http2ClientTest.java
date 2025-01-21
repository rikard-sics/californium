package org.eclipse.californium.oscore.federated;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.CompletableFuture;

import org.eclipse.jetty.http2.api.Session;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.transport.HttpClientTransportOverHTTP2;
import org.eclipse.jetty.io.ClientConnector;

public class Http2ClientTest {

	public static void main(String[] args) throws Exception {
		// The HTTP2Client powers the HTTP/2 transport.
		HTTP2Client http2Client = new HTTP2Client();
		http2Client.setInitialSessionRecvWindow(64 * 1024 * 1024);

		// Create and configure the HTTP/2 transport.
		HttpClientTransportOverHTTP2 transport = new HttpClientTransportOverHTTP2(http2Client);
		transport.setUseALPN(true);

		http2Client.start();

		ClientConnector connector = http2Client.getClientConnector();

		// Address of the server's encrypted port.
		SocketAddress serverAddress = new InetSocketAddress("localhost", 8443);

		// Connect to the server, the CompletableFuture will be
		// notified when the connection is succeeded (or failed).
		CompletableFuture<Session> sessionCF = http2Client.connect(connector.getSslContextFactory(), serverAddress, new Session.Listener() {});

		// Block to obtain the Session.
		// Alternatively you can use the CompletableFuture APIs to avoid blocking.
		Session session = sessionCF.get();
			
	}

}
