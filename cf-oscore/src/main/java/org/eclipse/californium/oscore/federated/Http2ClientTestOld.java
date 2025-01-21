package org.eclipse.californium.oscore.federated;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.CompletableFuture;

import org.eclipse.jetty.http.HttpFields;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http.MetaData;
import org.eclipse.jetty.http2.api.Session;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.transport.HttpClientTransportOverHTTP2;
import org.eclipse.jetty.http2.frames.HeadersFrame;
import org.eclipse.jetty.io.ClientConnector;

public class Http2ClientTestOld {

	public static void main(String[] args) throws Exception {

		mainTwo();
	}

	public static void mainTwo() throws Exception {
		System.out.println(System.getProperty("javax.net.ssl.trustStore"));
		System.out.println(System.getProperty("javax.net.ssl.trustStorePassword"));

		// The HTTP2Client powers the HTTP/2 transport.
		HTTP2Client http2Client = new HTTP2Client();
		http2Client.setInitialSessionRecvWindow(64 * 1024 * 1024);

		// Create and configure the HTTP/2 transport.
		HttpClientTransportOverHTTP2 transport = new HttpClientTransportOverHTTP2(http2Client);
		transport.setUseALPN(true);

		http2Client.start();

		ClientConnector connector = http2Client.getClientConnector();

		// Address of the server's encrypted port.
		SocketAddress serverAddress = new InetSocketAddress("myhost", 8443);

		connector.getSslContextFactory().setTrustAll(true);

		// Connect to the server, the CompletableFuture will be
		// notified when the connection is succeeded (or failed).
		CompletableFuture<Session> sessionCF = http2Client.connect(connector.getSslContextFactory(), serverAddress,
				new Session.Listener() {
				});

		// Block to obtain the Session.
		// Alternatively you can use the CompletableFuture APIs to avoid blocking.
		Session session = sessionCF.get();

		// Send request

		// Configure the request headers.
		HttpFields requestHeaders = HttpFields.build().put(HttpHeader.USER_AGENT, "Jetty HTTP2Client 12.0.16-SNAPSHOT");

		// The request metadata with method, URI and headers.
		MetaData.Request request = new MetaData.Request("GET", HttpURI.from("http://localhost:8080/path"),
				HttpVersion.HTTP_2, requestHeaders);

		// The HTTP/2 HEADERS frame, with endStream=true
		// to signal that this request has no content.
		HeadersFrame headersFrame = new HeadersFrame(request, null, true);

		// Open a Stream by sending the HEADERS frame.
		session.newStream(headersFrame, null);
	}

}
