package org.eclipse.californium.oscore.federated;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class FedResourceServlet extends HttpServlet {

	private static final long serialVersionUID = 17439274932L;
	GrpcServer theServer;

	public FedResourceServlet(GrpcServer grpcServer) {
		theServer = grpcServer;
	}

	protected void doGetTest(HttpServletRequest request, HttpServletResponse response) throws IOException {
		// response.setContentType("text/html;charset=utf-8");
		response.setStatus(HttpServletResponse.SC_OK);
		response.getWriter().println("<h1>Hello Rikard1 HTTP/2 World</h1>");
	}

	protected void doPostTest(HttpServletRequest request, HttpServletResponse response) throws IOException {
		// response.setContentType("text/html;charset=utf-8");
		response.setStatus(HttpServletResponse.SC_OK);
		response.getWriter().println("<h1>Hello Rikard2 HTTP/2 World</h1>");
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		byte[] responsePayload;
		byte[] requestPayload;

		InputStream is = request.getInputStream();
		requestPayload = is.readAllBytes();
		theServer.handleIncoming(requestPayload);
		// buildResponse(response);
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
		byte[] responsePayload;
		byte[] requestPayload;

		InputStream is = request.getInputStream();
		requestPayload = is.readAllBytes();
		responsePayload = theServer.handleIncoming(requestPayload);
		buildResponse(response, responsePayload);
	}

	/**
	 * @param response
	 * @throws IOException
	 */
	private void buildResponse(HttpServletResponse response, byte[] responsePayload) throws IOException {
		// Set header values

		response.setContentType("application/grpc");
		response.setStatus(HttpServletResponse.SC_OK);
		response.setHeader("grpc-encoding", "identity");
		// response.setHeader("content-type", "application/grpc");

		Supplier<Map<String, String>> trailerSupplier = new Supplier<Map<String, String>>() {

			@Override
			public Map<String, String> get() {
				Map<String, String> trailerHeaders = new HashMap<String, String>();
				trailerHeaders.put("grpc-status", "0");
				return trailerHeaders;
			}
		};
		response.setTrailerFields(trailerSupplier);

		response.setHeader("grpc-accept-encoding", "gzip");

		// Set response payload

		char[] actualPayload;
		actualPayload = new char[responsePayload.length];
		for (int i = 0; i < responsePayload.length; i++) {
			actualPayload[i] = (char) (responsePayload[i] & 0xFF);
		}

		response.getOutputStream().write(responsePayload);
		// response.getWriter().print(actualPayload);

		// response.getWriter()
		// .print(new char[] { (char) 0x00, (char) 0x00, (char) 0x00, (char)
		// 0x00,
		// (char) 0x0d, (char) 0x0a, (char) 0x0b, (char) 0x48, (char) 0x65,
		// (char) 0x6c, (char) 0x6c,
		// (char) 0x6f, (char) 0x20, (char) 0x77, (char) 0x6f, (char) 0x72,
		// (char) 0x6c, (char) 0x64 });
	}

}