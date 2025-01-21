package org.eclipse.californium.oscore.federated;


import java.io.IOException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@SuppressWarnings("serial")
public class HelloServlet extends HttpServlet {

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		response.setStatus(HttpServletResponse.SC_OK);
		response.setContentType("text/html");
		response.setCharacterEncoding("utf-8");
		response.getWriter().println("<h1>Hello from HelloServlet</h1>");
	}
}
