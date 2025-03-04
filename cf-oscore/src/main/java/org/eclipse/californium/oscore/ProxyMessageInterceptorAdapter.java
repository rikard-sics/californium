package org.eclipse.californium.oscore;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.interceptors.MessageInterceptorAdapter;

public class ProxyMessageInterceptorAdapter extends MessageInterceptorAdapter {
	@Override
	public void receiveRequest(Request request) {
		System.out.println("Intercepted recieve request in message interceptor");
		System.out.println(request);

		request.setIsForwardProxy();
	}
}