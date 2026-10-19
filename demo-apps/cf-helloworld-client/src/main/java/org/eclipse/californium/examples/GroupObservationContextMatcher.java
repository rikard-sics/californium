package org.eclipse.californium.examples;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.UdpEndpointContextMatcher;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Endpoint context matcher for the endpoint used by a group observation.
 * <p>
 * The client configures an observation of the target resource, relying on a
 * CoAP endpoint used for messages having as source address and port number
 * SRV_ADDR and SRV_PORT, as conveyed by 'tpi_server' in the informative
 * response (draft-ietf-core-observe-multicast-notifications-15, Section 5.2,
 * step 1). Multicast notifications from any other source are not related to
 * the phantom request and are dropped before any further processing.
 */
public class GroupObservationContextMatcher extends UdpEndpointContextMatcher {

	private static final Logger LOGGER = LoggerFactory.getLogger(GroupObservationContextMatcher.class);

	/**
	 * SRV_ADDR and SRV_PORT from 'tpi_server'.
	 */
	private final InetSocketAddress server;

	public GroupObservationContextMatcher(InetSocketAddress server) {
		this.server = server;
	}

	@Override
	public boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext) {
		InetSocketAddress destination = requestContext.getPeerAddress();
		InetSocketAddress source = responseContext.getPeerAddress();
		if (NetworkInterfacesUtil.isMultiAddress(destination.getAddress()) && !server.equals(source)) {
			LOGGER.warn("dropping notification for group {} from {}, expected tpi_server {}",
					StringUtil.toLog(destination), StringUtil.toLog(source), StringUtil.toLog(server));
			return false;
		}
		return super.isResponseRelatedToRequest(requestContext, responseContext);
	}
}
