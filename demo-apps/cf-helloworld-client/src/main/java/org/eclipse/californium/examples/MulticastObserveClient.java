package org.eclipse.californium.examples;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.option.OptionRegistry;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.observe.ObservationInfo;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MulticastObserveClient {

	static {
		CoapConfig.register();
		UdpConfig.register();
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(MulticastObserveClient.class);

	private static UDPConnector udpConnector;
	private static UdpMulticastConnector multicastReceiver;
	private static CoapEndpoint endpoint;
	private static CoapClient multicastClient;
	private static boolean receiverReady = false;

	private static class MulticastObserveHandler implements CoapHandler {

		private int notificationCount = 0;
		private final int targetCount;

		public MulticastObserveHandler(int targetCount) {
			this.targetCount = targetCount;
		}

		public synchronized void waitForNotifications() {
			while (notificationCount < targetCount) {
				try {
					this.wait();
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					return;
				}
			}
		}

		@Override
		public void onLoad(CoapResponse response) {
			LOGGER.info("onLoad(): \n {}", Utils.prettyPrint(response));

			if (response.getOptions().isContentFormat(MediaTypeRegistry.APPLICATION_INFORMATIVE_RESPONSE_CBOR)) {
				LOGGER.info("Got APPLICATION_INFORMATIVE_RESPONSE_CBOR (ObservationInfo)");
				ObservationInfo info = ObservationInfo.fromCbor(response.getPayload());

				InetSocketAddress groupSock = info.getTpInfo().getTpiClient().toSocketAddress();
				InetAddress groupAddr = groupSock.getAddress();
				int groupPort = groupSock.getPort();
				Token multicastToken = info.getToken();

				byte[] phantomRequestBytes = info.getPhReq();
				if (phantomRequestBytes != null && phantomRequestBytes.length > 0) {
					int reqCode = phantomRequestBytes[0] & 0xFF;
					byte[] reqOptionsAndPayload = new byte[phantomRequestBytes.length - 1];
					System.arraycopy(phantomRequestBytes, 1, reqOptionsAndPayload, 0, reqOptionsAndPayload.length);
					Request mess = new Request(org.eclipse.californium.core.coap.CoAP.Code.valueOf(reqCode));
					DataParser reqParser = new UdpDataParser(true, (OptionRegistry) null);
					reqParser.parseOptionsAndPayload(
							new DatagramReader(reqOptionsAndPayload),
							mess);
					LOGGER.info("Phantom request parsed successfully: {}", mess);
				}

				LOGGER.info("Requested URI: {}", info.getTpInfo().getTpiServer().toString());
				LOGGER.info("Multicast group: {} : {}", groupAddr, groupPort);
				LOGGER.info("Token: {}", multicastToken.getAsString());

				byte[] lastNotifBytes = info.getLastNotifBytes();
				if (lastNotifBytes != null && lastNotifBytes.length > 0) {
					int notifCode = lastNotifBytes[0] & 0xFF;
					byte[] notifOptionsAndPayload = new byte[lastNotifBytes.length - 1];
					System.arraycopy(lastNotifBytes, 1, notifOptionsAndPayload, 0, notifOptionsAndPayload.length);
					Response lastNotif = new Response(ResponseCode.valueOf(notifCode));
					lastNotif.setToken(multicastToken);
					DataParser notifParser = new UdpDataParser(true, (OptionRegistry) null);
					notifParser.parseOptionsAndPayload(
							new DatagramReader(notifOptionsAndPayload),
							lastNotif);
					LOGGER.info("last_notif - code: {}, payload: {}", lastNotif.getCode(), lastNotif.getPayloadString());
					LOGGER.info("last_notif: \n {}", Utils.prettyPrint(lastNotif));
				} else {
					LOGGER.info("No last_notif in informative response");
				}

				if (!receiverReady) {
					try {
						LOGGER.info("Setting up multicast receiver...");
						setupMulticastReceiverOnce(groupAddr, groupPort, Configuration.createStandardWithoutFile(), multicastToken,
								info.getTpInfo().getTpiServer().toSocketAddress());
						LOGGER.info("Multicast receiver activated.");

						Request phantomRequest = createPhantomRequest(multicastToken, info.getTpInfo().getTpiServer().toString(), groupAddr, groupPort);
						LOGGER.info("Created PhantomRequest with token: {}", multicastToken);

						multicastClient.observe(phantomRequest, this);
						LOGGER.info("Registered phantom observe relation.");

						receiverReady = true;
					} catch (IOException e) {
						LOGGER.error("Failed to activate multicast receiver", e);
					}
				} else {
					LOGGER.info("Multicast receiver already active");
				}

				return;
			}

			if (response.getCode() == ResponseCode.SERVICE_UNAVAILABLE
					&& !response.getOptions().hasObserve()
					&& (response.getPayload() == null || response.getPayload().length == 0)) {
				LOGGER.info("Received group observation cancellation (5.03, no payload, no Observe)");
				if (multicastClient != null) {
					multicastClient.shutdown();
				}
				receiverReady = false;
				synchronized (this) {
					notificationCount = targetCount;
					notifyAll();
				}
				return;
			}

			synchronized (this) {
				notificationCount++;
				notifyAll();
			}
		}

		@Override
		public void onError() {
			LOGGER.error("Error receiving multicast notification");
		}
	}

	private static Request createRequest(Code code, String resourceUri) {
		System.out.println("Connecting to: " + resourceUri);

		Request r = new Request(code);
		r.setConfirmable(true);
		r.setURI(resourceUri);
		r.setObserve();

		InetAddress destAddr = r.getDestinationContext() != null
				? r.getDestinationContext().getPeerAddress().getAddress() : null;
		if (destAddr != null && destAddr.isLinkLocalAddress()) {
			throw new IllegalArgumentException(
					"Observation request destination " + destAddr.getHostAddress()
					+ " is link-local (RFC Section 5.1)");
		}

		return r;
	}

	private static Request createPhantomRequest(Token multicastToken, String requestedURI, InetAddress groupAddr, int groupPort) {
		Request phantomRequest = Request.newGet();
		phantomRequest.setToken(multicastToken);
		phantomRequest.setObserve();
		phantomRequest.setDestinationContext(new AddressEndpointContext(new InetSocketAddress(groupAddr, groupPort)));
		phantomRequest.setURI(requestedURI);
		phantomRequest.setType(Type.NON);
		phantomRequest.setClientInjection(true);

		LOGGER.debug("Created phantom request: {}", phantomRequest);
		return phantomRequest;
	}

	public static void setupMulticastReceiverOnce(InetAddress groupAddr, int port, Configuration config, Token multicastToken,
			InetSocketAddress srvAddr) throws IOException {
		// Join the group on the interface that reaches the server rather than on a
		// globally selected one: the multicast traffic of a server which is reached
		// over loopback leaves through the loopback interface, so a receiver joined
		// on a physical interface never sees it. If srvAddr is not an address of
		// this host, the previous global selection is used unchanged.
		NetworkInterface ni = NetworkInterfacesUtil.getNetworkInterface(srvAddr.getAddress());
		Inet4Address ipv4 = null;
		if (ni != null && srvAddr.getAddress() instanceof Inet4Address) {
			ipv4 = (Inet4Address) srvAddr.getAddress();
		}
		if (ni == null) {
			ni = NetworkInterfacesUtil.getMulticastInterface();
			ipv4 = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
		}
		if (ni == null) {
			throw new IOException("No multicast network interface found");
		}

		if (ipv4 == null && ni != null) {
			java.util.Enumeration<InetAddress> addrs = ni.getInetAddresses();
			while (addrs.hasMoreElements()) {
				InetAddress a = addrs.nextElement();
				if (a instanceof Inet4Address) {
					ipv4 = (Inet4Address) a;
					break;
				}
			}
		}
		if (ipv4 == null) {
			throw new IOException("No IPv4 address found on multicast interface " + (ni != null ? ni.getDisplayName() : "null"));
		}

		InetSocketAddress bind = new InetSocketAddress(ipv4, 0);
		udpConnector = new UDPConnector(bind, config);
		udpConnector.setReuseAddress(true);
		LOGGER.info("Binding UDPConnector to {} (ephemeral port) on {}", ipv4, ni.getDisplayName());

		UdpMulticastConnector.Builder mcBuilder = new UdpMulticastConnector.Builder()
				.setConfiguration(config)
				.setMulticastReceiver(true)
				.setLocalAddress(groupAddr, port)
				.addMulticastGroup(groupAddr, ni);

		multicastReceiver = mcBuilder.build();

		try {
			multicastReceiver.start();
			multicastReceiver.setLoopbackMode(true);
			LOGGER.info("Multicast receiver started on {} port {}", groupAddr, port);
		} catch (java.net.BindException ex) {
			LOGGER.warn("Bind to multicast address failed, retrying with port only: {}", ex.getMessage());
			mcBuilder = new UdpMulticastConnector.Builder()
					.setConfiguration(config)
					.setMulticastReceiver(true)
					.setLocalPort(port)
					.addMulticastGroup(groupAddr, ni);
			multicastReceiver = mcBuilder.build();
			multicastReceiver.setLoopbackMode(true);
			multicastReceiver.start();
		}

		udpConnector.addMulticastReceiver(multicastReceiver);

		endpoint = new CoapEndpoint.Builder()
				.setConfiguration(config)
				.setConnector(udpConnector)
				.setEndpointContextMatcher(new GroupObservationContextMatcher(srvAddr))
				.build();

		endpoint.start();

		multicastClient = new CoapClient();
		multicastClient.setEndpoint(endpoint);

		LOGGER.info("Joined group {} on interface {} port {}", groupAddr, ni.getDisplayName(), port);
	}

	public static void main(String requestURI) {
		try {
			Configuration config = Configuration.getStandard();
			Configuration.setStandard(config);

			LOGGER.debug("Requesting {}", requestURI);

			CoapEndpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
			CoapClient client = new CoapClient();
			client.setEndpoint(endpoint);
			client.setURI(requestURI);

			Request multicastRequest = createRequest(Code.GET, requestURI);

			MulticastObserveHandler handler = new MulticastObserveHandler(100);
			client.observe(multicastRequest, handler);

			handler.waitForNotifications();

			if (multicastClient != null) multicastClient.shutdown();
		} catch (Exception e) {
			LOGGER.error("Error in multicast observe client", e);
		}
	}
}
