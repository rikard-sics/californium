package org.eclipse.californium.examples;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

import org.eclipse.californium.oscore.MulticastObservableResource;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.observe.GroupObservationsInfo;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Experiment server for Raspberry Pi multicast observe testing.
 * Run on Pi at 192.168.0.55 (or pass bind address as argument).
 *
 * Usage: java ExperimentServer [bindAddress]
 */
public class ExperimentServer extends CoapServer {

	private static final Logger LOGGER = LoggerFactory.getLogger(ExperimentServer.class);

	static {
		CoapConfig.register();
		UdpConfig.register();
	}

	public static void main(String[] args) {
		try {
			String bindAddress = args.length > 0 ? args[0] : null;
			ExperimentServer server = new ExperimentServer();
			server.addEndpoints(bindAddress);
			server.start();
			LOGGER.info("Experiment server started");
			try {
				Thread.currentThread().join();
			} catch (InterruptedException e) {
				LOGGER.warn("Main thread interrupted", e);
			}
		} catch (Exception e) {
			LOGGER.error("Failed to start server: {}", e.getMessage(), e);
		}
	}

	public ExperimentServer() throws SocketException {
		GroupObservationsInfo.init();
		add(new MulticastObservableResource("mult", true, new InetSocketAddress("224.0.1.187", 56830)));
	}

	private void addEndpoints(String bindAddress) throws Exception {
		Configuration config = Configuration.getStandard();
		int port = config.get(CoapConfig.COAP_PORT);

		InetAddress loopback = InetAddress.getLoopbackAddress();
		CoapEndpoint.Builder loopbackBuilder = new CoapEndpoint.Builder();
		loopbackBuilder.setInetSocketAddress(new InetSocketAddress(loopback, port));
		loopbackBuilder.setConfiguration(config);
		addEndpoint(loopbackBuilder.build());

		Inet4Address physicalAddr;
		if (bindAddress != null) {
			physicalAddr = (Inet4Address) InetAddress.getByName(bindAddress);
		} else {
			physicalAddr = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
		}

		if (physicalAddr == null) {
			throw new SocketException("No multicast-capable IPv4 interface found");
		}

		InetSocketAddress physicalSocket = new InetSocketAddress(physicalAddr, port);
		CoapEndpoint.Builder physicalBuilder = new CoapEndpoint.Builder();
		physicalBuilder.setInetSocketAddress(physicalSocket);
		physicalBuilder.setConfiguration(config);
		addEndpoint(physicalBuilder.build());
		LOGGER.info("Listening on {}", physicalSocket);
	}
}
