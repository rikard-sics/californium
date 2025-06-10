/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch.IO GmbH - derived from org.eclipse.californium.examples.ExampleCrossProxy
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.io.File;
import java.io.IOException;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.TrackerMode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapStackFactory;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.KeyToken;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.interceptors.MessageInterceptorAdapter;
import org.eclipse.californium.core.network.stack.BaseCoapStack;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.network.stack.CongestionControlLayer;
import org.eclipse.californium.core.network.stack.ExchangeCleanupLayer;
import org.eclipse.californium.core.network.stack.Layer;
import org.eclipse.californium.core.network.stack.ObserveLayer;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.Definition;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.IntegerDefinition;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.ProtocolScheduledExecutorService;
import org.eclipse.californium.oscore.group.OptionEncoder;
import org.eclipse.californium.proxy2.ClientEndpoints;
import org.eclipse.californium.proxy2.ClientSingleEndpoint;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.EndpointPool;
import org.eclipse.californium.proxy2.TranslationException;
import org.eclipse.californium.proxy2.config.Proxy2Config;

import org.eclipse.californium.proxy2.resources.CacheResource;
import org.eclipse.californium.proxy2.resources.ForwardProxyMessageDeliverer;
import org.eclipse.californium.proxy2.resources.ProxyCacheResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapClientResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;
import org.eclipse.californium.proxy2.resources.StatsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.core.network.interceptors.MessageInterceptor;

/**
 * Demonstrates the examples for cross proxy functionality of CoAP.
 * 
 * Http2CoAP: Insert in browser: URI:
 * {@code http://localhost:8080/proxy/coap://localhost:PORT/target}
 * 
 * Http2LocalCoAPResource: Insert in browser: URI:
 * {@code http://localhost:8080/local/target}
 * 
 * Http2CoAP: configure browser to use the proxy "localhost:8080". Insert in
 * browser: ("localhost" requests are not send to a proxy, so use the hostname
 * or none-local-ip-address) URI:
 * {@code http://<hostname>:5683/target/coap:}
 * 
 * CoAP2CoAP: Insert in Copper:
 * 
 * <pre>
 * URI: coap://localhost:PORT/coap2coap 
 * Proxy: coap://localhost:PORT/targetA
 * </pre>
 *
 * CoAP2Http: Insert in Copper:
 * 
 * <pre>
 * URI: coap://localhost:PORT/coap2http 
 * Proxy: http://lantersoft.ch/robots.txt
 * </pre>
 */
public class SimpleProxyProxy {

	private static final Logger STATISTIC_LOGGER = LoggerFactory.getLogger("org.eclipse.californium.proxy.statistics");

	/**
	 * File name for configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumProxy3.properties");
	/**
	 * Header for configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Example Proxy";
	/**
	 * Default maximum resource size.
	 */
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	/**
	 * Default block size.
	 */
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	static {
		CoapConfig.register();
		UdpConfig.register();
		TcpConfig.register();
		Proxy2Config.register();
	}

	/**
	 * Special configuration defaults handler.
	 */
	private static final DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 20000);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.DEDUPLICATOR, CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.set(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, 24, TimeUnit.HOURS);
			config.set(Proxy2Config.HTTP_CONNECTION_IDLE_TIMEOUT, 10, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTP_CONNECT_TIMEOUT, 15, TimeUnit.SECONDS);
			config.set(Proxy2Config.HTTPS_HANDSHAKE_TIMEOUT, 30, TimeUnit.SECONDS);
			config.set(UdpConfig.UDP_RECEIVE_BUFFER_SIZE, 8192);
			config.set(UdpConfig.UDP_SEND_BUFFER_SIZE, 8192);
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 60, TimeUnit.SECONDS);
		}

	};

	private static final String COAP2COAP = "coap2coap";

	private CoapServer coapProxyServer;
	private ClientEndpoints proxyToServerEndpoint;
	private CacheResource cache;
	
	private final static HashMapCtxDB db = new HashMapCtxDB(true);
	private final static String uriLocal = "coap://127.0.0.1";
	private final static int CoapProxyPort = 5685;

	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[] { 0x02 };
	private final static byte[] rid = new byte[] { 0x02 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	private final static byte[][] sids = {
			new byte[] { 0x02 }, 
			new byte[] { 0x03 }
			};
	
	private final static byte[][] rids = {
			new byte[] { 0x02 }, 
			new byte[] { 0x03 }
			};
	
	private final static byte[][] idcontexts = {
			new byte[] { 0x02 }, 
			new byte[] { 0x03 }
			};
	

	public SimpleProxyProxy(Configuration config, boolean accept, boolean cache) throws IOException, OSException {
		OSCoreCtx ctxToClient = new OSCoreCtx(master_secret, true, alg, sids[0], rids[0], kdf, 32, master_salt, idcontexts[0], MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriLocal + ":" + Objects.toString(CoapProxyPort + 1), ctxToClient); 

		OSCoreCtx ctxToServer = new OSCoreCtx(master_secret, true, alg, sids[1], rids[1], kdf, 32, master_salt, idcontexts[1], MAX_UNFRAGMENTED_SIZE);
		int i = CoapProxyPort - 1;
		db.addContext(uriLocal /*+ ":" + Objects.toString(i)*/, ctxToServer);

		OSCoreCoapStackFactory.useAsDefault(db);
		Configuration outgoingConfig = new Configuration(config);
		
		outgoingConfig.set(CoapConfig.MID_TRACKER, TrackerMode.NULL);
		CoapEndpoint.Builder builder = CoapEndpoint.builder()
				.setConfiguration(outgoingConfig);
		// builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		// builder.setCustomCoapStackArgument(db);//
		proxyToServerEndpoint = new ClientSingleEndpoint(builder.build());
		
		ProxyCacheResource cacheResource = null;
		StatsResource statsResource = null;
		if (cache) {
			cacheResource = new ProxyCacheResource(config, true);
			statsResource = new StatsResource(cacheResource);
		}
		ProxyCoapResource coap2coap = new ProxyCoapClientResource(COAP2COAP, false, accept, translator, proxyToServerEndpoint);
		
		if (cache) {
			coap2coap.setCache(cacheResource);
			coap2coap.setStatsResource(statsResource);
		}
		
		builder = CoapEndpoint.builder();
		// builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		// builder.setCustomCoapStackArgument(db);
		//builder.setPort(CoapProxyPort);
		builder.setInetSocketAddress(new InetSocketAddress("localhost", CoapProxyPort));
		CoapEndpoint clientToProxyEndpoint = builder.build();
		
		coapProxyServer = new CoapServer(config);
		coapProxyServer.addEndpoint(clientToProxyEndpoint);
		
		ForwardProxyMessageDeliverer proxyMessageDeliverer = new ForwardProxyMessageDeliverer(coapProxyServer.getRoot(),
				translator, config);
		
		proxyMessageDeliverer.addProxyCoapResources(coap2coap); 
		proxyMessageDeliverer.addExposedServiceAddresses(new InetSocketAddress("localhost", CoapProxyPort));
		coapProxyServer.setMessageDeliverer(proxyMessageDeliverer);

		coapProxyServer.add(coap2coap);
		if (cache) {
			coapProxyServer.add(statsResource);
		}
		coapProxyServer.add(new SimpleCoapResource("target",
				"Hi! I am the local coap server on port " + CoapProxyPort + ". Request %d."));

		CoapResource targets = new CoapResource("targets");
		coapProxyServer.add(targets);

		coapProxyServer.start();

		//System.out.println("CoAP Proxy at: coap://localhost:" + CoapProxyPort + "/coap2coap");
		this.cache = cacheResource;
		// receiving on any address => enable LocalAddressResolver
		proxyMessageDeliverer.startLocalAddressResolver();
	}
	
	
	public static void main(String args[]) throws IOException, OSException {
		Configuration proxyConfig = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		SimpleProxyProxy proxy = new SimpleProxyProxy(proxyConfig, false, true);
		for(;;) {
			try {
				Thread.sleep(15000);
			} catch (InterruptedException e) {

			}
		}
	}

	public Coap2CoapTranslator translator = new Coap2CoapTranslator(); 
	
	private static class SimpleCoapResource extends CoapResource {

		private final String value;

		private final AtomicInteger counter = new AtomicInteger();

		public SimpleCoapResource(String name, String value) {
			// set the resource hidden
			super(name);
			getAttributes().setTitle("Simple local coap resource.");
			this.value = value;
		}

		public void handleGET(CoapExchange exchange) {
			exchange.setMaxAge(0);
			exchange.respond(ResponseCode.CONTENT, String.format(value, counter.incrementAndGet()),
					MediaTypeRegistry.TEXT_PLAIN);
		}

	}
}



