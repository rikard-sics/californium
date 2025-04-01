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
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
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
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.KeyToken;
import org.eclipse.californium.core.network.interceptors.MessageInterceptorAdapter;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.Definition;
import org.eclipse.californium.elements.EndpointContext;
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
import org.eclipse.californium.proxy2.resources.ProxyCoapClientResource;
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

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost";
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
		OSCoreCtx ctxclient = new OSCoreCtx(master_secret, true, alg, sids[0], rids[0], kdf, 32, master_salt, idcontexts[0], MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriLocal + ":" + Objects.toString(CoapProxyPort + 1), ctxclient); 

		OSCoreCtx ctxserver = new OSCoreCtx(master_secret, true, alg, sids[1], rids[1], kdf, 32, master_salt, idcontexts[1], MAX_UNFRAGMENTED_SIZE);
		//int i = CoapProxyPort - 1;
		db.addContext(uriLocal /*+ ":" + Objects.toString(i)*/, ctxserver);
		
		Configuration outgoingConfig = new Configuration(config);
		outgoingConfig.set(CoapConfig.MID_TRACKER, TrackerMode.NULL);

		CoapEndpoint.Builder builder = CoapEndpoint.builder();
				//.setConfiguration(outgoingConfig);
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());//
		builder.setCustomCoapStackArgument(db);//
		builder.setPort(CoapProxyPort - 1); 


		CoapEndpoint proxyToServerEndpoint = builder.build();
		proxyToServerEndpoint.setIsForwardProxy();
		
		CoapClient proxyClient = new CoapClient();
		proxyClient.setEndpoint(proxyToServerEndpoint);
		
		builder = CoapEndpoint.builder();
				//.setConfiguration(outgoingConfig);
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());
		builder.setCustomCoapStackArgument(db);
		builder.setPort(CoapProxyPort);
		
		CoapEndpoint clientToProxyEndpoint = builder.build();
		clientToProxyEndpoint.setIsForwardProxy();
		clientToProxyEndpoint.addInterceptor(new MessageInterceptorAdapter() {
			@Override
			public void receiveRequest(Request request) {
				System.out.println(request.getSourceContext().entries());
				Attributes attributes = new Attributes();
				attributes.add(OSCoreEndpointContextInfo.FORWARD_PROXY_FLAG, true);
				MapBasedEndpointContext newEndpointContext = MapBasedEndpointContext.addEntries(request.getSourceContext(), attributes);
				request.setSourceContext(newEndpointContext);
				System.out.println(request.getSourceContext().entries());
				System.out.println();
			}
		});
		CoapServer proxyServer = new CoapServer();

		proxyServer.addEndpoint(clientToProxyEndpoint);
		proxyServer.setMessageDeliverer(new MessageDeliverer() {
			/**
			 * Delivers an inbound CoAP request to an appropriate resource.
			 * 
			 * @param exchange
			 *            the exchange containing the inbound {@code Request}
			 * @throws NullPointerException if exchange is {@code null}.
			 */
			@Override
			public void deliverRequest(Exchange exchange) {
				Request incomingRequest = exchange.getRequest();
				System.out.println("Recieved forwarding Request with " + incomingRequest.getToken());
				System.out.println("exchange endpoint uri is: " +  exchange.getEndpoint().getUri());
				try {
					if (!(incomingRequest.getScheme().equals("coap"))) {
						Response response = new Response(ResponseCode.BAD_GATEWAY);
						response.setPayload("Scheme not supported");
						exchange.sendResponse(response);
					}
					/*
					System.out.println(exchange);           // localhost + UDP port

					System.out.println(incomingRequest); // recieved request
					System.out.println(incomingRequest.getDestinationContext());
					System.out.println(incomingRequest.getSourceContext());

					System.out.println("exchange info in deliver request end");
					*/
					
					InetSocketAddress exposedInterface = translator.getExposedInterface(incomingRequest);
					URI destination = translator.getDestinationURI(incomingRequest, exposedInterface);
					Request outgoingRequest = translator.getRequest(destination, incomingRequest);		
					
					if (outgoingRequest.getDestinationContext() == null) {
						exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
						throw new NullPointerException("Destination is null");
					}
					
					/*outgoingRequest.addMessageObserver(new MessageObserverAdapter() {
						protected final Exchange incomingExchange = exchange;
						
						@Override
						public void onResponse(final Response response) {
							System.out.println();
							System.out.println("Received--------forwarding Response with " + response.getToken());
							incomingExchange.sendResponse(translator.getResponse(response));
						
						}
					});*/
					/*System.out.println("Proxy is sending outgoing request: " + outgoingRequest);
					int port = outgoingRequest.getDestinationContext().getPeerAddress().getPort();
					System.out.println("send to port: " + port);
					exchange.setEndpoint(proxy.getEndpoint(port));*/
					//System.out.println("endpoint context is: " + exchange.getEndpointContext());
					//exchange.getEndpoint().sendRequest(outgoingRequest);
					try {
						System.out.println("PROXIES OUTGOING REQUEST IS: " + outgoingRequest);
						
						/*
						byte[] oscoreopt = CBORObject.FromObject(outgoingRequest.getOptions().getOscore()).EncodeToBytes();
						byte[] index = CBORObject.FromObject(2).EncodeToBytes(); 
						
						byte[] instructions = OptionEncoder.combine(oscoreopt, index);
						
						int[] emptyOptionSets = {};

						//make for as many as you like
						instructions = OptionEncoder.combine(instructions, OptionEncoder.set(rids[1], idcontexts[1], emptyOptionSets));
						
						outgoingRequest.getOptions().setOscore(instructions);
						*/
						//outgoingRequest.getOptions().setOscore(new byte[0]);
						
						/*System.out.println("\n");
						System.out.println(exchange.getRequest().getSourceContext().entries());
						Attributes attributes = new Attributes();
						attributes.add(x, "2.getSenderIdString()");
						MapBasedEndpointContext newEndpointContext = MapBasedEndpointContext.addEntries(exchange.getRequest().getSourceContext(), attributes);
						exchange.getRequest().setSourceContext(newEndpointContext);
						System.out.println(exchange.getRequest().getSourceContext().entries()); */
						System.out.println();
						System.out.println(outgoingRequest.getSourceContext());
						outgoingRequest.setSourceContext(exchange.getRequest().getSourceContext());
						System.out.println(outgoingRequest.getSourceContext());
						System.out.println(outgoingRequest.getSourceContext().entries());


						System.out.println();

						CoapResponse response = proxyClient.advanced(outgoingRequest);
						Response outgoingResponse = translator.getResponse(response.advanced());
						System.out.println("Sending response from proxy now");
						outgoingResponse.getOptions().setContentFormat(1);
						exchange.sendResponse(outgoingResponse);
						
					} catch (ConnectorException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
					
				} catch (TranslationException e) {

					Response response = new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED);
					response.setPayload(e.getMessage());
					exchange.sendResponse(response);
				}

			}

			/**
			 * Delivers an inbound CoAP response message to its corresponding request.
			 * 
			 * @param exchange
			 *            the exchange containing the originating CoAP request
			 * @param response
			 *            the inbound CoAP response message
			 * @throws NullPointerException if exchange or response are {@code null}.
			 * @throws IllegalArgumentException if the exchange does not contain a request.
			 */
			@Override
			public void deliverResponse(Exchange exchange, Response response) {
				System.out.println("Recieved forwarding Response with " + response.getToken());
				System.out.println("Proxy: Deliver response called.");
				System.out.println();
				System.out.println(exchange.getEndpointContext());
				System.out.println(exchange.getRequest());
				//exchange.sendResponse(translator.getResponse(response));
			}
		});

		proxyServer.start();
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
}
