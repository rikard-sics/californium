/*******************************************************************************
 * Copyright (c) 2020 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial creation
 *    Rikard Höglund (RISE SICS) - Group OSCORE sender functionality
 ******************************************************************************/
package org.eclipse.californium.oscore.group;

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.security.Security;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test sender configured to support multicast requests.
 * Rebased.
 */
public class GroupOSCORESenderDeterministic {

	/**
	 * Whether to use OSCORE or not.
	 */
	static final boolean useOSCORE = true;
	
	/**
	 * Whether to use the pairwise mode of Group OSCORE or not.
	 * 
	 * If set to true, the request will be sent over unicast, otherwise over multicast
	 */
	static final boolean pairwiseMode = true;
	
	/**
	 * Whether to send the request as a deterministic request or not
	 * 
	 * It must be set to false if "pairwiseMode" is set to false
	 */
	static final boolean deterministicRequest = true;
	
	/**
	 * Whether to send the request through a proxy or not
	 * 
	 * It must be set to false if "pairwiseMode" is set to false
	 */
	static final boolean useProxy = false;
	
	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE_MULTICAST = new File("CaliforniumMulticast.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER_MULTICAST = "Californium CoAP Properties file for Multicast Client";
	/**
	 * Special network configuration defaults handler.
	 */
	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MULTICAST_BASE_MID, 65000);
		}

	};

	/**
	 * Time to wait for replies to the multicast request
	 */
	private static final int HANDLER_TIMEOUT = 2000;

	/**
	 * Multicast address to send to (use the first line to set a custom one).
	 */
	// static final InetAddress multicastIP = new 
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	/**
	 * Unicast address to send to
	 */
	static final InetAddress unicastIP = new InetSocketAddress("127.0.0.1", 0).getAddress();
	
	/**
	 * Port to send to.
	 */
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT;

	/**
	 * Resource to perform request against.
	 */
	static final String requestResource = "/helloWorld";

	/**
	 * Payload in request sent (POST)
	 */
	static final String requestPayload = "test";

	/**
	 * Unicast address of the proxy, if used
	 */
	static final InetAddress proxyIP = new InetSocketAddress("127.0.0.1", 0).getAddress();
	
	/**
	 * Port number of the CoAP-to-CoAP proxy
	 */
	private static final int proxyPort = 5685;
	
	/**
	 * Resource at the proxy to perform coap2coap forwarding
	 */
	static final String proxyResource = "/coap2coap";

	/**
	 * ED25519 curve value.
	 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
	 */
	// static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); //Integer value
	// 6

	/* --- OSCORE Security Context information (sender) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature (EdDSA)
	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;
	
	// Encryption algorithm for when using signatures
	private final static AlgorithmID algSignEnc = AlgorithmID.AES_CCM_16_64_128;
	
	// Algorithm for key agreement
	private final static AlgorithmID algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	

	/*
	// Test with Christian
	private final static byte[] master_secret = { (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55,
			                                      (byte) 0x66, (byte) 0x77, (byte) 0x88, (byte) 0x99, (byte) 0x00,
			                                      (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee,
			                                      (byte) 0xff };
	private final static byte[] master_salt =   { (byte) 0x1f, (byte) 0x2e, (byte) 0x3d, (byte) 0x4c, (byte) 0x5b,
			                                      (byte) 0x6a, (byte) 0x70, (byte) 0x81 };
	*/
	
	
	
	private static final int REPLAY_WINDOW = 32;
	
	private final static byte[] gm_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"A501781A636F6170733A2F2F6D79736974652E6578616D706C652E636F6D026C67726F75706D616E6167657203781A636F6170733A2F2F646F6D61696E2E6578616D706C652E6F7267041AAB9B154F08A101A4010103272006215820CDE3EFD3BC3F99C9C9EE210415C6CBA55061B5046E963B8A58C9143A61166472");

	private final static byte[] sid = new byte[] { 0x25 };
	private final static byte[] sid_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
	private static MultiKey sid_private_key;
	private static byte[] sid_private_key_bytes = new byte[] { (byte) 0x64, (byte) 0x71, (byte) 0x4D, (byte) 0x41,
			(byte) 0xA2, (byte) 0x40, (byte) 0xB6, (byte) 0x1D, (byte) 0x8D, (byte) 0x82, (byte) 0x35, (byte) 0x02,
			(byte) 0x71, (byte) 0x7A, (byte) 0xB0, (byte) 0x88, (byte) 0xC9, (byte) 0xF4, (byte) 0xAF, (byte) 0x6F,
			(byte) 0xC9, (byte) 0x84, (byte) 0x45, (byte) 0x53, (byte) 0xE4, (byte) 0xAD, (byte) 0x4C, (byte) 0x42,
			(byte) 0xCC, (byte) 0x73, (byte) 0x52, (byte) 0x39 };

	private final static byte[] rid1 = new byte[] { 0x52 }; // Recipient 1
	private static byte[] rid1_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B");
	private static MultiKey rid1_public_key;
	
	// Test with Christian
	/*
	private final static byte[] rid1 = new byte[] { (byte) 0x0a }; // Recipient 1
	*/
	
	
	
	private final static byte[] rid2 = new byte[] { 0x77 }; // Recipient 2
	private final static byte[] rid2_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820105B8C6A8C88019BF0C354592934130BAA8007399CC2AC3BE845884613D5BA2E");
	private static MultiKey rid2_public_key;

	private final static byte[] rid0 = new byte[] { (byte) 0xCC }; // Dummy

	private final static byte[] detSid = new byte[] { (byte) 0xdc }; // Sender ID of the deterministic client
	
	private final static byte[] group_identifier = new byte[] { (byte) 0xdd, (byte) 0x11 }; // GID
	
	
	
	/* --- OSCORE Security Context information --- */

	public static void main(String args[]) throws Exception {
		/**
		 * URI to perform request against. Need to check for IPv6 to surround it
		 * with []
		 */
		String multicastRequestURI = "";
		String unicastRequestURI = "";
		String unicastProxyURI = "";

		if (multicastIP instanceof Inet6Address) {
			multicastRequestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort + requestResource;
		} else {
			multicastRequestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort + requestResource;
		}
		if (unicastIP instanceof Inet6Address) {
			unicastRequestURI = "coap://" + "[" + unicastIP.getHostAddress() + "]" + ":" + destinationPort + requestResource;
		} else {
			unicastRequestURI = "coap://" + unicastIP.getHostAddress() + ":" + destinationPort + requestResource;
		}
		if (proxyIP instanceof Inet6Address) {
			unicastProxyURI = "coap://" + "[" + proxyIP.getHostAddress() + "]" + ":" + proxyPort + proxyResource;
		} else {
			unicastProxyURI = "coap://" + proxyIP.getHostAddress() + ":" + proxyPort + proxyResource;
		}

		
		// Test with Christian
		// unicastRequestURI = "coap://detsrv.proxy.rd.coap.amsuess.com/.well-known/core";
		
		
		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);
		// InstallCryptoProviders.generateCounterSignKey();

		// Add private & public keys for sender & receiver(s)
		sid_private_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);
		rid1_public_key = new MultiKey(rid1_public_key_bytes);
		rid2_public_key = new MultiKey(rid2_public_key_bytes);
		
		/*
		// Test with Christian
			rid1_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
				"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B");
			rid1_public_key = new MultiKey(rid1_public_key_bytes);
		*/
		
		// If OSCORE is being used set the context information
		if (useOSCORE) {

			byte[] gmPublicKey = gm_public_key_bytes;
			GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
											  algSignEnc, algKeyAgreement, gmPublicKey);
			
			commonCtx.addSenderCtxCcs(sid, sid_private_key);

			commonCtx.addRecipientCtxCcs(rid0, REPLAY_WINDOW, null);
			commonCtx.addRecipientCtxCcs(rid1, REPLAY_WINDOW, rid1_public_key);
			commonCtx.addRecipientCtxCcs(rid2, REPLAY_WINDOW, rid2_public_key);

			commonCtx.addDeterministicSenderCtx(detSid, "SHA-256");
			commonCtx.addDeterministicRecipientCtx(detSid, 0, "SHA-256");
			
			db.addContext(multicastRequestURI, commonCtx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		CoapClient client = new CoapClient();
				
		if (pairwiseMode && useProxy == false) {
				client.setURI(unicastRequestURI);
		}
		else {
			Configuration config = Configuration.createWithFile(CONFIG_FILE_MULTICAST, CONFIG_HEADER_MULTICAST, DEFAULTS);
			CoapEndpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
			client.setEndpoint(endpoint);
			client.setURI(multicastRequestURI);
		}
		
		Request request;
		Code requestCode = Code.POST;
		if (useOSCORE) {

			if (!pairwiseMode) {
				request = Request.newPost();
				request.setPayload(requestPayload);
				request.setType(Type.NON);
				
				// Protect the request in group mode
				request.getOptions().setOscore(Bytes.EMPTY);
			}
			else {
				if (!deterministicRequest) {
					request = Request.newPost();
					request.setPayload(requestPayload);
					request.setType(Type.CON);
					
					// Protect the request in pairwise mode for a particular group member
					request.getOptions().setOscore(OptionEncoder.set(true, multicastRequestURI, rid1, false));
				}
				else {
					request = new Request(Code.GET);
					request.setType(Type.CON);
					requestCode = Code.GET;
					
					// Protect the request in pairwise mode as a deterministic request
					request.getOptions().setOscore(OptionEncoder.set(true, multicastRequestURI, null, true));
				}
				
			}
		}

		// Information about the sender
		System.out.println("==================");
		System.out.println("*Group sender");
		System.out.println("Uses OSCORE: " + useOSCORE);
		if (!pairwiseMode) {
			System.out.println("Request destination: " + multicastRequestURI);
		}
		else {
			System.out.println("Request destination: " + unicastRequestURI);
		}
		System.out.println("Request destination port: " + destinationPort);
		System.out.println("Request method: " + request.getCode());
		if (requestCode != Code.GET && requestCode != Code.DELETE && requestPayload != null) {
			System.out.println("Request payload: " + requestPayload);
		}
		System.out.println("==================");

		try {
			String host;
			int port;
			String path;
			if (useProxy == false) {
				host = new URI(client.getURI()).getHost();
				port = new URI(client.getURI()).getPort();
				path = new URI(client.getURI()).getPath();
			}
			else {
				host = new URI(unicastProxyURI).getHost();
				port = proxyPort;
				path = proxyResource;
			}
			System.out.println("Sending to: " + host + ":" + port + path);
		} catch (URISyntaxException e) {
			System.err.println("Failed to parse destination URI");
			e.printStackTrace();
		}

		System.out.println(Utils.prettyPrint(request));
		
		if (useOSCORE && pairwiseMode) {
			
			// sends a unicast request

			/*
			CoapResponse response = client.advanced(request);
			
			System.out.println("Sending from: " + client.getEndpoint().getAddress());
			System.out.println("Receiving from: " + response.advanced().getSourceContext().getPeerAddress());
			System.out.println(Utils.prettyPrint(response));
			*/
			
			if (useProxy == true) {
				// Use the Proxy-Uri option
				request.setURI(unicastProxyURI);
				request.getOptions().setProxyUri(unicastRequestURI);
				
				// Placeholder for using Proxy-Scheme instead
				/*
				AddressEndpointContext proxy = new AddressEndpointContext(new InetSocketAddress(proxyIP, proxyPort));
				request.setDestinationContext(proxy);
				request.setURI(unicastRequestURI);
				request.setProxyScheme("coap");
				*/
			}
			
			// Send a first request as prepared above
			client.advanced(handler, request);
			while (handler.waitOn(HANDLER_TIMEOUT)) {
				// Wait for responses
			}
			
			// Prepare a second request, with the same type and payload of the first one
			requestCode = Code.POST;
			if (!deterministicRequest) {
				request = Request.newPost();
				request.setPayload(requestPayload);
				request.setType(Type.CON);
				
				// Protect the request in pairwise mode for a particular group member
				request.getOptions().setOscore(OptionEncoder.set(true, multicastRequestURI, rid1, false));
			}
			else {

				request = new Request(Code.GET);
				request.setType(Type.CON);
				requestCode = Code.GET;
				
				// Protect the request in pairwise mode as a deterministic request
				request.getOptions().setOscore(OptionEncoder.set(true, multicastRequestURI, null, true));
			}
			
			if (useProxy == true) {
				// Use the Proxy-Uri option
				request.setURI(unicastProxyURI);
				request.getOptions().setProxyUri(unicastRequestURI);
				
				// Placeholder for using Proxy-Scheme instead
				/*
				AddressEndpointContext proxy = new AddressEndpointContext(new InetSocketAddress(proxyIP, proxyPort));
				request.setDestinationContext(proxy);
				request.setURI(unicastRequestURI);
				request.setProxyScheme("coap");
				*/
			}
			
			// Send the second request
			client.advanced(handler, request);
			while (handler.waitOn(HANDLER_TIMEOUT)) {
				// Wait for responses
			}
			
		}
		else if (useOSCORE && !pairwiseMode) {
			// Sends a first multicast request, as prepared above
			client.advanced(handler, request);
			System.out.println("Sending from: " + client.getEndpoint().getAddress());
			while (handler.waitOn(HANDLER_TIMEOUT)) {
				// Wait for responses
			}
			
			// Prepare a second request, with the same type and payload of the first one
			request = Request.newPost();
			request.setPayload(requestPayload);
			request.setType(Type.NON);
			
			// Protect the request in group mode
			request.getOptions().setOscore(Bytes.EMPTY);
			
			// Send the second multicast request, with the same type and payload of the first one 
			client.advanced(handler, request);
			System.out.println("Sending from: " + client.getEndpoint().getAddress());
			while (handler.waitOn(HANDLER_TIMEOUT)) {
				// Wait for responses
			}
		}

	}

	private static MultiCoapHandlerDeterministic handler = new MultiCoapHandlerDeterministic();
	
	private static class MultiCoapHandlerDeterministic implements CoapHandler {

		private boolean on;

		public synchronized boolean waitOn(long timeout) {
			on = false;
			try {
				wait(timeout);
			} catch (InterruptedException e) {
			}
			return on;
		}

		private synchronized void on() {
			on = true;
			notifyAll();
		}

		
		//Handle and parse incoming responses.
		@Override
		public void onLoad(CoapResponse response) {
			on();

			System.out.println("Receiving from: " + response.advanced().getSourceContext().getPeerAddress());
			System.out.println(Utils.prettyPrint(response));
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	}

}
