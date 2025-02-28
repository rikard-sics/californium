package org.eclipse.californium.oscore;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.proxy2.ClientEndpoints;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.TranslationException;
import org.eclipse.californium.proxy2.resources.CacheKey;
import org.eclipse.californium.proxy2.resources.CacheResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapClientResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;
import org.eclipse.californium.proxy2.resources.StatsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ProxyOSCoreClientResource extends ProxyCoapClientResource {

	static final Logger LOGGER = LoggerFactory.getLogger(ProxyOSCoreClientResource.class);

	private HashMapCtxDB db;
	
	public ProxyOSCoreClientResource(String name, boolean visible, boolean accept, Coap2CoapTranslator translator, HashMapCtxDB db,
			ClientEndpoints... endpointsList) {
		super(name, visible, accept, translator, endpointsList);
		this.db = db;
		// TODO Auto-generated constructor stub
	}


	@Override
	public void handleRequest(final Exchange exchange) {
		Request incomingRequest = exchange.getRequest();
		System.out.println("--------");
		System.out.println("Recieved forwarding Request with " + incomingRequest.getToken() + " in proxyOSCore");
		System.out.println("--------");

		//isAcceptableToForward(exchange, false); // incorrect
		OptionSet options = incomingRequest.getOptions();
		if (OptionJuggle.hasProxyRelatedOptions(options)) {
			System.out.println("has proxy related optinos tru");

			if (OptionJuggle.hasProxyUriOrCriOptions(options)) {
				System.out.println("has proxy uri true");

				isForwardProxy(exchange); // am i a forward proxy? function
			}
			else if (OptionJuggle.hasSchemeAndUri(options)){
				System.out.println("has scheme and uri true");

				isForwardProxy(exchange);
			}
			else if (OptionJuggle.hasUriPathHostPort(options)) {
				System.out.println("has uri path host or port true");

				// am i a reverse proxy 
				// do Uri path host or/and port identfify me as a reverse proxy?
				// if (yes) {
				// 		isAcceptableToForward(exchange, true);

				// }
			}
		}
		else {
			System.out.println("has checking oscore options ");

			hasOscoreOption(incomingRequest.getOptions(), exchange);
		}
	}
	public void hasOscoreOption(OptionSet options, Exchange exchange) {
		if (options.hasOscore()) {
			if (options.hasUriPath()) {
				// return 4.00
			}
			else {
				if (isAcceptableToDecrypt(exchange)) {
					Request request = exchange.getRequest();
					try {
						OSCoreCtx ctx = db.getContext(request, false);
						Request decryptedRequest = RequestDecryptor.decrypt(this.db, request, ctx);
						exchange.setRequest(decryptedRequest);
						handleRequest(exchange);
					}
					catch (Exception e) {
						System.out.println("decryption failed ");
						
					}
				}
				else {
					//return 4.01
				}
			}
		}
		// else is there an application
	}

	public void isForwardProxy(Exchange exchange) {
		if (true) {
			isAcceptableToForward(exchange, false);
		}/*
		else {
			return 5.05
		}*/
		
	}
	public boolean isAcceptableToDecrypt(Exchange exchange) {
		// do some actual checking
		return true;
		//if return true else return false
	}
	public void isAcceptableToForward(Exchange exchange, boolean isReverseProxy) {
		Request incomingRequest = exchange.getRequest();

		// authorization reinforcement
		boolean acceptableToForward = true;

		try {
			if (acceptableToForward) {
				OptionSet options = new OptionSet(incomingRequest.getOptions());
				
				if (isReverseProxy) {
					// do Does the authority (host and port) of the request Uri identify me?
					// default no
					String UriHost = options.getUriHost();
					int port = options.getUriPort();
				}
				

				InetSocketAddress exposedInterface = translator.getExposedInterface(incomingRequest);
				URI destination = translator.getDestinationURI(incomingRequest, exposedInterface);


				options.removeProxyScheme();
				options.removeProxyUri();
				options.removeBlock1();
				options.removeBlock2();
				options.removeUriHost();
				options.removeUriPort();
				options.clearUriPath();
				options.clearUriQuery();


				incomingRequest.setOptions(options);
				forwardRequest( exchange, exposedInterface, destination);
			}
			/*
			else {
				return 4.01
			}*/
		} catch (TranslationException e) {
			LOGGER.debug("Proxy-uri option malformed: {}", e.getMessage());
			Response response = new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED);
			response.setPayload(e.getMessage());
			exchange.sendResponse(response);
		}
	}
	public void forwardRequest(final Exchange exchange, InetSocketAddress exposedInterface, URI destination) {
		Request incomingRequest = exchange.getRequest();
		System.out.println("Forwarding Request with " + incomingRequest.getToken() + " in proxyOSCore");

		LOGGER.debug("ProxyCoapClientResource forwards {}", incomingRequest);

		try {
			// create the new request from the original
			System.out.println("creating new request");
			//InetSocketAddress exposedInterface = translator.getExposedInterface(incomingRequest);
			//URI destination = translator.getDestinationURI(incomingRequest, exposedInterface);
			Request outgoingRequest = translator.getRequest(destination, incomingRequest);
			System.out.println("new request created");

			// execute the request
			if (outgoingRequest.getDestinationContext() == null) {
				exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
				throw new NullPointerException("Destination is null");
			}
			CacheKey cacheKey = null;
			CacheResource cache = getCache();
			if (cache != null) {
				cacheKey = new CacheKey(outgoingRequest.getCode(), destination, outgoingRequest.getOptions().getAccept(), outgoingRequest.getPayload());
				Response response = cache.getResponse(cacheKey);
				StatsResource statsResource = getStatsResource();
				if (statsResource != null) {
					statsResource.updateStatistics(destination, response != null);
				}
				if (response != null) {
					LOGGER.info("Cache returned {}", response);
					exchange.sendResponse(response);
					return;
				}
			}
			LOGGER.debug("Sending proxied CoAP request to {}", outgoingRequest.getDestinationContext());
			if (accept) {
				exchange.sendAccept();
			}
			outgoingRequest.addMessageObserver(
					new OSCoreProxySendResponseMessageObserver(translator, exchange, cacheKey, cache, this));
			ClientEndpoints endpoints = mapSchemeToEndpoints.get(outgoingRequest.getScheme());
			System.out.println("sending from proxy coap client resource, to sendrequest of endpoint");
			endpoints.sendRequest(outgoingRequest);
		} catch (TranslationException e) {
			LOGGER.debug("Proxy-uri option malformed: {}", e.getMessage());
			Response response = new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED);
			response.setPayload(e.getMessage());
			exchange.sendResponse(response);
		} catch (Exception e) {
			LOGGER.warn("Failed to execute request: {}", e.getMessage(), e);
			exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
		}
	}
	public static class OSCoreProxySendResponseMessageObserver extends ProxySendResponseMessageObserver {

		private OSCoreProxySendResponseMessageObserver(Coap2CoapTranslator translator, Exchange incomingExchange,
				CacheKey cacheKey, CacheResource cache, ProxyCoapResource baseResource) {
			super(translator, incomingExchange, cacheKey, cache, baseResource);
			// TODO Auto-generated constructor stub
		}

		@Override
		public void onResponse(Response incomingResponse) {
			System.out.println("Received forwarding Response with " + incomingResponse.getToken());
			int size = incomingResponse.getPayloadSize();
			if (!baseResource.checkMaxResourceBodySize(size)) {
				incomingResponse = new Response(ResponseCode.BAD_GATEWAY);
				incomingResponse.setPayload("CoAP response of " + size + " bytes exceeds maximum support size of "
						+ baseResource.getMaxResourceBodySize() + " bytes!");
				incomingResponse.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			}
			if (cache != null) {
				cache.cacheResponse(cacheKey, incomingResponse);
			}
			ProxyOSCoreClientResource.LOGGER.debug("ProxyCoapClientResource received {}", incomingResponse);

			incomingExchange.sendResponse(translator.getResponse(incomingResponse));

		}
	}
}