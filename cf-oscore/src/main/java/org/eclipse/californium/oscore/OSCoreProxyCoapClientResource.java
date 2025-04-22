package org.eclipse.californium.oscore;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.hc.client5.http.utils.Hex;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.OptionEncoder;
import org.eclipse.californium.proxy2.ClientEndpoints;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.CoapUriTranslator;
import org.eclipse.californium.proxy2.TranslationException;
import org.eclipse.californium.proxy2.resources.CacheKey;
import org.eclipse.californium.proxy2.resources.CacheResource;
import org.eclipse.californium.proxy2.resources.ProxyCoapResource;
import org.eclipse.californium.proxy2.resources.StatsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

/**
 * Resource that forwards a coap request with the proxy-uri, proxy-scheme,
 * URI-host, or URI-port option set to the desired coap server.
 */
public class OSCoreProxyCoapClientResource extends ProxyCoapResource {

	static final Logger LOGGER = LoggerFactory.getLogger(OSCoreProxyCoapClientResource.class);

	/**
	 * Maps scheme to client endpoints.
	 */
	private Map<String, ClientEndpoints> mapSchemeToEndpoints = new HashMap<>();
	/**
	 * Coap2Coap translator.
	 */
	private Coap2CoapTranslator translator;
	/**
	 * OSCore context database 
	 */
	private static OSCoreCtxDB db;
	/**
	 * Create proxy resource for outgoing coap-requests.
	 * 
	 * @param name name of the resource
	 * @param visible visibility of the resource
	 * @param accept accept CON request before forwarding the request
	 * @param translator translator for coap2coap messages. {@code null} to use
	 *            default implementation {@link Coap2CoapTranslator}.
	 * @param endpointsList list of client endpoints for outgoing requests
	 */
	public OSCoreProxyCoapClientResource(String name, boolean visible, boolean accept, Coap2CoapTranslator translator,
			OSCoreCtxDB db, ClientEndpoints... endpointsList) {
		// set the resource hidden
		super(name, visible, accept);
		getAttributes().setTitle("Forward the requests to a CoAP server.");
		this.translator = translator != null ? translator : new Coap2CoapTranslator();
		OSCoreProxyCoapClientResource.db = db;
		for (ClientEndpoints endpoints : endpointsList) {
			this.mapSchemeToEndpoints.put(endpoints.getScheme(), endpoints);
		}
	}

	@Override
	public void handleRequest(final Exchange exchange) {

		System.out.println("The Client resource that is handling this request is: " + this.getName());
		System.out.println("Using destination schemes: " + this.getDestinationSchemes());
		System.out.println("Parent is: " + this.getParent());
		Request incomingRequest = exchange.getRequest();
		LOGGER.debug("OSCoreProxyCoapClientResource forwards {}", incomingRequest);
		System.out.println("Recieved forwarding Request with " + incomingRequest.getToken());

		try {
			// create the new request from the original
			InetSocketAddress exposedInterface = translator.getExposedInterface(incomingRequest);
			URI destination = translator.getDestinationURI(incomingRequest, exposedInterface);
			Request outgoingRequest = translator.getRequest(destination, incomingRequest);
			System.out.println(incomingRequest.getSourceContext().entries());

			if (incomingRequest.getOptions().hasOscore()) {
				OSCoreCtx ctx = db.getContext(outgoingRequest.getURI());

				if (ctx != null) {
					// need to handle case where there is not a context?
					// or just make sure it does not "crash" here
					byte[] oscoreopt = CBORObject.FromObject(incomingRequest.getOptions().getOscore()).EncodeToBytes();
					byte[] index = CBORObject.FromObject(2).EncodeToBytes();

					byte[] instructions = Bytes.concatenate(oscoreopt, index);

					boolean[] promotionAnswers = {false, true, true, true, false};
					instructions = Bytes.concatenate(instructions, OptionEncoder.set(ctx.getSenderId(), ctx.getMessageIdContext(), new int[] {OptionNumberRegistry.OSCORE}, new boolean[][] {promotionAnswers}));

					outgoingRequest.getOptions().setOscore(instructions);
				}
			}

			System.out.println("incoming Request was: " + incomingRequest);

			System.out.println("outgoing Request is:  " + outgoingRequest);
			System.out.println();
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
					new ProxySendResponseMessageObserver(translator, exchange, cacheKey, cache, this));
			ClientEndpoints endpoints = mapSchemeToEndpoints.get(outgoingRequest.getScheme());
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

	@Override
	public CoapUriTranslator getUriTranslater() {
		return translator;
	}

	@Override
	public Set<String> getDestinationSchemes() {
		return Collections.unmodifiableSet(mapSchemeToEndpoints.keySet());
	}

	private static class ProxySendResponseMessageObserver extends MessageObserverAdapter {

		private final Coap2CoapTranslator translator;
		private final Exchange incomingExchange;
		private final CacheKey cacheKey;
		private final CacheResource cache;
		private final ProxyCoapResource baseResource;

		private ProxySendResponseMessageObserver(Coap2CoapTranslator translator, Exchange incomingExchange,
				CacheKey cacheKey, CacheResource cache, ProxyCoapResource baseResource) {
			this.translator = translator;
			this.incomingExchange = incomingExchange;
			this.cacheKey = cacheKey;
			this.cache = cache;
			this.baseResource = baseResource;
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
			OSCoreProxyCoapClientResource.LOGGER.debug("OSCoreProxyCoapClientResource received {}", incomingResponse);

			Response outgoingResponse = translator.getResponse(incomingResponse);

			if (outgoingResponse.getOptions().hasOscore()) {

				OSCoreCtx ctx = db.getContextByToken(incomingExchange.getRequest().getToken());

				if (ctx != null) {
					byte[] oscoreopt = CBORObject.FromObject(outgoingResponse.getOptions().getOscore()).EncodeToBytes();
					byte[] index = CBORObject.FromObject(2).EncodeToBytes();

					byte[] instructions = Bytes.concatenate(oscoreopt, index);

					db.size();

					//this only works when the proxy provides one layer of encryption

					System.out.println(incomingResponse.getSourceContext().entries());

					boolean[] promotionAnswers = {false, true, true, true, false};
					//instructions = Bytes.concatenate(instructions, OptionEncoder.set(ctx.getSenderId(), ctx.getMessageIdContext(), new int[] {OptionNumberRegistry.OSCORE}, new boolean[][] {promotionAnswers}));
					instructions = Bytes.concatenate(instructions, OptionEncoder.set(ctx.getSenderId(), ctx.getMessageIdContext(), new int[] {OptionNumberRegistry.OSCORE}, new boolean[][] {promotionAnswers}, ctx.getSenderSeq()));

					db.addInstructions(incomingExchange.getRequest().getToken(), CBORObject.DecodeSequenceFromBytes(instructions));
				}
			}
			incomingExchange.sendResponse(outgoingResponse);

		}

		@Override
		public void onReject() {
			fail(ResponseCode.SERVICE_UNAVAILABLE);
			OSCoreProxyCoapClientResource.LOGGER.debug("Request rejected");
		}

		@Override
		public void onTimeout() {
			fail(ResponseCode.GATEWAY_TIMEOUT);
			OSCoreProxyCoapClientResource.LOGGER.debug("Request timed out.");
		}

		@Override
		public void onCancel() {
			fail(ResponseCode.SERVICE_UNAVAILABLE);
			OSCoreProxyCoapClientResource.LOGGER.debug("Request canceled");
		}

		@Override
		public void onSendError(Throwable e) {
			fail(ResponseCode.SERVICE_UNAVAILABLE);
			OSCoreProxyCoapClientResource.LOGGER.warn("Send error", e);
		}

		private void fail(ResponseCode response) {
			incomingExchange.sendResponse(new Response(response));
		}
	}
}
