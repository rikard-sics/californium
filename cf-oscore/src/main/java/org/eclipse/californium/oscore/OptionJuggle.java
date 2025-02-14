/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.StringOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

/**
 * 
 * Provides option handling methods necessary for OSCORE mechanics.
 *
 */
public class OptionJuggle {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OptionJuggle.class);
	
	private static List<Integer> allEOptions = populateAllEOptions();
	private static List<Integer> sourceDestinationEOptions = populateSourceDestinationEOptions();
	private static List<Integer> sourceProxyEOptions = populateSourceProxyEOptions();
	private static List<Integer> proxyDestinationEOptions = populateProxyDestinationEOptions();
	private static List<Integer> proxypProxyEOptions = populateProxyProxyEOptions();

	private static List<Integer> populateAllEOptions() {
		List<Integer> allEOptions = new ArrayList<Integer>();
		allEOptions.add(OptionNumberRegistry.IF_MATCH);
		allEOptions.add(OptionNumberRegistry.ETAG);
		allEOptions.add(OptionNumberRegistry.IF_NONE_MATCH);
		allEOptions.add(OptionNumberRegistry.OBSERVE);
		allEOptions.add(OptionNumberRegistry.LOCATION_PATH);
		allEOptions.add(OptionNumberRegistry.URI_PATH);
		allEOptions.add(OptionNumberRegistry.CONTENT_FORMAT);
		allEOptions.add(OptionNumberRegistry.MAX_AGE);
		allEOptions.add(OptionNumberRegistry.URI_QUERY);
		allEOptions.add(OptionNumberRegistry.ACCEPT);
		allEOptions.add(OptionNumberRegistry.LOCATION_QUERY);
		allEOptions.add(OptionNumberRegistry.BLOCK2);
		allEOptions.add(OptionNumberRegistry.BLOCK1);
		allEOptions.add(OptionNumberRegistry.SIZE2);
		allEOptions.add(OptionNumberRegistry.SIZE1);
		allEOptions.add(OptionNumberRegistry.OSCORE); 
		return allEOptions;
	}
	
	private static List<Integer> populateSourceDestinationEOptions() {
		List<Integer> sourceDestinationEOptions = new ArrayList<Integer>();
		sourceDestinationEOptions.add(OptionNumberRegistry.IF_MATCH);
		sourceDestinationEOptions.add(OptionNumberRegistry.ETAG);
		sourceDestinationEOptions.add(OptionNumberRegistry.IF_NONE_MATCH);
		sourceDestinationEOptions.add(OptionNumberRegistry.OBSERVE);
		sourceDestinationEOptions.add(OptionNumberRegistry.LOCATION_PATH);
		sourceDestinationEOptions.add(OptionNumberRegistry.URI_PATH);
		sourceDestinationEOptions.add(OptionNumberRegistry.CONTENT_FORMAT);
		sourceDestinationEOptions.add(OptionNumberRegistry.MAX_AGE);
		sourceDestinationEOptions.add(OptionNumberRegistry.URI_QUERY);
		sourceDestinationEOptions.add(OptionNumberRegistry.ACCEPT);
		sourceDestinationEOptions.add(OptionNumberRegistry.LOCATION_QUERY);
		sourceDestinationEOptions.add(OptionNumberRegistry.BLOCK2);
		sourceDestinationEOptions.add(OptionNumberRegistry.BLOCK1);
		sourceDestinationEOptions.add(OptionNumberRegistry.SIZE2);
		sourceDestinationEOptions.add(OptionNumberRegistry.SIZE1);
		sourceDestinationEOptions.add(OptionNumberRegistry.OSCORE); 
		return sourceDestinationEOptions;
	}
	
	private static List<Integer> populateSourceProxyEOptions() {
		List<Integer> sourceProxyEOptions = new ArrayList<Integer>();
		sourceProxyEOptions.add(OptionNumberRegistry.IF_MATCH);
		sourceProxyEOptions.add(OptionNumberRegistry.ETAG);
		sourceProxyEOptions.add(OptionNumberRegistry.IF_NONE_MATCH);
		sourceProxyEOptions.add(OptionNumberRegistry.OBSERVE);
		sourceProxyEOptions.add(OptionNumberRegistry.LOCATION_PATH);
		sourceProxyEOptions.add(OptionNumberRegistry.URI_PATH);
		sourceProxyEOptions.add(OptionNumberRegistry.CONTENT_FORMAT);
		sourceProxyEOptions.add(OptionNumberRegistry.MAX_AGE);
		sourceProxyEOptions.add(OptionNumberRegistry.URI_QUERY);
		sourceProxyEOptions.add(OptionNumberRegistry.ACCEPT);
		sourceProxyEOptions.add(OptionNumberRegistry.LOCATION_QUERY);
		sourceProxyEOptions.add(OptionNumberRegistry.BLOCK2);
		sourceProxyEOptions.add(OptionNumberRegistry.BLOCK1);
		sourceProxyEOptions.add(OptionNumberRegistry.SIZE2);
		sourceProxyEOptions.add(OptionNumberRegistry.SIZE1);
		sourceProxyEOptions.add(OptionNumberRegistry.OSCORE); 
		return sourceProxyEOptions;
	}
	
	private static List<Integer> populateProxyDestinationEOptions() {
		List<Integer> proxyDestinationEOptions = new ArrayList<Integer>();
		proxyDestinationEOptions.add(OptionNumberRegistry.IF_MATCH);
		proxyDestinationEOptions.add(OptionNumberRegistry.ETAG);
		proxyDestinationEOptions.add(OptionNumberRegistry.IF_NONE_MATCH);
		proxyDestinationEOptions.add(OptionNumberRegistry.OBSERVE);
		proxyDestinationEOptions.add(OptionNumberRegistry.LOCATION_PATH);
		proxyDestinationEOptions.add(OptionNumberRegistry.URI_PATH);
		proxyDestinationEOptions.add(OptionNumberRegistry.CONTENT_FORMAT);
		proxyDestinationEOptions.add(OptionNumberRegistry.MAX_AGE);
		proxyDestinationEOptions.add(OptionNumberRegistry.URI_QUERY);
		proxyDestinationEOptions.add(OptionNumberRegistry.ACCEPT);
		proxyDestinationEOptions.add(OptionNumberRegistry.LOCATION_QUERY);
		proxyDestinationEOptions.add(OptionNumberRegistry.BLOCK2);
		proxyDestinationEOptions.add(OptionNumberRegistry.BLOCK1);
		proxyDestinationEOptions.add(OptionNumberRegistry.SIZE2);
		proxyDestinationEOptions.add(OptionNumberRegistry.SIZE1);
		proxyDestinationEOptions.add(OptionNumberRegistry.OSCORE); // wee wee woo
		return proxyDestinationEOptions;
	}
	
	private static List<Integer> populateProxyProxyEOptions() {
		List<Integer> proxypProxyEOptions = new ArrayList<Integer>();
		proxypProxyEOptions.add(OptionNumberRegistry.IF_MATCH);
		proxypProxyEOptions.add(OptionNumberRegistry.ETAG);
		proxypProxyEOptions.add(OptionNumberRegistry.IF_NONE_MATCH);
		proxypProxyEOptions.add(OptionNumberRegistry.OBSERVE);
		proxypProxyEOptions.add(OptionNumberRegistry.LOCATION_PATH);
		proxypProxyEOptions.add(OptionNumberRegistry.URI_PATH);
		proxypProxyEOptions.add(OptionNumberRegistry.CONTENT_FORMAT);
		proxypProxyEOptions.add(OptionNumberRegistry.MAX_AGE);
		proxypProxyEOptions.add(OptionNumberRegistry.URI_QUERY);
		proxypProxyEOptions.add(OptionNumberRegistry.ACCEPT);
		proxypProxyEOptions.add(OptionNumberRegistry.LOCATION_QUERY);
		proxypProxyEOptions.add(OptionNumberRegistry.BLOCK2);
		proxypProxyEOptions.add(OptionNumberRegistry.BLOCK1);
		proxypProxyEOptions.add(OptionNumberRegistry.SIZE2);
		proxypProxyEOptions.add(OptionNumberRegistry.SIZE1);
		proxypProxyEOptions.add(OptionNumberRegistry.OSCORE); // wee wee woo
		return proxypProxyEOptions;
	}

	/**
	 * Prepare a set or original CoAP options for unprotected use with OSCore.
	 * 
	 * @param options the original options
	 * 
	 * @return the OSCore-U option set
	 */
	public static OptionSet prepareUoptions(OptionSet options) {
		boolean hasProxyUri = options.hasProxyUri();
		boolean hasUriHost = options.hasUriHost();
		boolean hasUriPort = options.hasUriPort();
		boolean hasProxyScheme = options.hasProxyScheme();
		boolean hasMaxAge = options.hasMaxAge();
		boolean hasObserve = options.hasObserve();

		OptionSet ret = new OptionSet();

		if (hasUriHost) {
			ret.setUriHost(options.getUriHost());
		}

		if (hasUriPort) {
			ret.setUriPort(options.getUriPort());
		}

		if (hasMaxAge) {
			ret.setMaxAge(options.getMaxAge());
		}

		if (hasProxyScheme) {
			ret.setProxyScheme(options.getProxyScheme());
		}

		if (hasObserve) {
			ret.setObserve(options.getObserve());
		}

		if (hasProxyUri) {
			String proxyUri = options.getProxyUri();
			proxyUri = proxyUri.replace("coap://", "");
			proxyUri = proxyUri.replace("coaps://", "");
			int i = proxyUri.indexOf('/');
			if (i >= 0) {
				proxyUri = proxyUri.substring(0, i);
			}
			proxyUri = "coap://" + proxyUri;
			ret.setProxyUri(proxyUri);
		}

		byte[] oscore = options.getOscore();
		if (oscore != null) {
			ret.setOscore(oscore);
		}

		return ret;
	}

	/**
	 * Prepare a set or original CoAP options for encryption with OSCore.
	 * 
	 * @param options the original CoAP options
	 * 
	 * @return the option to be encrypted
	 */
	public static OptionSet prepareEoptions(OptionSet options, Request request, CBORObject[] instructions) {
		OptionSet ret = new OptionSet();
		
		
		System.out.println("initial optionset: " + options);
		for (Option o : options.asSortedList()) {
			// did i add opt to m?
			// maybe add onto "endpointcontext" in request if it is a creator, would need request as param to know (or just endppintcontext)
			// Is x a consumer of opt?
			boolean isConsumer = false;
			if (processOptionAsE(o, request, instructions)) {
				ret.addOption(o);
			}
			/*
			// Is x the immediately next consumer of opt?
			// assume it is for now for simplicity
			*/
			
			
			switch (o.getNumber()) {
			case OptionNumberRegistry.URI_HOST:
			case OptionNumberRegistry.URI_PORT:
			case OptionNumberRegistry.PROXY_SCHEME:
			case OptionNumberRegistry.OSCORE:
				// do not encrypt
				break;
			case OptionNumberRegistry.PROXY_URI:
				// create Uri-Path and Uri-Query
				String proxyUri = ((StringOption)o).getStringValue();
				proxyUri = proxyUri.replace("coap://", "");
				proxyUri = proxyUri.replace("coaps://", "");
				int i = proxyUri.indexOf('/');
				if (i >= 0) {
					proxyUri = proxyUri.substring(i + 1, proxyUri.length());
				} else {// No Uri-Path and Uri-Query
					break;
				}
				i = proxyUri.indexOf("?");
				String uriPath = proxyUri;
				String uriQuery = null;
				if (i >= 0) {
					uriPath = proxyUri.substring(0, i);
					uriQuery = proxyUri.substring(i + 1, proxyUri.length());
				}

				if (uriPath != null) {
					ret.setUriPath(uriPath);
				}

				if (uriQuery != null) {
					String[] uriQueries = uriQuery.split("&");
					for (int idx = 0; idx < uriQueries.length; idx++) {
						ret.setUriQuery(uriQueries[idx]);
					}
				}
				break;
			default: // default is encrypt
				System.out.println("encrypting opt: " + o);
				ret.addOption(o);
			}
		}
		System.out.println("out optionset: " + ret);

		return ret;
	}

	/**
	 * Returns a new OptionSet, result, which doesn't contain any e options
	 * 
	 * @param optionSet the options
	 * @return a new optionSet which have had the non-special e options removed
	 */
	public static OptionSet discardEOptions(OptionSet optionSet) {
		LOGGER.trace("Removing inner only E options from the outer options");
		OptionSet result = new OptionSet();
		
		for (Option opt : optionSet.asSortedList()) {
			if (!allEOptions.contains(opt.getNumber())) {
				result.addOption(opt);
			}
		}
		return result;
	}
	
	public static boolean processOptionAsE(Option option, Request request, CBORObject[] instructions) {
		// did I add OPT to M?
		System.out.println(request.getSourceContext().getPeerAddress().getAddress().getCanonicalHostName());
		String canonicalHostName = request.getSourceContext().getPeerAddress().getAddress().getCanonicalHostName();
		// where find it's own ip adress.
		if (canonicalHostName == "localhost" || true) {
			// is x a consumer of opt?
			return processIsEndpointConsumer(option, request, instructions);
		}
		return false;
	}

	public static boolean processIsEndpointConsumer(Option option, Request request, CBORObject[] instructions) {
		//should check other way for normal requests (i.e. no instructions, but still source)
		boolean isSource = instructions != null ? true : false;
		
		boolean toDestination = false;
		if (isSource && ((int) instructions[1].ToObject(int.class) == 2)) {
			toDestination = true;
		}
		// else check to see if not proxy sending to proxy
		// i.e. no instructions but also not proxy but still source
		// else check to see if proxy sending to proxy.
		
		if (isSource && toDestination) {      // source -> destination
			for (Option opt : sourceDestinationSet)
		}
		else if (isSource && !toDestination) {// source -> proxy
			
		}
		else if (!isSource && toDestination) {// proxy  -> destination
			
		}
		else {                                // proxy  -> proxy
			
		}
		if () { // assume x is destination endpoint
			// list of all consumable options for a destination endpoint?
			for (Option consumable : destinationConsumable) {
				if (option.getNumber() == consumable.getNumber()) {
					// source -> destination
					// proxy  -> destination
					
					return processIsEndpointImmediateConsumer(option, request, instructions);
				}
			}
		}
		else { // assume x is not a destination endpoint, i.e. proxy
			// list of all consumable options for a proxy?
			for (Option consumable : proxyConsumable) {
				if (option.getNumber() == consumable.getNumber()) {
					// source -> proxy
					// proxy  -> proxy
					return processIsEndpointImmediateConsumer(option, request, instructions);
				}
			}
		}
		return false;
	}
	
	public static boolean processIsEndpointImmediateConsumer(Option option, Request request, CBORObject[] instructions) {
		
		
		
		if (true) {
		return processNeedBeforeDecryption(option, request, instructions);
		}	
		return false;
	}
	
	/**
	 * Sets the fake code in the coap header and returns the real code.
	 * 
	 * @param request the request that receives its fake code.
	 * @return request with fake code.
	 */
	public static Request setFakeCodeRequest(Request request) {
		Code fakeCode = request.getOptions().hasObserve() ? Code.FETCH : Code.POST;
		return requestWithNewCode(request, fakeCode);
	}

	/**
	 * Sets the Request's CoAP Code with realCode
	 * 
	 * @param request the request that receives its real code
	 * @param realCode the real code
	 * @return request with real code.
	 */
	public static Request setRealCodeRequest(Request request, Code realCode) {
		return requestWithNewCode(request, realCode);
	}

	/**
	 * Sets the fake code in the coap header and returns the real code.
	 * 
	 * @param response the response that receives its fake code.
	 * @return response with fake code.
	 */
	public static Response setFakeCodeResponse(Response response) {
		return responseWithNewCode(response, ResponseCode.CHANGED);
	}

	/**
	 * Sets the realCode for a response
	 * 
	 * @param response response
	 * @param realCode real code
	 * @return response with real code
	 */
	public static Response setRealCodeResponse(Response response, ResponseCode realCode) {
		return responseWithNewCode(response, realCode);
	}

	/**
	 * Change the CoAP Code of the request to code
	 * 
	 * @param request the Request having its CoAP Code changed
	 * @param code the new CoAP Code
	 * @return request with new code.
	 */
	private static Request requestWithNewCode(Request request, Code code) {

		Request newRequest = new Request(code);
		copy(newRequest, request);
		newRequest.setUserContext(request.getUserContext());

		return newRequest;
	}

	/**
	 * Change the ResponseCode of the response to code
	 * 
	 * @param response the Response having its ResponseCode changed
	 * @param code the new ResponseCode
	 * @return response with new code.
	 */
	private static Response responseWithNewCode(Response response, ResponseCode code) {
		Long rtt = response.getApplicationRttNanos();

		Response newResponse = new Response(code);
		copy(newResponse, response);
		if (rtt != null) {
			newResponse.setApplicationRttNanos(rtt);
		}

		return newResponse;
	}

	private static void copy(Message newMessage, Message oldMessage) {
		newMessage.setOptions(oldMessage.getOptions());
		newMessage.setPayload(oldMessage.getPayload());
		newMessage.setToken(oldMessage.getToken());
		newMessage.setDestinationContext(oldMessage.getDestinationContext());
		newMessage.setSourceContext(oldMessage.getSourceContext());
		newMessage.addMessageObservers(oldMessage.getMessageObservers());
		newMessage.setMID(oldMessage.getMID());
		newMessage.setType(oldMessage.getType());
		newMessage.setDuplicate(oldMessage.isDuplicate());
		newMessage.setNanoTimestamp(oldMessage.getNanoTimestamp());
	}
	
	/**
	 * Merges two optionSets and returns the merge. Priority is eOptions
	 * 
	 * @param eOptions priority options
	 * @param uOptions options to be added
	 * @return merged OptionSet
	 */
	public static OptionSet merge(OptionSet eOptions, OptionSet uOptions) {

		List<Option> e = eOptions.asSortedList();

		for (Option tmp : uOptions.asSortedList()) {
			if (Collections.binarySearch(e, tmp) < 0) {
				System.out.println("merging eOption: " + e + " with uOption: " + tmp);
				eOptions.addOption(tmp);
			}
		}
		return eOptions;
	}
}
