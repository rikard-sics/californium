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
import java.util.Objects;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.StringOption;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.oscore.group.OptionEncoder;
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
	private static List<Integer> allUOptions = populateAllUOptions();
	private static List<Integer> serverConsumeOptions = populateServerConsumeOptions();
	private static List<Integer> proxyConsumeOptions = populateProxyConsumeOptions();

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
		return allEOptions;
	}

	private static List<Integer> populateAllUOptions() {
		List<Integer> proxyConsumeOptions = new ArrayList<Integer>();
		proxyConsumeOptions.add(OptionNumberRegistry.URI_HOST);
		proxyConsumeOptions.add(OptionNumberRegistry.OBSERVE);
		proxyConsumeOptions.add(OptionNumberRegistry.URI_PORT);
		proxyConsumeOptions.add(OptionNumberRegistry.OSCORE);
		proxyConsumeOptions.add(OptionNumberRegistry.MAX_AGE);
		proxyConsumeOptions.add(OptionNumberRegistry.PROXY_URI);
		proxyConsumeOptions.add(OptionNumberRegistry.PROXY_SCHEME);
		return proxyConsumeOptions;
	}
	private static List<Integer> populateServerConsumeOptions() {
		List<Integer> serverConsumeOptions = new ArrayList<Integer>();
		//serverConsumeOptions.add(OptionNumberRegistry.URI_HOST);
		//serverConsumeOptions.add(OptionNumberRegistry.URI_PORT);
		serverConsumeOptions.add(OptionNumberRegistry.URI_PATH);
		serverConsumeOptions.add(OptionNumberRegistry.URI_QUERY);

		serverConsumeOptions.add(OptionNumberRegistry.OBSERVE);
		serverConsumeOptions.add(OptionNumberRegistry.OSCORE);
		serverConsumeOptions.add(OptionNumberRegistry.MAX_AGE);


		return serverConsumeOptions;
	}

	private static List<Integer> populateProxyConsumeOptions() {
		List<Integer> proxyConsumeOptions = new ArrayList<Integer>();
		proxyConsumeOptions.add(OptionNumberRegistry.URI_HOST);
		proxyConsumeOptions.add(OptionNumberRegistry.URI_PORT);
		proxyConsumeOptions.add(OptionNumberRegistry.PROXY_SCHEME);
		proxyConsumeOptions.add(OptionNumberRegistry.PROXY_URI);

		proxyConsumeOptions.add(OptionNumberRegistry.OBSERVE);
		proxyConsumeOptions.add(OptionNumberRegistry.OSCORE);
		proxyConsumeOptions.add(OptionNumberRegistry.MAX_AGE);

		return proxyConsumeOptions;
	}

	public static boolean hasProxyRelatedOptions(OptionSet options) {
		if (options.hasProxyScheme() || options.hasProxyUri()) {
			return true;
		}
		else return false;
	}
	
	public static boolean hasProxyUriOrCriOptions(OptionSet options) {
		if (options.hasProxyUri() /*|| options.hasProxyCri()*/) {
			return true;
		}
		else return false;
	}
	
	public static boolean hasSchemeAndUri(OptionSet options) {
		if ((options.hasProxyScheme() /* || options.hasProxySchemeNumber()*/) && 
				(options.hasUriHost() || options.hasUriPort())) {
			return true;
		}
		else return false;
	}
	
	public static boolean hasUriPathHostPort(OptionSet options) {
		if (options.hasUriHost() || options.hasUriPort() || options.hasUriPath()) {
			return true;
		}
		else return false;
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

	public static OptionSet[] prepareUandEOptions(OptionSet options, byte[] encodedInstructions) {
		OptionSet[] result = {
				new OptionSet(),
				new OptionSet()
		};
		if (options.hasProxyUri()) {
			options = handleProxyUri(options.getProxyUri(), options);
		}

		CBORObject[] instructions = OptionEncoder.decodeCBORSequence(encodedInstructions);

		for (Option o : options.asSortedList()) {
			if (processOptionAsE(o, options, instructions)) {
				result[1].addOption(o);
				System.out.println("processing opt " + o + " as E");
			}
			else {
				result[0].addOption(o);
				System.out.println("processing opt " + o + " as U");

			}
		}
		System.out.println("Returning optionset to encryptor: ");
		System.out.println("U Options are --> " + result[0]);

		System.out.println("E Options are --> " + result[1]);


		return result;
	}

	public static OptionSet handleProxyUri(String proxyUri, OptionSet options) {
		String UProxyUri = proxyUri;

		proxyUri = proxyUri.replace("coap://", "");
		proxyUri = proxyUri.replace("coaps://", "");

		int i = proxyUri.indexOf('/');
		System.out.println(i);
		if (i >= 0) {
			UProxyUri = proxyUri.substring(0, i);
			proxyUri = proxyUri.substring(i + 1, proxyUri.length());
		} else {// No Uri-Path and Uri-Query

		}
		UProxyUri = "coap://" + UProxyUri;
		options.setProxyUri(UProxyUri);

		i = proxyUri.indexOf("?");
		String uriPath = proxyUri;
		String uriQuery = null;
		if (i >= 0) {
			uriPath = proxyUri.substring(0, i);
			uriQuery = proxyUri.substring(i + 1, proxyUri.length());
		}

		if (uriPath != null) {
			options.setUriPath(uriPath);
		}

		if (uriQuery != null) {
			String[] uriQueries = uriQuery.split("&");
			for (int idx = 0; idx < uriQueries.length; idx++) {
				options.setUriQuery(uriQueries[idx]);
			}
		}
		return options;
	}

	/**
	 * Prepare a set or original CoAP options for encryption with OSCore.
	 * 
	 * @param options the original CoAP options
	 * 
	 * @return the option to be encrypted
	 */
	public static OptionSet prepareEoptions(OptionSet options) {
		OptionSet ret = new OptionSet();


		System.out.println("initial optionset: " + options);
		for (Option o : options.asSortedList()) {

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

	public static boolean isClassEOption(Option option) {
		return !isClassUOption(option);
	}
	
	public static boolean isClassUOption(Option option) {
		if (allUOptions.contains(option.getNumber())) {
			return true;
		}
		else return false;
	}
	
	private static boolean processOptionAsE(Option option, OptionSet options, CBORObject[] instructions) {
		if (isClassEOption(option)) {
			return true;
		}
		// did I add OPT to M?
		if (true) { 
			// should be endpoint context check // i.e. add "I sent this request" option
			// or check for every option // i.e. have list of options that it has added

			// is x a consumer of opt?
			return processIsEndpointConsumer(option, options, instructions);
		}
		else return processNotConsumeOption(option, options, instructions);
	}

	private static boolean processIsEndpointConsumer(Option option, OptionSet options, CBORObject[] instructions) {
		boolean instructionsExists = Objects.nonNull(instructions);

		if (instructionsExists) { 
			int index = instructions[1].ToObject(int.class); 
			boolean hasOptions = instructions[index].ContainsKey(6);

			if (hasOptions) { 
				int[] optionArray = instructions[index].get(6).ToObject(int[].class);

				for (int optionNumber : optionArray) {
					if (optionNumber == option.getNumber()) {
						//This class U option is not intended for the current endpoint
						System.out.println("Option " + option + " was not intended");
						return processNotConsumeOption(option, options, instructions);

					}
				}
			}
		}

		System.out.println("Option " + option + " was intended");
		if (processIsNextImmediateConsumer(option, options, instructions)) {
			return processNeedBeforeDecryption(option, options);
		}
		else return false;

	}



	private static boolean processNotConsumeOption(Option option, OptionSet options, CBORObject[] instructions) {

		if (processIsNextHop(option, options, instructions) || !(processIsNextImmediateConsumer(option, options, instructions ))) {
			return processIsOptionURIHostOrURIPort(option, options);
		}
		else return false;
	}

	private static boolean processIsNextHop(Option option, OptionSet options, CBORObject[] instructions) {
		// how to check if as a forward proxy? didn't add option but next might be server.
		if (Objects.nonNull(instructions)) {
			if ((int) instructions[1].ToObject(int.class) == (instructions.length - 2)) {
				return true;
			}
		}
		return false;
	}
	private static boolean processIsNextImmediateConsumer(Option option, OptionSet options, CBORObject[] instructions) {

		boolean instructionsForProxyExists = false;

		if (Objects.nonNull(instructions)) {
			instructionsForProxyExists = ((int) instructions[1].ToObject(int.class) > 2);
		}

		System.out.println("instructions for proxy exists is: " + instructionsForProxyExists);
		if (instructionsForProxyExists) { 
			
			//these are options that has to be consumed by a proxy (if we guess there is one)
			if (proxyConsumeOptions.contains(option.getNumber())) { 
				System.out.println("returning false for optionProxy: " + option);
				return false;
			}
			else return true;

		}
		
		//no instructions = vanilla oscore, do not encrypt U options
		return false;
		/*
		// we believe we are communicating with a server through a proxy
		if (options.hasProxyScheme() || options.hasProxyUri()) {
			// is the option an option that is needed by the proxy that we cannot encrypt
			if (proxyConsumeOptions.contains(option.getNumber())) { 
				System.out.println("vanilla case, not encrypting " + option);
				return false;
			}
		}
		*/

/*
		if (serverConsumeOptions.contains(option.getNumber())) {
			System.out.println("returning true for optionServer: " + option);
			return true;
		}
		else return false;*/

	}

	private static boolean processNeedBeforeDecryption(Option option, OptionSet options) {

		switch (option.getNumber()) {
		case OptionNumberRegistry.OSCORE:
			return false;
		default:
			return processIsOptionURIHostOrURIPort(option, options);
		}
	}

	private static boolean processIsOptionURIHostOrURIPort(Option option, OptionSet options) {

		switch (option.getNumber()) {
		case OptionNumberRegistry.URI_HOST:
		case OptionNumberRegistry.URI_PORT:
			if (options.getProxyScheme() != null
					/*|| options.getProxySchemeNumber() == null*/) {
				return true;
			}
			else return false;
		default:
			return true;
		}
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
				System.out.println("merging E option: " + e + " with U option: " + tmp);
				eOptions.addOption(tmp);
			}
		}
		return eOptions;
	}
}
