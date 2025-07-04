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
import java.util.Arrays;
import java.util.Collection;
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
import org.eclipse.californium.core.coap.option.OpaqueOption;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.option.StringOption;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.InstructionIDRegistry;
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

	public static boolean hasProxyRelatedOptions(OptionSet options) {
		if (hasProxySchemeAndUri(options) 
				|| options.hasProxyUri()
				/*|| options.hasProxyCri()*/
				|| hasUriPathHostPort(options)) {
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

	public static boolean hasProxySchemeAndUri(OptionSet options) {
		if ((options.hasProxyScheme() /* || options.hasProxySchemeNumber()*/) && 
				(options.hasUriHost() || options.hasUriPort())) {
			return true;
		}
		else return false;
	}

	public static boolean hasUriPathHostPort(OptionSet options) {
		if (options.hasUriHost() || options.hasUriPort() || options.getURIPathCount() > 0) {
			return true;
		}
		else return false;
	}

	public static OptionSet postInstruction(OptionSet uOptions, CBORObject[] instructions) {
		boolean instructionsExists = Objects.nonNull(instructions);

		if (!instructionsExists) return uOptions;

		CBORObject instruction = null;
		int index = -1;

		if (instructionsExists) { 
			index = instructions[1].ToObject(int.class);
			instruction = instructions[index];
		}

		CBORObject postSet = instruction.get(InstructionIDRegistry.PostSet);

		if (postSet == null) return uOptions;

		if (postSet.size() == 0) return uOptions;

		Collection<CBORObject> collection = postSet.getKeys();

		for (CBORObject key : collection) {

			int optionNumber = key.ToObject(int.class);
			// get encoded value(s)
			CBORObject values = postSet.get(optionNumber);

			switch (optionNumber) {
			case OptionNumberRegistry.URI_HOST:
				// check if it already exists as a uOption
				if (uOptions.hasUriHost()) {
					// if it does, runtimeException
					throw new RuntimeException("Option to be added already exists as an option in the message!");
				}

				// put in variable
				String uriHost = values.ToObject(String.class);

				// if outer only, add to pre encryption set (if it exists) 
				//addToPreEncryptionSet(index, instructions, optionNumber);

				// set post instruction
				uOptions.setUriHost(uriHost);

				break;
			case OptionNumberRegistry.OBSERVE:
				// check if it already exists as a uOption
				if (uOptions.hasObserve()) {
					// if it does, runtimeException
					throw new RuntimeException("Option to be added already exists as an option in the message!");
				}

				// put in variable
				int sequenceNumber = values.ToObject(int.class);	

				// set post instruction
				uOptions.setObserve(sequenceNumber);

				break;
			case OptionNumberRegistry.URI_PORT:
				// check if it already exists as a uOption
				if (uOptions.hasUriPort()) {
					// if it does, runtimeException
					throw new RuntimeException("Option to be added already exists as an option in the message!");
				}

				// put in variable
				int port = values.ToObject(int.class);

				// if outer only, add to pre encryption set (if it exists) 
				//addToPreEncryptionSet(index, instructions, optionNumber);

				// set post instruction
				uOptions.setUriPort(port);

				break;
			case OptionNumberRegistry.OSCORE:
				throw new IllegalArgumentException("OSCORE is not allowed as an option in the post-set!");

			case OptionNumberRegistry.MAX_AGE:

				// check if it already exists as a uOption
				if (uOptions.hasMaxAge()) {
					// if it does, runtimeException
					throw new RuntimeException("Option to be added already exists as an option in the message!");
				}

				// put in variable
				long age = values.ToObject(long.class);

				// set post instruction
				uOptions.setMaxAge(age);
				break;
			case OptionNumberRegistry.BLOCK2:
				// TODO: implement
				throw new IllegalArgumentException("Option not yet implemented");
				//break;
			case OptionNumberRegistry.BLOCK1:
				// TODO: implement
				throw new IllegalArgumentException("Option not yet implemented");
				//break;
			case OptionNumberRegistry.SIZE2:
				// TODO: implement
				throw new IllegalArgumentException("Option not yet implemented");
				//break;
			case OptionNumberRegistry.SIZE1:
				// TODO: implement
				throw new IllegalArgumentException("Option not yet implemented");
				//break;
			case OptionNumberRegistry.PROXY_URI:

				break;
			case OptionNumberRegistry.PROXY_SCHEME:
				// check if it already exists as a uOption
				if (uOptions.hasProxyScheme()) {
					// if it does, runtimeException
					throw new RuntimeException("Option to be added already exists as an option in the message!");
				}

				// put in variable
				String proxyScheme = values.ToObject(String.class);

				// if outer only, add to pre encryption set (if it exists) 
				//addToPreEncryptionSet(index, instructions, optionNumber);

				// set post instruction
				uOptions.setProxyScheme(proxyScheme);

				break;

			case OptionNumberRegistry.NO_RESPONSE:
				// check if it already exists as a uOption
				if (uOptions.hasNoResponse()) {
					// if it does, runtimeException
					throw new RuntimeException("Option to be added already exists as an option in the message!");
				}

				// put in variable
				int noResponse = values.ToObject(int.class);

				// set post instruction
				uOptions.setNoResponse(noResponse);
				break;
			default:
				throw new IllegalArgumentException("Option is not class U or unrecognized");
			}
		}

		return uOptions;

	}
	public static OptionSet promotion(OptionSet options, boolean isResponse, CBORObject[] instructions) {
		OptionSet result = new OptionSet();
		boolean includes = false;
		boolean instructionsExists = Objects.nonNull(instructions);
		CBORObject instruction = null;
		int index = -1;
		int toTouch = 0;
		int timesTouched = 0;
		
		if (options.hasProxyScheme() /* || options.hasProxySchemeNumber()*/) {
			includes = true;
		}

		if (instructionsExists) { 
			index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);
			instruction = instructions[index];

			CBORObject preSet = instruction.get(InstructionIDRegistry.PreSet);
			if (preSet != null) {
				toTouch = instruction.get(InstructionIDRegistry.PreSet).size();
			}
		}

		for (Option o : options.asSortedList()) {

			switch (o.getNumber()) {
			/* Class U ONLY options */
			case OptionNumberRegistry.OSCORE:
				/* 
				 * Always promote the OSCORE option if it is a response
				 * the logic for when not to encrypt a response is in 
				 * the ObjectSecurityLayer, before calling prepareResponse
				 */
				if (isResponse || !Arrays.equals(((OpaqueOption) o).getValue(), Bytes.EMPTY)) {
					result.addOption(o);
					options.removeOscore();
					break;
				}
			case OptionNumberRegistry.URI_HOST:
			case OptionNumberRegistry.URI_PORT:
			case OptionNumberRegistry.PROXY_SCHEME:
			case OptionNumberRegistry.PROXY_URI:
				// Does it have instructions?
				if (instructionsExists)  {
					boolean[] promotionAnswers = OptionEncoder.extractPromotionAnswers(o.getNumber(), instruction);

					boolean promoted = false;
					if (promotionAnswers != null) {
						promoted = processPromotion(o, promotionAnswers, includes);
						timesTouched++;
					}

					if (promoted) {
						result.addOption(o);
						switch (o.getNumber()) {
						case OptionNumberRegistry.URI_HOST:
							options.removeUriHost();
							break;
						case OptionNumberRegistry.URI_PORT:
							options.removeUriPort();
							break;
						case OptionNumberRegistry.PROXY_SCHEME:
							options.removeProxyScheme();
							break;
						case OptionNumberRegistry.PROXY_URI:
							options.removeProxyUri();
							break;
						}
						break;
					}
					// keep as is if not promoted, i.e. Class U
				}
				else {
					// if no instructions, the default is to keep the option as Class U
				}

			default:
				/* 
				 * do nothing for options that are both Class U and E 
				 * these are already handled in filterOptions
				 * perhaps use this as a way to have inner only max-age and observe?
				 */
				break;
			}
		}

		if (toTouch > timesTouched) {
			throw new RuntimeException("Not all pre set instructions were used");
		}
		else if (toTouch < timesTouched) {
			throw new RuntimeException("There are pre set instructions that are unused");
			// likely because the option for the instruction is not present
		}

		return result;
	}

	/**
	 * Filters all options into Class U and/or E
	 * @param options set of options to be filtered
	 * @return 
	 */
	public static OptionSet[] filterOptions(OptionSet options) {
		OptionSet[] result = {
				new OptionSet(), // Class U options
				new OptionSet()  // Class E options
		};

		for (Option o : options.asSortedList()) {

			switch (o.getNumber()) {
			/* Class U ONLY options*/
			case OptionNumberRegistry.OSCORE:
			case OptionNumberRegistry.URI_HOST:
			case OptionNumberRegistry.URI_PORT:
			case OptionNumberRegistry.PROXY_SCHEME:
				// do not encrypt
				result[0].addOption(o);
				break;
			case OptionNumberRegistry.PROXY_URI:

				OptionSet proxyURIOptions = handleProxyURI(o);
				// create Uri-Path and Uri-Query and add to Class E options
				// add proxy-uri to Class U options
				if (proxyURIOptions.getURIPathCount() > 0) {
					result[1].setUriPath(proxyURIOptions.getUriPathString());
				}
				if (proxyURIOptions.getURIQueryCount() > 0) {
					result[1].setUriQuery(proxyURIOptions.getUriQueryString());
				}
				if (proxyURIOptions.hasProxyUri()) {
					result[0].setProxyUri(proxyURIOptions.getProxyUri());
				}
				break;
				/* Class U and E options */
			case OptionNumberRegistry.OBSERVE:
				result[0].addOption(o);
				result[1].addOption(o);
				break;
			case OptionNumberRegistry.MAX_AGE:
				// create outer max age option that is 0, and keep inner the same
				result[0].addOption(StandardOptionRegistry.MAX_AGE.create(0));
				result[1].addOption(o);
				break;
				/* Class E options*/
			default: 
				result[1].addOption(o);
			}
		}
		return result;
	}

	public static OptionSet handleProxyURIInstruction(OptionSet options, CBORObject[] instructions) {
		if (Objects.nonNull(instructions)) {
			int index = instructions[1].ToObject(int.class);
			CBORObject instruction = instructions[index];

			CBORObject postSet = instruction.get(InstructionIDRegistry.PostSet);

			if (postSet == null || postSet.size() == 0) return options;

			CBORObject value = postSet.get(StandardOptionRegistry.PROXY_URI.getNumber());

			if (value == null) return options;

			String proxyUri = value.ToObject(String.class);

			Option option = StandardOptionRegistry.PROXY_URI.create(proxyUri);

			OptionSet proxyURIOptions = handleProxyURI(option);

			// create Uri-Path and Uri-Query and add to Class E options
			// add proxy-uri to Class U options

			if (proxyURIOptions.getURIPathCount() > 0 && options.getURIPathCount() > 0) {
				throw new RuntimeException("Tried to add Uri-Path option through Proxy-Uri, but it already exists as an option in the message!");
			}
			else if (proxyURIOptions.getURIPathCount() > 0) {
				options.setUriPath(proxyURIOptions.getUriPathString());
			}

			if (proxyURIOptions.getURIQueryCount() > 0 && options.getURIQueryCount() > 0) {
				throw new RuntimeException("Tried to add Uri-Query option through Proxy-Uri, but it already exists as an option in the message!");
			}
			else if (proxyURIOptions.getURIQueryCount() > 0) { 
				options.setUriQuery(proxyURIOptions.getUriQueryString());
			}

			if (options.hasProxyUri() && proxyURIOptions.hasProxyUri()) {
				throw new RuntimeException("Option to be added already exists as an option in the message!");
			}
			else if (proxyURIOptions.hasProxyUri()) {
				options.setProxyUri(proxyURIOptions.getProxyUri());
			}
		}
		return options;
	}

	public static OptionSet handleProxyURI(Option option) {
		OptionSet result = new OptionSet();
		String EProxyUri = ((StringOption)option).getStringValue();
		String UProxyUri = EProxyUri;

		EProxyUri = EProxyUri.replace("coap://", "");
		EProxyUri = EProxyUri.replace("coaps://", "");

		int i = EProxyUri.indexOf('/');
		boolean hasPathOrQuery = false;
		if (i >= 0) {
			hasPathOrQuery = true;

			UProxyUri = EProxyUri.substring(0, i);
			EProxyUri = EProxyUri.substring(i + 1, EProxyUri.length());
		} 
		if (!UProxyUri.contains("coap://") && !UProxyUri.contains("coaps://")) {
			UProxyUri = "coap://" + UProxyUri;
		}
		result.setProxyUri(UProxyUri);

		if (!hasPathOrQuery) {
			return result;
		}

		i = EProxyUri.indexOf("?");
		String uriPath = EProxyUri;
		String uriQuery = null;
		if (i >= 0) {
			uriPath = EProxyUri.substring(0, i);
			uriQuery = EProxyUri.substring(i + 1, EProxyUri.length());
		}

		if (uriPath != null) {
			result.setUriPath(uriPath);
		}

		if (uriQuery != null) {
			String[] uriQueries = uriQuery.split("&");
			for (int idx = 0; idx < uriQueries.length; idx++) {
				result.setUriQuery(uriQueries[idx]);
			}
		}
		return result;
	}
	/**
	 * Prepare a set or original CoAP options for unprotected use with OSCore.
	 * 
	 * @param options the original options
	 * 
	 * @return the OSCore-U option set
	 */
	// needed for tests
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
	// needed for tests
	public static OptionSet prepareEoptions(OptionSet options) {
		OptionSet ret = new OptionSet();


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
				ret.addOption(o);

			}

		}

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

	private static boolean processPromotion(Option option, boolean[] answers, boolean includes) {
		// did I add OPT to M?
		if (answers[0]) { 
			// is x a consumer of opt?
			return processIsXConsumer(option, answers, includes);
		}
		else return processIsXNextHopOrNotImmediateNextConsumer(option, answers, includes);
	}

	private static boolean processIsXConsumer(Option option, boolean[] answers, boolean includes) {
		// is x a consumer of opt?
		if (answers[1]) {
			return processIsXNextImmediateNextConsumer(option, answers, includes);
		}
		else {
			return processIsXNextHopOrNotImmediateNextConsumer(option, answers, includes);
		}
	}
	private static boolean processIsXNextHopOrNotImmediateNextConsumer(Option option, boolean[] answers, boolean includes) {
		// is x my next hop OR is next hop not the immediate consumer of the option
		if (answers[3]) {
			return processIsOptionURIHostOrURIPort(option, answers, includes);
		}
		else return false;
	}



	private static boolean processIsXNextImmediateNextConsumer(Option option, boolean[] answers, boolean includes) {
		// is x the immediate consumer of the option
		if (answers[2]) { 
			return processXNeedBeforeDecryption(option, answers, includes);
		}
		else return false;


	}

	private static boolean processXNeedBeforeDecryption(Option option, boolean[] answers, boolean includes) {

		if (answers[4]) {
			return false;
		}
		else {
			return processIsOptionURIHostOrURIPort(option, answers, includes);
		}
	}

	private static boolean processIsOptionURIHostOrURIPort(Option option, boolean[] answers, boolean includes) {

		switch (option.getNumber()) {
		case OptionNumberRegistry.URI_HOST:
		case OptionNumberRegistry.URI_PORT:
			return processMIncludeProxySchemeOrProxySchemeNumber(option, answers, includes);
		default:
			return true;
		}
	}

	private static boolean processMIncludeProxySchemeOrProxySchemeNumber(Option option, boolean[] answers, boolean includes) {
		if (includes) {
			return true;
		}
		else {
			return false;
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
				eOptions.addOption(tmp);
			}
		}
		return eOptions;
	}
}
