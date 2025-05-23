/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

import org.apache.hc.client5.http.utils.Hex;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.InstructionIDRegistry;
import org.eclipse.californium.oscore.group.OptionEncoder;


/**
 * 
 * Implements the OSCoreCtxDB interface with HashMaps.
 *
 */
public class HashMapCtxDB implements OSCoreCtxDB {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(HashMapCtxDB.class);

	// The outer HashMap has RID as key and the inner ID Context
	private HashMap<ByteId, HashMap<ByteId, OSCoreCtx>> contextMap;

	private HashMap<Token, OSCoreCtx> tokenMap;
	private HashMap<String, OSCoreCtx> uriMap;
	private HashMap<Token, CBORObject[]> instructionMap;
	private ArrayList<Token> forwardedWithoutProtection;
	private ArrayList<Token> forwardedWithProtection;
	private ArrayList<Token> allTokens;
	private boolean proxyable;

	/**
	 * Create the database, with no proxying allowed
	 */
	public HashMapCtxDB() {
		this(false);
		/*
		this.tokenMap = new HashMap<>();
		this.contextMap = new HashMap<>();
		this.uriMap = new HashMap<>();
		this.instructionMap = new HashMap<>();
		this.forwardedWithoutProtection = new ArrayList<Token>();
		this.allTokens = new ArrayList<Token>();*/
	}

	/**
	 * Create the database
	 * @param proxyable This controls whether the server can act as a proxy
	 */
	public HashMapCtxDB(boolean proxyable) {

		this.tokenMap = new HashMap<>();
		this.contextMap = new HashMap<>();
		this.uriMap = new HashMap<>();
		this.instructionMap = new HashMap<>();
		this.forwardedWithoutProtection = new ArrayList<Token>();
		this.forwardedWithProtection = new ArrayList<Token>();
		this.allTokens = new ArrayList<Token>();
		this.proxyable = proxyable;
	}

	@Override
	public synchronized void removeInstructions(Token token) {
		if (token != null) {
			instructionMap.remove(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}
	@Override
	public synchronized boolean getIfProxyable() {
		return this.proxyable;
	}

	@Override
	public synchronized void size() {
		System.out.println("Context map is size: " + contextMap.size());
		System.out.println("Token map is size;   " + tokenMap.size());
		System.out.println("instruction map is size: " + instructionMap.size());
		System.out.println("forwarded array list is size: " + forwardedWithoutProtection.size());
	}

	@Override
	public synchronized void addForwarded(Token token) {
		if (token != null) {
			if (!tokenExist(token)) {
				allTokens.add(token);
			}
			forwardedWithoutProtection.add(token);	
		}
	}

	@Override
	public synchronized boolean hasBeenForwarded(Token token) {
		if (token != null) {
			return forwardedWithoutProtection.contains(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}

	@Override
	public synchronized void addInstructions(Token token, CBORObject[] instructions) {
		if (token != null) {
			if (instructions != null) {
				if (!tokenExist(token)) {
					allTokens.add(token);
				}

				instructionMap.put(token, instructions);
			}
			else {
				LOGGER.error("Instruction is null");
				throw new NullPointerException("Instruction is null");
			}
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}

	/**
	 * 
	 */
	@Override
	public synchronized CBORObject[] getInstructions(Token token) {
		if (token != null) {
			return instructionMap.get(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}
	/**
	 * Retrieve context using a request. If the provided request has 
	 * instructions in the OSCORE option, the context will be returned
	 * from the current instruction, otherwise it will return the 
	 * context using the URI or ProxyUri
	 */
	@Override
	public synchronized OSCoreCtx getContext(Request request, CBORObject[] instructions) throws OSException {
		if (!(Objects.nonNull(instructions))) { 
			String uri; 
			if (request.getOptions().hasProxyUri()) {
				uri = request.getOptions().getProxyUri();
			} else {
				uri = request.getURI();
			}

			if (uri == null) {
				LOGGER.error(ErrorDescriptions.URI_NULL);
				throw new OSException(ErrorDescriptions.URI_NULL);
			}
			return getContext(uri);
		}

		// get index for current instruction
		int index = instructions[InstructionIDRegistry.Header.Index].ToObject(int.class);

		// get instruction
		CBORObject instruction = instructions[index];

		byte[] RID       = instruction.get(InstructionIDRegistry.KID).ToObject(byte[].class);
		byte[] IDCONTEXT = instruction.get(InstructionIDRegistry.IDContext).ToObject(byte[].class);

		return getContext(RID, IDCONTEXT);
	}

	/**
	 * Retrieve context using RID and ID Context. If the provided ID Context is
	 * null a result will be returned if there is only one unique context for
	 * that RID.
	 */
	@Override
	public synchronized OSCoreCtx getContext(byte[] rid, byte[] IDContext) throws CoapOSException {
		// Do not allow a null RID
		if (rid == null) {
			LOGGER.error(ErrorDescriptions.MISSING_KID);
			throw new CoapOSException(ErrorDescriptions.MISSING_KID, ResponseCode.UNAUTHORIZED);
		}

		HashMap<ByteId, OSCoreCtx> matchingRidMap = contextMap.get(new ByteId(rid));

		// No matching RID found at all
		if (matchingRidMap == null) {
			return null;
		}

		// If a RID was found get the specific context
		if (IDContext == null) {
			// If retrieving using only RID, there must be only 1 match maximum
			if (matchingRidMap.size() > 1) {
				throw new CoapOSException(ErrorDescriptions.CONTEXT_NOT_FOUND_IDCONTEXT, ResponseCode.UNAUTHORIZED);
			} else {
				// If only one entry return it
				Map.Entry<ByteId, OSCoreCtx> first = matchingRidMap.entrySet().iterator().next();
				return first.getValue();
			}

		} else {
			// If retrieving using both RID and ID Context
			return matchingRidMap.get(new ByteId(IDContext));
		}
	}

	/**
	 * Retrieve context using only RID when it is certain it is unique.
	 */
	@Override
	public synchronized OSCoreCtx getContext(byte[] rid) {
		HashMap<ByteId, OSCoreCtx> matchingRidMap = contextMap.get(new ByteId(rid));

		if (matchingRidMap == null) {
			return null;
		}

		if (matchingRidMap.size() > 1) {
			throw new RuntimeException("Attempting to retrieve context with only non-unique RID.");
		}

		Map.Entry<ByteId, OSCoreCtx> first = matchingRidMap.entrySet().iterator().next();
		return first.getValue();
	}

	@Override
	public synchronized OSCoreCtx getContextByToken(Token token) {
		if (token != null) {
			return tokenMap.get(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}

	@Override
	public synchronized OSCoreCtx getContext(String uri) throws OSException {
		if (uri != null) {
			return uriMap.get(normalizeServerUri(uri));
		} else {
			LOGGER.error(ErrorDescriptions.STRING_NULL);
			throw new NullPointerException(ErrorDescriptions.STRING_NULL);
		}
	}

	@Override
	public synchronized void addContext(Token token, OSCoreCtx ctx) {
		if (token != null) {
			if (!tokenExist(token)) {
				allTokens.add(token);
			}
			tokenMap.put(token, ctx);
		}
		if (ctx != null) {
			addContext(ctx);
		}
	}

	@Override
	public synchronized void addContext(String uri, OSCoreCtx ctx) throws OSException {
		if (uri != null) {
			String normalizedUri = normalizeServerUri(uri);
			uriMap.put(normalizedUri, ctx);
			ctx.setUri(normalizedUri);
		}
		addContext(ctx);
	}

	@Override
	public synchronized void addContext(OSCoreCtx ctx) {
		if (ctx != null) {

			ByteId rid = new ByteId(ctx.getRecipientId());
			HashMap<ByteId, OSCoreCtx> ridMap = contextMap.get(rid);

			// If there is no existing map for this RID, create it
			if (ridMap == null) {
				ridMap = new HashMap<ByteId, OSCoreCtx>();
			}

			// Add the context to the RID map with ID context as key
			byte[] IDContext = ctx.getIdContext();
			if (IDContext == null) {
				IDContext = Bytes.EMPTY;
			}
			ridMap.put(new ByteId(IDContext), ctx);

			// Put the updated map for this RID in the context map
			contextMap.put(rid, ridMap);

		} else {
			LOGGER.error(ErrorDescriptions.CONTEXT_NULL);
			throw new NullPointerException(ErrorDescriptions.CONTEXT_NULL);
		}
	}

	@Override
	public synchronized void removeContext(OSCoreCtx ctx) {
		if (ctx != null) {

			ByteId rid = new ByteId(ctx.getRecipientId());
			HashMap<ByteId, OSCoreCtx> ridMap = contextMap.get(rid);

			// If there is no existing map for this RID return
			if (ridMap == null) {
				return;
			}

			// Remove the context from the RID map with ID context as key
			byte[] IDContext = ctx.getIdContext();
			if (IDContext == null) {
				IDContext = Bytes.EMPTY;
			}
			ridMap.remove(new ByteId(IDContext));

			if (ridMap.isEmpty()) {
				// If the RID map is now empty, remove it
				contextMap.remove(rid);
			} else {

				// Put the updated map for this RID in the context map
				contextMap.put(rid, ridMap);
			}

		} else {
			LOGGER.error(ErrorDescriptions.CONTEXT_NULL);
			throw new NullPointerException(ErrorDescriptions.CONTEXT_NULL);
		}
	}

	@Override
	public synchronized boolean tokenExist(Token token) {
		if (token != null) {
			return allTokens.contains(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}

	@Override
	public synchronized boolean instructionsExistForToken(Token token) {
		if (token != null) {
			return instructionMap.containsKey(token);
		} else {
			LOGGER.error(ErrorDescriptions.TOKEN_NULL);
			throw new NullPointerException(ErrorDescriptions.TOKEN_NULL);
		}
	}

	/**
	 * Normalize the request uri.
	 * 
	 * @param uri the request uri
	 * @return the normalized uri
	 *
	 * @throws OSException on failure to parse the URI
	 */
	private static String normalizeServerUri(String uri) throws OSException {
		String normalized = null;
		int port = -1;

		try {
			URI serverUri = new URI(uri);
			port = serverUri.getPort();
			normalized = serverUri.getHost();
		} catch (URISyntaxException e) {
			// workaround for openjdk bug JDK-8199396.
			// some characters are not supported for the ipv6 scope.
			try {
				String patternString = "(%.*)]";
				Pattern pattern = Pattern.compile(patternString);

				//Save the original scope
				Matcher matcher = pattern.matcher(uri);
				String originalScope = null;
				if (matcher.find()) {
					originalScope = matcher.group(1);
				}

				//Remove unsupported characters in scope before getting the host component
				normalized = (new URI(uri.replaceAll("[-._~]", ""))).getHost();

				//Find the modified new scope
				matcher = pattern.matcher(normalized);
				String newScope = null;
				if (matcher.find()) {
					newScope = matcher.group(1);
				}

				//Restore original scope for the IPv6 normalization
				//Otherwise getByName below will fail with "no such interface"
				//Since the scope is no longer matching the interface
				if (newScope != null && originalScope != null) {
					normalized = normalized.replace(newScope, originalScope);
				}

			} catch (URISyntaxException e2) {
				LOGGER.error("Error in the request URI: {} message: {}", uri, e.getMessage());
				throw new OSException(e.getMessage());
			}
		}

		//Further normalization for IPv6 addresses
		//Normalization above can give different results depending on structure of IPv6 address
		InetAddress ipv6Addr = null;
		try {
			ipv6Addr = InetAddress.getByName(normalized);
		} catch (UnknownHostException e) {
			LOGGER.error("Error finding host of request URI: {} message: {}", uri, e.getMessage());
		}
		if (ipv6Addr instanceof Inet6Address) {
			normalized = "[" + ipv6Addr.getHostAddress() + "]";
		}

		// Consider port, if not default
		if (port != -1 && port != CoAP.DEFAULT_COAP_PORT) {
			normalized = normalized + ":" + port;
		}

		return normalized;
	}

	/**
	 * Removes associations for this token, except for the generator
	 * 
	 * @param token the token to remove
	 */
	@Override
	public synchronized void removeToken(Token token) {
		tokenMap.remove(token);
		instructionMap.remove(token); //maybe
		forwardedWithoutProtection.remove(token); // might not work, curse Bytes
	}

	/**
	 * Used mainly for test purpose, to purge the db of all contexts
	 */
	@Override
	public synchronized void purge() {
		contextMap.clear();
		tokenMap.clear();
		instructionMap.clear();
		uriMap.clear();
		allTokens = new ArrayList<Token>();
	}
}
