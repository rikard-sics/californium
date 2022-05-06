/*******************************************************************************
 * Copyright (c) 2020 RISE SICS and others.
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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore.group;

import com.upokecenter.cbor.CBORObject;

/**
 * Class that allows an application to set the OSCORE option in a convenient way
 * to indicate various options about the outgoing request.
 * 
 * The value in the option here is only used for internal communication in the
 * implementation.
 * 
 * 
 * Empty OSCORE option:
 * 
 * Works as before where the context is retrieved using the URI in the request.
 * 
 * 
 * Non-empty OSCORE option:
 * 
 * The option is decoded to extract the following 3 parameters. Pairwise mode
 * used, URI of the associated Sender Context, and RID of the recipient (from
 * the Sender's point of view).
 * 
 * The URI in the option is then used to retrieve the context.
 * 
 */
public class OptionEncoder {


	/**
	 * Generate an OSCORE option using parameters from the application.
	 * 
	 * @param pairwiseMode if pairwise mode is used
	 * @param contextUri the uri associated with the sender context to use
	 * @param rid the RID (KID) of the receiver
	 * @param detReq set to true if the client is sending a deterministic request
	 * @return the encode option value
	 */
	public static byte[] set(boolean pairwiseMode, String contextUri, byte[] rid, boolean detReq) {
		CBORObject option = CBORObject.NewMap();
		option.Add(1, pairwiseMode);
		option.Add(2, contextUri);
		option.Add(3, rid);
		option.Add(4, detReq);

		return option.EncodeToBytes();
	}

	/**
	 * Generate an OSCORE option using parameters from the application.
	 * 
	 * @param pairwiseMode if pairwise mode is used
	 * @param contextUri the uri associated with the sender context to use
	 * @param rid the RID (KID) of the receiver
	 * @return the encode option value
	 */
	public static byte[] set(boolean pairwiseMode, String contextUri, byte[] rid) {
		CBORObject option = CBORObject.NewMap();
		option.Add(1, pairwiseMode);
		option.Add(2, contextUri);
		option.Add(3, rid);
		option.Add(4, false);

		return option.EncodeToBytes();
	}

	/**
	 * Generate an OSCORE option using parameters from the application. Skips
	 * setting the rid in case it is a group mode request.
	 * 
	 * @param pairwiseMode if pairwise mode is used
	 * @param contextUri the uri associated with the sender context to use
	 * @return the encode option value
	 */
	public static byte[] set(boolean pairwiseMode, String contextUri) {
		return set(pairwiseMode, contextUri, null);
	}
	
	/**
	 * Get the pairwise mode boolean value from the option.
	 * 
	 * @param optionBytes the option
	 * @return if pairwise mode is to be used
	 */
	public static boolean getPairwiseMode(byte[] optionBytes) {
		if (optionBytes == null || optionBytes.length == 0) {
			return false;
		}

		CBORObject option = CBORObject.DecodeFromBytes(optionBytes);
		return option.get(1).AsBoolean();
	}

	/**
	 * Get the context URI value from the option.
	 * 
	 * @param optionBytes the option
	 * @return the context uri string
	 */
	public static String getContextUri(byte[] optionBytes) {
		CBORObject option = CBORObject.DecodeFromBytes(optionBytes);
		return option.get(2).AsString();
	}

	/**
	 * Get the RID value from the option.
	 * 
	 * @param optionBytes the option
	 * @return the RID
	 */
	public static byte[] getRID(byte[] optionBytes) {
		CBORObject option = CBORObject.DecodeFromBytes(optionBytes);
		return option.get(3).GetByteString();
	}
	
	/**
	 * Get the detReq value from the option.
	 * 
	 * @param optionBytes the option
	 * @return the value of the detReq; if true, the client is sending a deterministic request
	 */
	public static boolean getDetReq(byte[] optionBytes) {
		if (optionBytes == null || optionBytes.length == 0) {
			return false;
		}
		
		CBORObject option = CBORObject.DecodeFromBytes(optionBytes);
		return (option.get(4).AsBoolean());
	}

}
