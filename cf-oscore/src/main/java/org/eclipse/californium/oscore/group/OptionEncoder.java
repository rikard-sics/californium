/*******************************************************************************
 * Copyright (c) 2023 RISE SICS and others.
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

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

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
	 * @return the encode option value
	 */
	public static byte[] set(boolean pairwiseMode, String contextUri, byte[] rid) {
		CBORObject option = CBORObject.NewMap();
		option.Add(1, pairwiseMode);
		option.Add(2, contextUri);
		option.Add(3, rid);

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
	 * here be Javadoc
	 * @param endpoints ordered array of endpoints
	 */
	public static byte[] set(byte[] rid, byte[] idcontext) {
		
		CBORObject option = CBORObject.NewMap();
		//option.Add(2, contextUri);
		option.Add(3, rid);
		
		option.Add(5, idcontext);

		return option.EncodeToBytes();
	}
	
	/**
	 * here be Javadoc
	 * @param endpoints ordered array of endpoints
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] options) {
		
		CBORObject option = CBORObject.NewMap();
		//option.Add(2, contextUri);
		option.Add(3, rid);
		
		option.Add(5, idcontext);
		
		// calculate delta later as optimization
		CBORObject optionsHolder = CBORObject.NewArray();
		for (int opt : options) {
			
			optionsHolder.Add(opt);
		}
		option.Add(6, optionsHolder);
		return option.EncodeToBytes();
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
	 * Decodes and returns a CBOR sequence from a provided byte array
	 * @param sequenceBytes the byte array containing a CBOR sequence 
	 * @return the CBOR sequence, or null if the byte array is null or it is an invalid CBOR sequence
	 */
	public static CBORObject[] decodeCBORSequence(byte[] sequenceBytes) {
		if (sequenceBytes == null) {
			return null;
		}

		try {
			CBORObject[] decodedSequence = CBORObject.DecodeSequenceFromBytes(sequenceBytes);
			if (decodedSequence.length < 2 ) {
				return null;
			}
			if (decodedSequence[1].isNumber() && (decodedSequence[2].getType() == CBORType.Map)) {
				return decodedSequence;
			}
			else return null;
		} catch (com.upokecenter.cbor.CBORException e) {
			System.out.println("Decode CBORSequence Threw error: " + e.getLocalizedMessage());
			return null;
		}
		catch (java.lang.ArrayIndexOutOfBoundsException e) {
			System.out.println("Decode CBORSequence Threw error: " + e.getLocalizedMessage());
			return null;
		}
	}
	
	/**
	 * Encodes a CBOR sequence into a byte array
	 * @param instructions CBOR sequence to be encoded
	 * @return byte array containing the encoded CBOR sequence
	 */
	public static byte[] encodeSequence(CBORObject[] CBORSequence) {
		byte[] result = new byte[0];
		for (CBORObject object : CBORSequence) {
			result = OptionEncoder.combine(result, object.EncodeToBytes());
		}
		
		return result;
	}
	
	/**
	 * Appends the append byte array to the src byte array
	 * @param src byte array to be appended
	 * @param append byte array to append
	 * @return src byte array appended with append byte array
	 */
	public static byte[] combine(byte[] src, byte[] append) {
		byte[] result = new byte[src.length + append.length];
		System.arraycopy(src, 0, result, 0, src.length);
		System.arraycopy(append, 0, result, src.length, append.length);
		return result;
	}
}
