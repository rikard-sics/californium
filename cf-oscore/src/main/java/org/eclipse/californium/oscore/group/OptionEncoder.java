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

import java.util.ArrayList;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.elements.util.Bytes;

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
		option.Add(InstructionIDRegistry.PairwiseMode, pairwiseMode);
		option.Add(InstructionIDRegistry.ContextUri, contextUri);
		option.Add(InstructionIDRegistry.KID, rid);

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
		option.Add(InstructionIDRegistry.KID, rid);

		option.Add(InstructionIDRegistry.IDContext, idcontext);

		return option.EncodeToBytes();
	}

	/**
	 * here be Javadoc
	 * @param endpoints ordered array of endpoints
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] options, boolean[][] answers) {
		CBORObject option = CBORObject.NewMap();
		//option.Add(2, contextUri);
		option.Add(InstructionIDRegistry.KID, rid);

		option.Add(InstructionIDRegistry.IDContext, idcontext);

		CBORObject optionsHolder = CBORObject.NewMap();
		
		if (options.length != answers.length) {
			throw new RuntimeException("Unequal amount of options: " + options.length + " and answers: " + answers.length);
		}

		int index = 0;
		for (int o : options) {
			if (answers[index].length != 5) {
				throw new RuntimeException("bad answer array, length should be 5");
			}
			optionsHolder.Add(o,answers[index]);
			index++;
			
		}


		option.Add(InstructionIDRegistry.PreSet, optionsHolder);
		return option.EncodeToBytes();
	}


	public static byte[] set(byte[] rid, byte[] idcontext, int requestSequenceNumber) {

		CBORObject option = CBORObject.NewMap();
		//option.Add(2, contextUri);
		option.Add(InstructionIDRegistry.KID, rid);

		option.Add(InstructionIDRegistry.IDContext, idcontext);


		option.Add(InstructionIDRegistry.RequestSequenceNumber, requestSequenceNumber);

		return option.EncodeToBytes();
	}
	/**
	 * here be Javadoc
	 * @param endpoints ordered array of endpoints
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] optionsPostSet, CBORObject[] values) {
		CBORObject option = CBORObject.NewMap();
		//option.Add(2, contextUri);
		option.Add(InstructionIDRegistry.KID, rid);

		option.Add(InstructionIDRegistry.IDContext, idcontext);

		int index = 0;
		
		CBORObject optionsPostSetHolder = CBORObject.NewMap();
		if (optionsPostSet.length != values.length) {
			//might become more complicated with blockwise, but it's a problem for later
			throw new RuntimeException("Unequal amount of options: " + optionsPostSet.length + " and values: " + values.length);
		}
		
		index = 0;
		for (int o : optionsPostSet) {
			optionsPostSetHolder.Add(o, values[index]);
			index++;
		}
		
		option.Add(InstructionIDRegistry.PostSet, optionsPostSetHolder);
		return option.EncodeToBytes();
	}
	/**
	 * here be Javadoc
	 * @param endpoints ordered array of endpoints
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] optionsPreSet, boolean[][] answers, int[] optionsPostSet, CBORObject[] values) {
		CBORObject option = CBORObject.NewMap();
		//option.Add(2, contextUri);
		option.Add(InstructionIDRegistry.KID, rid);

		option.Add(InstructionIDRegistry.IDContext, idcontext);

		CBORObject optionsPreSetHolder = CBORObject.NewMap();
		
		if (optionsPreSet.length != answers.length) {
			throw new RuntimeException("Unequal amount of options: " + optionsPreSet.length + " and answers: " + answers.length);
		}

		int index = 0;
		for (int o : optionsPreSet) {
			if (answers[index].length != 5) {
				throw new RuntimeException("bad answer array, length should be 5");
			}
			optionsPreSetHolder.Add(o,answers[index]);
			index++;
			
		}

		option.Add(InstructionIDRegistry.PreSet, optionsPreSetHolder);
		
		CBORObject optionsPostSetHolder = CBORObject.NewMap();
		if (optionsPostSet.length != values.length) {
			//might become more complicated with blockwise, but it's a problem for later
			throw new RuntimeException("Unequal amount of options: " + optionsPostSet.length + " and values: " + values.length);
		}
		
		index = 0;
		for (int o : optionsPostSet) {
			optionsPostSetHolder.Add(o, values[index]);
			index++;
		}
		
		option.Add(InstructionIDRegistry.PostSet, optionsPostSetHolder);
		return option.EncodeToBytes();
	}
	/**
	 * here be Javadoc
	 * @param endpoints ordered array of endpoints
	 */
	public static byte[] set(byte[] rid, byte[] idcontext,  int[] optionsPostSet, CBORObject[] values, int requestSequenceNumber) {
		CBORObject option = CBORObject.NewMap();
		//option.Add(2, contextUri);
		option.Add(InstructionIDRegistry.KID, rid);

		option.Add(InstructionIDRegistry.IDContext, idcontext);

		CBORObject optionsHolder = CBORObject.NewMap();
		
		
		CBORObject optionsPostSetHolder = CBORObject.NewMap();
		if (optionsPostSet.length != values.length) {
			//might become more complicated with blockwise, but it's a problem for later
			throw new RuntimeException("Unequal amount of options: " + optionsPostSet.length + " and values: " + values.length);
		}
		
		int index = 0;
		for (int o : optionsPostSet) {
			optionsPostSetHolder.Add(o, values[index]);
			index++;
		}
		
		option.Add(InstructionIDRegistry.PostSet, optionsPostSetHolder);
		option.Add(InstructionIDRegistry.RequestSequenceNumber, requestSequenceNumber);
		return option.EncodeToBytes();
	}
	/**
	 * here be Javadoc
	 * @param endpoints ordered array of endpoints
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] options, boolean[][] answers, int requestSequenceNumber) {
		CBORObject option = CBORObject.NewMap();
		//option.Add(2, contextUri);
		option.Add(InstructionIDRegistry.KID, rid);

		option.Add(InstructionIDRegistry.IDContext, idcontext);

		CBORObject optionsHolder = CBORObject.NewMap();
		
		if (options.length != answers.length) {
			throw new RuntimeException("Unequal amount of options: " + options.length + " and answers: " + answers.length);
		}

		int index = 0;
		for (int o : options) {
			if (answers[index].length != 5) {
				throw new RuntimeException("bad answer array, length should be 5");
			}
			optionsHolder.Add(o,answers[index]);
			index++;
			
		}

		option.Add(InstructionIDRegistry.PreSet, optionsHolder);
		
		option.Add(InstructionIDRegistry.RequestSequenceNumber, requestSequenceNumber);
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
		return option.get(InstructionIDRegistry.PairwiseMode).AsBoolean();
	}

	/**
	 * Get the context URI value from the option.
	 * 
	 * @param optionBytes the option
	 * @return the context uri string
	 */
	public static String getContextUri(byte[] optionBytes) {
		CBORObject option = CBORObject.DecodeFromBytes(optionBytes);
		return option.get(InstructionIDRegistry.ContextUri).AsString();
	}

	/**
	 * Get the RID value from the option.
	 * 
	 * @param optionBytes the option
	 * @return the RID
	 */
	public static byte[] getRID(byte[] optionBytes) {
		CBORObject option = CBORObject.DecodeFromBytes(optionBytes);
		return option.get(InstructionIDRegistry.KID).GetByteString();
	}

	/**
	 * Decodes and returns a CBOR sequence from a provided byte array
	 * this function only ensures that the headers exist and the first instruction is a map
	 * but not if all instructions are maps
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
			if (decodedSequence[0].getType() == CBORType.ByteString  && decodedSequence[1].isNumber() && (decodedSequence[2].getType() == CBORType.Map)) {
				return decodedSequence;
			}
			else return null;
		} catch (Exception e) {
			return null;
		}
	}

	public static boolean[] extractPromotionAnswers(int optionNumber, CBORObject instruction) {

		if (instruction == null) return null;

		try {
			//the instruction is a map
			CBORObject preSet = instruction.get(6);

			if (preSet == null) return null;

			CBORObject booleanArray = preSet.get(optionNumber);

			if (booleanArray == null) return null;
			
			return booleanArray.ToObject(boolean[].class);

		} catch (Exception e) {
			System.out.println(e.getLocalizedMessage());
			// TODO: handle exception
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
			result = Bytes.concatenate(result, object.EncodeToBytes());
		}

		return result;
	}
}
