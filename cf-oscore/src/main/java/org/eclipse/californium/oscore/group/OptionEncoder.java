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
	 * Set the instruction
	 * @param rid the RID (KID) of the receiver
	 * @param idcontext the ID Context of the receiver
	 * @return the encode option value
	 */
	public static byte[] set(byte[] rid, byte[] idcontext) {
		return set(rid, idcontext, null, null, null, null, -1, false);
	}

	/**
	 * Set the instruction
	 * @param rid the RID (KID) of the receiver
	 * @param idcontext the ID Context of the receiver
	 * @param requestSequenceNumber the request sequence number of message
	 * @return the encode option value
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int requestSequenceNumber) {
		return set(rid, idcontext, null, null, null, null, requestSequenceNumber, false);
	}

	/**
	 * Set the instruction
	 * @param rid the RID (KID) of the receiver
	 * @param idcontext the ID Context of the receiver
	 * @param optionsPreSet the set of options which have instructions
	 * 						for if they should be encrypted or not
	 * @param answers answers for the set of options for if they
	 * 				  should be encrypted or not
	 * @return the encode option value
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] optionsPreSet, boolean[][] answers) {
		return set(rid, idcontext, optionsPreSet, answers, null, null, -1, false);
	}

	/**
	 * Set the instruction
	 * @param rid the RID (KID) of the receiver
	 * @param idcontext the ID Context of the receiver
	 * @param optionsPreSet the set of options which have instructions
	 * 						for if they should be encrypted or not
	 * @param answers answers for the set of options for if they
	 * 				  should be encrypted or not
	 * @param requestSequenceNumber the request sequence number of message
	 * @return the encode option value
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] optionsPreSet, boolean[][] answers, int requestSequenceNumber) {
		return set(rid, idcontext, optionsPreSet, answers, null, null, requestSequenceNumber, false);
	}

	public static byte[] set(byte[] rid, byte[] idcontext, int[] optionsPreSet, boolean[][] answers, boolean breaker) {
		return set(rid, idcontext, optionsPreSet, answers, null, null, -1, breaker);
	}

	/**
	 * Set the instruction
	 * @param rid the RID (KID) of the receiver
	 * @param idcontext the ID Context of the receiver
	 * @param optionsPostSet the set of options to add after encryption
	 * @param values the value of the option to add after encryption
	 * @return the encode option value
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] optionsPostSet, CBORObject[] values) {
		return set(rid, idcontext, null, null, optionsPostSet, values, -1, false);
	}

	/**
	 * Set the instruction
	 * @param rid the RID (KID) of the receiver
	 * @param idcontext the ID Context of the receiver
	 * @param optionsPostSet the set of options to add after encryption
	 * @param values the value of the option to add after encryption
	 * @param requestSequenceNumber the request sequence number of message
	 * @return the encode option value
	 */
	public static byte[] set(byte[] rid, byte[] idcontext,  int[] optionsPostSet, CBORObject[] values, int requestSequenceNumber) {
		return set(rid, idcontext, null, null, optionsPostSet, values, requestSequenceNumber, false);
	}
	
	public static byte[] set(byte[] rid, byte[] idcontext,  int[] optionsPostSet, CBORObject[] values, boolean breaker) {
		return set(rid, idcontext, null, null, optionsPostSet, values, -1, breaker);
	}

	/**
	 * Set the instruction
	 * @param rid the RID (KID) of the receiver
	 * @param idcontext the ID Context of the receiver
	 * @param optionsPreSet the set of options which have instructions
	 * 						for if they should be encrypted or not
	 * @param answers answers for the set of options for if they
	 * 				  should be encrypted or not
	 * @param optionsPostSet the set of options to add after encryption
	 * @param values the value of the option to add after encryption
	 * @return the encode option value
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] optionsPreSet, boolean[][] answers, int[] optionsPostSet, CBORObject[] values) {
		return set(rid, idcontext, optionsPreSet, answers, optionsPostSet, values, -1, false);
	}

	/**
	 * Set the instruction
	 * @param rid the RID (KID) of the receiver
	 * @param idcontext the ID Context of the receiver
	 * @param optionsPreSet the set of options which have instructions
	 * 						for if they should be encrypted or not
	 * @param answers answers for the set of options for if they
	 * 				  should be encrypted or not
	 * @param optionsPostSet the set of options to add after encryption
	 * @param values the value of the option to add after encryption
	 * @param requestSequenceNumber the request sequence number of message
	 * @return the encode option value
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] optionsPreSet, boolean[][] answers, int[] optionsPostSet, CBORObject[] values, boolean breaker) {
		return set(rid, idcontext, optionsPreSet, answers, optionsPostSet, values, -1, breaker);

	}
	/**
	 * Set the instruction
	 * @param rid the RID (KID) of the receiver
	 * @param idcontext the ID Context of the receiver
	 * @param optionsPreSet the set of options which have instructions
	 * 						for if they should be encrypted or not
	 * @param answers answers for the set of options for if they
	 * 				  should be encrypted or not
	 * @param optionsPostSet the set of options to add after encryption
	 * @param values the value of the option to add after encryption
	 * @param requestSequenceNumber the request sequence number of message
	 * @return the encode option value
	 */
	public static byte[] set(byte[] rid, byte[] idcontext, int[] optionsPreSet, boolean[][] answers, int[] optionsPostSet, CBORObject[] values, int requestSequenceNumber, boolean breaker) {
		CBORObject option = CBORObject.NewMap();
		int index = 0;

		option.Add(InstructionIDRegistry.KID, rid);
		option.Add(InstructionIDRegistry.IDContext, idcontext);

		if (optionsPreSet != null) {
			CBORObject optionsPreSetHolder = CBORObject.NewMap();
			if (optionsPreSet.length != answers.length) {
				throw new RuntimeException("Unequal amount of options: " + optionsPreSet.length + " and answers: " + answers.length);
			}

			for (int o : optionsPreSet) {
				if (answers[index].length != 5) {
					throw new RuntimeException("bad answer array, length should be 5");
				}
				optionsPreSetHolder.Add(o,answers[index]);
				index++;

			}

			if (index > 0) {
				option.Add(InstructionIDRegistry.PreSet, optionsPreSetHolder);
			}
		}

		if (optionsPostSet != null) {
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

			if (index > 0) {
				option.Add(InstructionIDRegistry.PostSet, optionsPostSetHolder);
			}
		}

		if (requestSequenceNumber > -1) {
			option.Add(InstructionIDRegistry.RequestSequenceNumber, requestSequenceNumber);
		}
		
		if (breaker) {
			option.Add(InstructionIDRegistry.Break, true);
		}

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
