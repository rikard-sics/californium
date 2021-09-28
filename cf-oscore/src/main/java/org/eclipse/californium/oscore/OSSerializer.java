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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.nio.ByteBuffer;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.oscore.group.GroupRecipientCtx;
import org.eclipse.californium.oscore.group.GroupSenderCtx;
import org.eclipse.californium.oscore.group.OptionEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.Utils;

/**
 * 
 * Implements methods for serializing OSCORE data, creating AAD, reading data
 * and generating nonce.
 *
 */
public class OSSerializer {

	private static final byte[] ONE_ZERO = new byte[] { 0x00 };

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OSSerializer.class);

	/**
	 * Prepare options and payload for encrypting.
	 * 
	 * @param options the options
	 * 
	 * @param payload the payload
 	 * @param realCode the actual code of the message
	 * 
	 * @return the serialized plaintext for OSCore
	 */
	public static byte[] serializeConfidentialData(OptionSet options, byte[] payload, int realCode) {
		if (options != null) {
			DatagramWriter writer = new DatagramWriter();
			if (realCode > 0) {
				OptionSet filteredOptions = OptionJuggle.prepareEoptions(options);
				writer.write(realCode, CoAP.MessageFormat.CODE_BITS);
				DataSerializer.serializeOptionsAndPayload(writer, filteredOptions, payload);
				return writer.toByteArray();
			} else {
				LOGGER.error(ErrorDescriptions.COAP_CODE_INVALID);
				throw new IllegalArgumentException(ErrorDescriptions.COAP_CODE_INVALID);
			}
		} else {
			LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
			throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
		}
	}

	/**
	 * Prepare the additional authenticated data of a message.
	 * 
	 * Note that for the request* parameters they must contain the value of what was in
	 * a request. Either this actual request or the request associated to this response. 
	 * 
	 * external_aad = [ ver : uint, alg : int, request_kid : bstr, request_piv :
	 * bstr, options : bstr]
	 * 
	 * @param version the CoAP version number
	 * @param algorithm AEAD algorithm
	 * @param requestSeq the sequence number (request PIV)
	 * @param requestSenderId sender ID (request KID)
	 * @param options the option set
	 * @return byte array with AAD
	 */
	public static byte[] serializeAAD(int version, AlgorithmID algorithm, int requestSeq, byte[] requestSenderId, OptionSet options) {
		if (version == CoAP.VERSION) {
			if (requestSeq > -1) {
				if (algorithm != null) {
					if (options != null) {
						CBORObject algorithms = CBORObject.NewArray();
						algorithms.Add(algorithm.AsCBOR());

						CBORObject aad = CBORObject.NewArray();
						aad.Add(version);
						aad.Add(algorithms);
						aad.Add(requestSenderId);
						aad.Add(processPartialIV(requestSeq));
						
						//I-class options (currently none)
						aad.Add(CBORObject.FromObject(Bytes.EMPTY));
						
						return aad.EncodeToBytes();
					} else {
						LOGGER.error(ErrorDescriptions.OPTIONSET_NULL);
						throw new NullPointerException(ErrorDescriptions.OPTIONSET_NULL);
					}
				} else {
					LOGGER.error(ErrorDescriptions.ALGORITHM_NOT_DEFINED);
					throw new NullPointerException(ErrorDescriptions.ALGORITHM_NOT_DEFINED);
				}
			} else {
				LOGGER.error(ErrorDescriptions.SEQ_NBR_INVALID);
				throw new IllegalArgumentException(ErrorDescriptions.SEQ_NBR_INVALID);
			}
		} else {
			LOGGER.error(ErrorDescriptions.WRONG_VERSION_NBR);
			throw new IllegalArgumentException(ErrorDescriptions.WRONG_VERSION_NBR);
		}
	}

	/**
	 * Generates the nonce.
	 * 
	 * Note that that if a response does not include a partial IV the nonce will be 
	 * generated using parameters from the corresponding original request.
	 * 
	 * See https://tools.ietf.org/html/draft-ietf-core-object-security-16#section-5.2
	 * 
	 * @param partialIV partial IV to calculate nonce with (from original request or response)
	 * @param senderID sender ID of message (either original request or response)
	 * @param commonIV common IV shared between sender and recipient
	 * @param nonceLength the algorithm dependent length of nonce
	 * @return the generated nonce or null if either one of the input parameters
	 *         are null
	 * @throws OSException if any of the parameters are invalid
	 */
	public static byte[] nonceGeneration(byte[] partialIV, byte[] senderID, byte[] commonIV, int nonceLength)
			throws OSException {
		if (partialIV != null) {
			if (senderID != null) {
				if (commonIV != null) {
					if (nonceLength > 0) {
						int s = senderID.length;
						int zeroes = 5 - partialIV.length;

						if (zeroes > 0) {
							partialIV = leftPaddingZeroes(partialIV, zeroes);
						}

						zeroes = (nonceLength - 6) - senderID.length;

						if (zeroes > 0) {
							senderID = leftPaddingZeroes(senderID, zeroes);
						}

						zeroes = nonceLength - commonIV.length;

						if (zeroes > 0) {
							commonIV = leftPaddingZeroes(commonIV, zeroes);
						}

						byte[] tmp = new byte[1 + senderID.length + partialIV.length];
						tmp[0] = (byte) s;
						System.arraycopy(senderID, 0, tmp, 1, senderID.length);
						System.arraycopy(partialIV, 0, tmp, senderID.length + 1, partialIV.length);

						byte[] result = new byte[commonIV.length];

						int i = 0;
						for (byte b : tmp) {
							result[i] = (byte) (b ^ commonIV[i++]);
						}

						return result;
					} else {
						LOGGER.error(ErrorDescriptions.NONCE_LENGTH_INVALID);
						throw new IllegalArgumentException(ErrorDescriptions.NONCE_LENGTH_INVALID);
					}
				} else {
					LOGGER.error(ErrorDescriptions.COMMON_IV_NULL);
					throw new NullPointerException(ErrorDescriptions.COMMON_IV_NULL);
				}
			} else {
				LOGGER.error(ErrorDescriptions.SENDER_ID_NULL);
				throw new NullPointerException(ErrorDescriptions.SENDER_ID_NULL);
			}
		} else {
			LOGGER.error(ErrorDescriptions.PARTIAL_IV_NULL);
			throw new NullPointerException(ErrorDescriptions.PARTIAL_IV_NULL);
		}
	}

	/**
	 * Padds the left side of the byte array paddMe with zeros as the int zeros
	 * has
	 * 
	 * @param paddMe byte array to pad
	 * @param zeros number of zeroes to pad with
	 * @return the left-padded byte array
	 */
	public static byte[] leftPaddingZeroes(byte[] paddMe, int zeros) {
		byte[] tmp = new byte[zeros + paddMe.length];
		System.arraycopy(paddMe, 0, tmp, zeros, paddMe.length);
		return tmp;
	}

	/**
	 * Processes a partialIV correctly
	 * 
	 * @param value the partialIV
	 * @return the processed partialIV
	 */
	public static byte[] processPartialIV(int value) {
		byte[] partialIV = ByteBuffer.allocate(Decryptor.INTEGER_BYTES).putInt(value).array();
		return stripZeroes(partialIV);
	}

	/**
	 * Remove trailing zeroes in a byte array
	 * 
	 * @param in the incoming array
	 * @return the array with trailing zeroes removed
	 */
	public static byte[] stripZeroes(byte[] in) {
		if (in != null) {
			if (in.length == 0) {
				return Bytes.EMPTY;
			}
			if (in.length == 1)
				return in;

			int firstValue = 0;

			while (firstValue < in.length && in[firstValue] == 0) {
				firstValue++;
			}

			int newLength = in.length - firstValue;

			if (newLength == 0) {
				return ONE_ZERO;
			}

			byte[] out = new byte[newLength];
			System.arraycopy(in, firstValue, out, 0, out.length);

			return out;
		} else {
			LOGGER.error(ErrorDescriptions.BYTE_ARRAY_NULL);
			throw new NullPointerException(ErrorDescriptions.BYTE_ARRAY_NULL);
		}
	}

	/**
	 * Update the external AAD for Group OSCORE by adding further parameters.
	 * 
	 * @param ctx the context used
	 * @param aadBytes the current external AAD value
	 * @param message the CoAP message being processed
	 * @return the updated external AAD
	 */
	public static byte[] updateAADForGroup(OSCoreCtx ctx, byte[] aadBytes, Message message) {

		CBORObject algSign;
		CBORObject algSignEnc;
		CBORObject algKeyAgreement;

		byte[] senderPublicKey;
		byte[] gmPublicKey;

		if (ctx instanceof GroupRecipientCtx) {
			GroupRecipientCtx recipientCtx = (GroupRecipientCtx) ctx;
			algSign = recipientCtx.getAlgSign().AsCBOR();
			algSignEnc = recipientCtx.getAlgSignEnc().AsCBOR();
			algKeyAgreement = recipientCtx.getAlgKeyAgreement().AsCBOR();
			senderPublicKey = recipientCtx.getPublicKeyRaw();
			gmPublicKey = recipientCtx.getCommonCtx().getGmPublicKey();
		} else {
			GroupSenderCtx senderCtx = (GroupSenderCtx) ctx;
			algSign = senderCtx.getAlgSign().AsCBOR();
			algSignEnc = senderCtx.getAlgSignEnc().AsCBOR();
			algKeyAgreement = senderCtx.getAlgKeyAgreement().AsCBOR();
			senderPublicKey = senderCtx.getPublicKeyRaw();
			gmPublicKey = senderCtx.getCommonCtx().getGmPublicKey();
		}

		CBORObject groupAadEnc = CBORObject.DecodeFromBytes(aadBytes);

		// Build index 1 which holds the algorithms array
		CBORObject algorithms = groupAadEnc.get(1);
		algorithms.Add(algSignEnc);
		algorithms.Add(algSign);
		algorithms.Add(algKeyAgreement);

		// Add update algorithms array to external AAD (used for encryption)
		groupAadEnc.set(1, algorithms);

		// Add request_kid_context //FIXME
		if (ctx.getIdContext() == null || ctx.getIdContext().length == 0) {
			groupAadEnc.Add(CBORObject.FromObject(Bytes.EMPTY));
		} else {
			CBORObject requestKidContext = CBORObject.FromObject(ctx.getIdContext());
			groupAadEnc.Add(requestKidContext);
		}

		// Adding OSCORE option

		byte[] oscoreOption = message.getOptions().getOscore();

		// Check if this is an outgoing message //TODO: Check with option null?
		boolean outgoing = message.getSourceContext() == null;

		if (outgoing) {

			if (message instanceof Request) {
				boolean groupModeRequest = OptionEncoder.getPairwiseMode(oscoreOption) == false;
				oscoreOption = Encryptor.encodeOSCoreRequest(ctx, groupModeRequest);
			} else {
				boolean newPartialIV = ctx.getResponsesIncludePartialIV() || message.getOptions().hasObserve();
				oscoreOption = Encryptor.encodeOSCoreResponse(ctx, newPartialIV);
			}
		}

		// Actually add OSCORE option to external AAD
		groupAadEnc.Add(oscoreOption);

		// Add the sender public key
		// System.out.println("Sender public key: " +
		// Utils.bytesToHex(senderPublicKey));
		groupAadEnc.Add(CBORObject.FromObject(senderPublicKey));

		// Add the Group Manager's public key
		// System.out.println("Sender public key: " +
		// Utils.bytesToHex(senderPublicKey));
		groupAadEnc.Add(CBORObject.FromObject(gmPublicKey));

		return groupAadEnc.EncodeToBytes();
	}

}
