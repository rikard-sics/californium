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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.CounterSign1;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.GroupSenderCtx;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.GroupDeterministicSenderCtx;
import org.eclipse.californium.oscore.group.OptionEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORObject;

/**
 * 
 * Gathers generalized methods for encryption and compression of OSCORE
 * protected messages. Also encodes the OSCORE option.
 *
 */
public abstract class Encryptor {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Encryptor.class);

	protected static byte[] encryptAndEncode(Encrypt0Message enc, OSCoreCtx ctx, Message message,
			boolean newPartialIV) throws OSException {
		return encryptAndEncode(enc, ctx, message, newPartialIV, null);
	}
	/**
	 * Encrypt the COSE message using the OSCore context.
	 * 
	 * @param enc the encrypt structure
	 * @param ctx the OSCore context
	 * @param message the message
	 * @param newPartialIV if response contains partialIV
	 * @param correspondingReqOption the OSCORE option of the corresponding request
	 *
	 * @return the COSE message
	 * 
	 * @throws OSException if encryption or encoding fails
	 */
	protected static byte[] encryptAndEncode(Encrypt0Message enc, OSCoreCtx ctx, Message message, boolean newPartialIV,
			byte[] correspondingReqOption)
			throws OSException {
		boolean isRequest = message instanceof Request;

		try {
			byte[] key = ctx.getSenderKey();
			byte[] partialIV = null;
			byte[] nonce = null;
			byte[] aad = null;
			
			// DET_REQ
			boolean isDetReq = false; // Will be set to true in case of a deterministic request
			byte[] hash = null; // Hash of the original CoAP request, to use for building a deterministic request
			byte[] detKey = null; // Deterministic pairwise sender key, to use for encrypting a deterministic request
			OSCoreCtx oldCtx = null; // auxiliary variable

			if (isRequest) {
				
				// DET_REQ
				// If it is a deterministic request, switch to the Deterministic Sender Context
				isDetReq = OptionEncoder.getDetReq(message.getOptions().getOscore());
				if (isDetReq) {
					oldCtx = ctx;
					ctx = ((GroupSenderCtx) ctx).getDeterministicSenderCtx();
				}
				
				partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
				nonce = OSSerializer.nonceGeneration(partialIV, ctx.getSenderId(), ctx.getCommonIV(),
						ctx.getIVLength());
				aad = OSSerializer.serializeAAD(CoAP.VERSION, ctx.getAlg(), ctx.getSenderSeq(), ctx.getSenderId(), message.getOptions());
				enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(partialIV), Attribute.UNPROTECTED);
				enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ctx.getSenderId()), Attribute.UNPROTECTED);
				
				// If it is a deterministic request, switch back to the Sender Context
				if (isDetReq) {
					ctx = oldCtx;
				}
				
			} else {

				// TODO: Include KID for responses here too?

				byte[] recipientId = null;
				int requestSeq = 0;

				if (ctx.isGroupContext() == false) {
					recipientId = ctx.getRecipientId();
					requestSeq = ctx.getReceiverSeq();

				} else if (ctx.isGroupContext()) {
					// For Group OSCORE use RID and seq from request
					recipientId = OptionJuggle.getRid(correspondingReqOption);
					requestSeq = OptionJuggle.getPartialIV(correspondingReqOption);
				}

				if (!newPartialIV) {
					// use nonce from request
					partialIV = OSSerializer.processPartialIV(requestSeq);
					nonce = OSSerializer.nonceGeneration(partialIV, recipientId, ctx.getCommonIV(),
							ctx.getIVLength());
				} else {
					// response creates its own partialIV
					partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
					nonce = OSSerializer.nonceGeneration(partialIV, ctx.getSenderId(), ctx.getCommonIV(),
							ctx.getIVLength());
				}
				aad = OSSerializer.serializeAAD(CoAP.VERSION, ctx.getAlg(), requestSeq, recipientId,
						message.getOptions());

			}
			
			// Handle Group OSCORE messages
			boolean groupModeMessage = false;
			if (ctx.isGroupContext()) {

				boolean pairwiseResponse = ((GroupSenderCtx) ctx).getPairwiseModeResponses() && !isRequest;
				boolean pairwiseRequest = OptionEncoder.getPairwiseMode(message.getOptions().getOscore()) && isRequest;
				groupModeMessage = !pairwiseResponse && !pairwiseRequest;

				LOGGER.debug("Encrypting outgoing " + message.getClass().getSimpleName()
						+ " using Group OSCORE. Pairwise mode: " + !groupModeMessage);

				// DET_REQ
				// If it is a deterministic request, switch to the Deterministic Sender Context
				if (isDetReq) {
					ctx = ((GroupSenderCtx) ctx).getDeterministicSenderCtx();
				}
				
				// Update external AAD value for Group OSCORE
				aad = OSSerializer.updateAADForGroup(ctx, aad, message);
				
				// DET_REQ
				// Additional steps in case of a deterministic request
				if (isDetReq) {
					detKey = ctx.getSenderKey();
					
					int hashInputLength = detKey.length + aad.length + enc.GetContent().length;
					
					int index = 0;
					byte[] hashInput = new byte[hashInputLength];
					System.arraycopy(detKey, 0, hashInput, index, detKey.length);
					index += detKey.length;
					System.arraycopy(aad, 0, hashInput, index, aad.length);
					index += aad.length;
					System.arraycopy(enc.GetContent(), 0, hashInput, index, enc.GetContent().length);
					
					// Compute the hash value
					try {
						String hashAlg = ((GroupDeterministicSenderCtx) ctx).getHashAlg();
						hash = GroupCtx.computeHash(hashInput, hashAlg);
					} catch (NoSuchAlgorithmException e) {						
						System.err.println("Error while computing the hash for the a deterministic request: " + e.getMessage());
						throw new OSException(e.getMessage());
					}
					
					System.out.println("Deterministic Request - Hash value: " + Utils.toHexString(hash) + "\n");
					
					message.getOptions().setRequestHash(hash);
					
					// TODO Further update the external_aad with the hash value as 'request_kid'
					
				}
				
				System.out.println("Encrypting outgoing " + message.getClass().getSimpleName() + " with AAD "
						+ Utils.toHexString(aad));

				System.out.println("Encrypting outgoing " + message.getClass().getSimpleName() + " with nonce "
						+ Utils.toHexString(nonce));

				// If this is a pairwise response/request use the pairwise key
				if (pairwiseResponse) {
					key = ((GroupSenderCtx) ctx).getPairwiseSenderKey(OptionJuggle.getRid(correspondingReqOption));
				} else if (pairwiseRequest) {
					// DET_REQ (extended here)
					if (!isDetReq) {
						// Get RID of intended recipient encoded in option
						byte[] recipientRID = OptionEncoder.getRID(message.getOptions().getOscore());
						key = ((GroupSenderCtx) ctx).getPairwiseSenderKey(recipientRID);
					}
					else {
						// TODO Derive the proper deterministic pairwise sender key
						key = detKey;
					}
				} else {
					// If group mode is used prepare adding the signature
					prepareSignature(enc, ctx, aad, message);
				}

			}

			// DET_REQ
			if (isRequest) {
				System.out.println("\nDeterministic request: " + isDetReq + "\n");
			}
			// DET_REQ
			// Moved down here
			System.out.println("Encrypting outgoing " + message.getClass().getSimpleName());
			System.out.println("Key " + Utils.toHexString(ctx.getSenderKey()));
			System.out.println("PartialIV " + Utils.toHexString(partialIV));
			System.out.println("Nonce " + Utils.toHexString(nonce));
			System.out.println("AAD " + Utils.toHexString(aad));
			
			enc.setExternal(aad);
			
			enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
			enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg().AsCBOR(), Attribute.DO_NOT_SEND);

			enc.encrypt(key);

			if (groupModeMessage) {
				appendSignature(enc);
			}

			return enc.getEncryptedContent();
		} catch (CoseException e) {
			LOGGER.error("COSE/Crypto exception: " + e.getMessage());
			throw new OSException(e.getMessage());
		}
	}

	/**
	 * Initiates the encrypt0message object and sets the confidential (plaintext
	 * to be encrypted).
	 * 
	 * @param confidential the plaintext to be encrypted
	 * @return the initiated and prepared encrypt0message object
	 */
	protected static Encrypt0Message prepareCOSEStructure(byte[] confidential) {
		Encrypt0Message enc = new Encrypt0Message(false, true);
		enc.SetContent(confidential);
		return enc;
	}

	/**
	 * Compresses the message by encoding the Object-Security value and sets the
	 * message's payload to the cipherText.
	 * 
	 * @param ctx the OSCoreCtx
	 * @param cipherText the cipher text to be appended to this compression
	 * @param message the message
	 * @param newPartialIV if response contains partialIV
	 * @return the entire message's byte array
	 */
	protected static byte[] compression(OSCoreCtx ctx, byte[] cipherText, Message message, final boolean newPartialIV) {
		boolean request = message instanceof Request;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();
		OptionSet options = message.getOptions();
		boolean groupModeRequest = !(OptionEncoder.getPairwiseMode(options.getOscore())
				&& message.getSourceContext() == null) && ctx.isGroupContext();
		options.removeOscore();

		if (request) {
			message.getOptions().setOscore(encodeOSCoreRequest(ctx, groupModeRequest));
		} else {
			message.getOptions().setOscore(encodeOSCoreResponse(ctx, newPartialIV));
		}

		if (cipherText != null) {
			message.setPayload(cipherText);
		}

		return bRes.toByteArray();
	}

	// TODO: Remove?
	public static byte[] encodeOSCoreRequest(OSCoreCtx ctx) {
		return encodeOSCoreRequest(ctx, false);
	}

	/**
	 * Encodes the Object-Security value for a Request.
	 * 
	 * @param ctx the context
	 * @param groupModeRequest if this is a Group OSCORE group mode request
	 * @return the Object-Security value as byte array
	 */
	public static byte[] encodeOSCoreRequest(OSCoreCtx ctx, boolean groupModeRequest) {
		int firstByte = 0x00;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();
		byte[] partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
		firstByte = firstByte | (partialIV.length & 0x07); //PartialIV length
		firstByte = firstByte | 0x08; //Set the KID bit
		
		//If the Context ID should be included for this context, set its bit
		if (ctx.getIncludeContextId() || ctx.isGroupContext()) {
			firstByte = firstByte | 0x10;
		}

		// If this is a group mode request
		if (groupModeRequest) {
			firstByte = firstByte | 0x20;
		}

		bRes.write(firstByte);

		try {
			bRes.write(partialIV);

			//Encode the Context ID length and value if to be included
			if (ctx.getIncludeContextId() || ctx.isGroupContext()) {
				bRes.write(ctx.getMessageIdContext().length);
				bRes.write(ctx.getMessageIdContext());
			}

			//Encode Sender ID (KID)
			bRes.write(ctx.getSenderId());
		} catch (IOException e) {
			e.printStackTrace();
		}
		return bRes.toByteArray();
	}

	/**
	 * Encodes the Object-Security value for a Response.
	 * 
	 * @param ctx the context
	 * @param newPartialIV if true encodes the partialIV, otherwise partialIV is
	 *            not encoded
	 * @return the Object-Security value as byte array
	 */
	public static byte[] encodeOSCoreResponse(OSCoreCtx ctx, final boolean newPartialIV) {
		int firstByte = 0x00;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();

		//If the Context ID should be included for this context, set its bit
		if (ctx.getIncludeContextId()) {
			firstByte = firstByte | 0x10;
		}

		// If the KID should be included (Group OSCORE), set its bit
		if (ctx.isGroupContext()) {
			firstByte = firstByte | 0x08;
		}

		// If this is a group mode response
		if (ctx instanceof GroupSenderCtx && ((GroupSenderCtx) ctx).getPairwiseModeResponses() == false) {
			firstByte = firstByte | 0x20;
		}

		if (newPartialIV) {
			byte[] partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
			firstByte = firstByte | (partialIV.length & 0x07);

			bRes.write(firstByte);
			try {
				bRes.write(partialIV);
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			bRes.write(firstByte);
		}

		//Encode the Context ID length and value if to be included
		if (ctx.getIncludeContextId()) {
			try {
				bRes.write(ctx.getMessageIdContext().length);
				bRes.write(ctx.getMessageIdContext());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		//For Group OSCORE always include the KID (Sender ID) in responses
		if (ctx.isGroupContext()) {
			try {
				bRes.write(ctx.getSenderId());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		//If the OSCORE option is length 1 and 0x00, it should be empty
		//See https://tools.ietf.org/html/draft-ietf-core-object-security-16#section-2
		byte[] optionBytes = bRes.toByteArray();
		if (optionBytes.length == 1 && optionBytes[0] == 0x00) {
			return Bytes.EMPTY;
		} else {
			return optionBytes;
		}
	}

	private static void prepareSignature(Encrypt0Message enc, OSCoreCtx ctx, byte[] aad, Message message) {
		GroupSenderCtx senderCtx = (GroupSenderCtx) ctx;
		
		OneKey senderPrivateKey = senderCtx.getPrivateKey();
		CounterSign1 sign = new CounterSign1(senderPrivateKey);

		CBORObject signAlg = senderCtx.getAlgCountersign().AsCBOR();
		try {
			sign.addAttribute(HeaderKeys.Algorithm, signAlg, Attribute.DO_NOT_SEND);
		} catch (CoseException e) {
			LOGGER.error("Failed to prepare the Countersignature.");
			e.printStackTrace();
		}

		enc.setCountersign1(sign);

		byte[] signAad = aad;
		sign.setExternal(signAad); // Set external AAD for signing

		System.out.println("Signing outgoing " + message.getClass().getSimpleName() + " with sign AAD "
				+ Utils.toHexString(signAad));

	}

	private static void appendSignature(Encrypt0Message enc) {
		CBORObject mySignature = enc.getUnprotectedAttributes().get(HeaderKeys.CounterSignature0.AsCBOR());
		byte[] countersignBytes = mySignature.GetByteString();

		byte[] ciphertext = null;
		try {
			ciphertext = enc.getEncryptedContent();
		} catch (CoseException e) {
			LOGGER.error("Failed to append the Countersignature.");
			e.printStackTrace();
		}

		ByteArrayOutputStream os = new ByteArrayOutputStream();
		try {
			os.write(ciphertext);
			os.write(countersignBytes);
		} catch (IOException e) {
			LOGGER.error("Failed to append the Countersignature.");
			e.printStackTrace();
		}

		byte[] fullPayload = os.toByteArray();

		System.out.println("countersignBytes len: " + countersignBytes.length);
		System.out.println("ciphertext len: " + ciphertext.length);
		enc.setEncryptedContent(fullPayload);
	}
}
