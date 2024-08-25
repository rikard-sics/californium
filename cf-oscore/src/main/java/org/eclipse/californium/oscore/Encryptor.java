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
import java.util.Arrays;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.CounterSign1;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.cose.EncryptCommon;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.group.GroupSenderCtx;
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
		return encryptAndEncode(enc, ctx, message, newPartialIV, null, null);
	}
	/**
	 * Encrypt the COSE message using the OSCore context.
	 * 
	 * @param enc the encrypt structure
	 * @param ctx the OSCore context
	 * @param message the message
	 * @param newPartialIV if response contains partialIV
	 * @param requestSequenceNr the sequence number (Partial IV) from the
	 *            request (when encrypting a response or null otherwise)
	 * @param correspondingReqOption the OSCORE option of the corresponding request
	 *
	 * @return the COSE message
	 * 
	 * @throws OSException if encryption or encoding fails
	 */
	protected static byte[] encryptAndEncode(Encrypt0Message enc, OSCoreCtx ctx, Message message, boolean newPartialIV,
			Integer requestSequenceNr, byte[] correspondingReqOption)
			throws OSException {
		boolean isRequest = message instanceof Request;

		AlgorithmID encryptionAlg = ctx.getAlg();

		// Adjust nonce/IV and Common IV lengths depending on algorithm used
		boolean groupModeMessage = false;
		boolean pairwiseResponse = ctx.isGroupContext() && ((GroupSenderCtx) ctx).getPairwiseModeResponses()
				&& !isRequest;
		boolean pairwiseRequest = ctx.isGroupContext()
				&& OptionEncoder.getPairwiseMode(message.getOptions().getOscore()) && isRequest;
		groupModeMessage = ctx.isGroupContext() && !pairwiseResponse && !pairwiseRequest;
		int nonceLength = ctx.getIVLength();
		byte[] commonIV = ctx.getCommonIV();
		if (ctx.isGroupContext() && groupModeMessage) {
			int algGroupEncIvLen = EncryptCommon.getIvLength(((GroupSenderCtx) ctx).getAlgGroupEnc());
			nonceLength = algGroupEncIvLen;
			commonIV = Arrays.copyOfRange(ctx.getCommonIV(), 0, nonceLength);
		} else if (ctx.isGroupContext() && !groupModeMessage) {
			int algIvLen = EncryptCommon.getIvLength(((GroupSenderCtx) ctx).getAlg());
			nonceLength = algIvLen;
			commonIV = Arrays.copyOfRange(ctx.getCommonIV(), 0, nonceLength);
		}
		System.out.println("Encryption nonce length: " + nonceLength);

		try {
			byte[] key = ctx.getSenderKey();
			byte[] partialIV = null;
			byte[] nonce = null;
			byte[] aad = null;
			byte[] recipientId = null;

			if (isRequest) {
				partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
				nonce = OSSerializer.nonceGeneration(partialIV, ctx.getSenderId(), commonIV,
						nonceLength);
				aad = OSSerializer.serializeAAD(CoAP.VERSION, ctx.getAlg(), ctx.getSenderSeq(), ctx.getSenderId(), message.getOptions());
				enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(partialIV), Attribute.UNPROTECTED);
				enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(ctx.getSenderId()), Attribute.UNPROTECTED);
			} else {

				// TODO: Include KID for responses here too?

				recipientId = null;
				int requestSeq = 0;

				
				// TODO: Get recipientId and seqNr from message as below
				if (ctx.isGroupContext() == false) {
					recipientId = ctx.getRecipientId();
					requestSeq = requestSequenceNr;

				} else if (ctx.isGroupContext()) {
					// For Group OSCORE use RID and seq from request
					recipientId = OptionJuggle.getRid(correspondingReqOption);
					requestSeq = OptionJuggle.getPartialIV(correspondingReqOption);
				}

				if (!newPartialIV) {
					// use nonce from request
					partialIV = OSSerializer.processPartialIV(requestSeq);
					nonce = OSSerializer.nonceGeneration(partialIV, recipientId, commonIV,
							nonceLength);
				} else {
					// response creates its own partialIV
					partialIV = OSSerializer.processPartialIV(ctx.getSenderSeq());
					nonce = OSSerializer.nonceGeneration(partialIV, ctx.getSenderId(), commonIV,
							nonceLength);
				}
				aad = OSSerializer.serializeAAD(CoAP.VERSION, ctx.getAlg(), requestSeq, recipientId,
						message.getOptions());

			}

			System.out.println("Encrypting outgoing " + message.getClass().getSimpleName());
			System.out.println("Key " + Utils.toHexString(ctx.getSenderKey()));
			System.out.println("Plaintext " + Utils.toHexString(enc.GetContent()));
			System.out.println("PartialIV " + Utils.toHexString(partialIV));
			System.out.println("Nonce " + Utils.toHexString(nonce));
			System.out.println("AAD " + Utils.toHexString(aad));

			// Handle Group OSCORE messages
			if (ctx.isGroupContext()) {
				LOGGER.debug("Encrypting outgoing " + message.getClass().getSimpleName()
						+ " using Group OSCORE. Pairwise mode: " + !groupModeMessage);

				// Update external AAD value for Group OSCORE
				aad = OSSerializer.updateAADForGroup(ctx, aad, message);

				System.out.println("Encrypting outgoing " + message.getClass().getSimpleName() + " with AAD "
						+ Utils.toHexString(aad));

				System.out.println("Encrypting outgoing " + message.getClass().getSimpleName() + " with nonce "
						+ Utils.toHexString(nonce));

				// If this is a pairwise response/request use the pairwise key
				if (pairwiseResponse) {
					key = ((GroupSenderCtx) ctx).getPairwiseSenderKey(OptionJuggle.getRid(correspondingReqOption));
				} else if (pairwiseRequest) {
					// Get RID of intended recipient encoded in option
					byte[] recipientRID = OptionEncoder.getRID(message.getOptions().getOscore());
					key = ((GroupSenderCtx) ctx).getPairwiseSenderKey(recipientRID);
				} else {
					// If group mode is used prepare adding the signature
					encryptionAlg = ((GroupSenderCtx) ctx).getAlgGroupEnc();
					prepareSignature(enc, ctx, aad, message);
				}

			}

			// Warning: Using algos without integrity in pairwise mode
			if (encryptionAlg.getTagSize() == 0 && !groupModeMessage) {
				LOGGER.warn("Using an algorithm without integrity protection in pairwise mode!");
			}

			if (ctx.getContextRederivationPhase() == PHASE.SERVER_PHASE_2 && ctx.getNonceHandover() != null) {
				nonce = ctx.getNonceHandover();
			} else if (ctx.getContextRederivationPhase() == PHASE.CLIENT_PHASE_1
					|| ctx.getContextRederivationPhase() == PHASE.INACTIVE) {
				ctx.setNonceHandover(nonce);
			}

			enc.setExternal(aad);
			
			enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
			enc.addAttribute(HeaderKeys.Algorithm, encryptionAlg.AsCBOR(), Attribute.DO_NOT_SEND);

			enc.encrypt(key);

			if (groupModeMessage) {
				// Encrypt the signature.
				if (isRequest || newPartialIV) {
					encryptSignature(enc, (GroupSenderCtx) ctx, partialIV, ctx.getSenderId(), isRequest);
				} else {
					encryptSignature(enc, (GroupSenderCtx) ctx, partialIV, recipientId, isRequest);
				}

				// Append the signature
				appendSignature(enc);
			}

			return enc.getEncryptedContent();
		} catch (CoseException e) {
			LOGGER.error("COSE/Crypto exception: {}", e.getMessage());
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
	 * @param groupModeRequest if the request is using group mode
	 * 
	 * @return the Object-Security value as byte array
	 */
	public static byte[] encodeOSCoreRequest(OSCoreCtx ctx, boolean groupModeRequest) {

		OscoreOptionEncoder optionEncoder = new OscoreOptionEncoder();
		if (ctx.getIncludeContextId() || ctx.isGroupContext()) {
			optionEncoder.setIdContext(ctx.getMessageIdContext());
		}

		if (groupModeRequest) {
			optionEncoder.setGroupFlag(true);
		}

		optionEncoder.setPartialIV(ctx.getSenderSeq());
		optionEncoder.setKid(ctx.getSenderId());

		return optionEncoder.getBytes();
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

		OscoreOptionEncoder optionEncoder = new OscoreOptionEncoder();
		if (ctx.getIncludeContextId()) {
			optionEncoder.setIdContext(ctx.getMessageIdContext());
		}
		if (newPartialIV) {
			optionEncoder.setPartialIV(ctx.getSenderSeq());
		}

		// If this is a group mode response, set flag bit
		if (ctx instanceof GroupSenderCtx && ((GroupSenderCtx) ctx).getPairwiseModeResponses() == false) {
			optionEncoder.setGroupFlag(true);
		}

		// Always include KID for Group OSCORE (for now)
		if (ctx.isGroupContext()) {
			optionEncoder.setKid(ctx.getSenderId());
		}

		return optionEncoder.getBytes();
	}

	private static void prepareSignature(Encrypt0Message enc, OSCoreCtx ctx, byte[] aad, Message message) {
		GroupSenderCtx senderCtx = (GroupSenderCtx) ctx;
		
		OneKey senderPrivateKey = senderCtx.getPrivateKey();
		CounterSign1 sign = new CounterSign1(senderPrivateKey);

		CBORObject signAlg = senderCtx.getAlgSign().AsCBOR();
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

	private static void encryptSignature(Encrypt0Message enc, GroupSenderCtx ctx, byte[] partialIV, byte[] kid,
			boolean isRequest) {

		// Derive the keystream
		String digest = "";
		if (ctx.getKdf().toString().contains("SHA_256")) {
			digest = "SHA256";
		} else if (ctx.getKdf().toString().contains("SHA_512")) {
			digest = "SHA512";
		}

		CBORObject info = CBORObject.NewArray();
		int keyLength = ctx.getCommonCtx().getCountersignatureLen();

		info = CBORObject.NewArray();
		info.Add(kid);
		info.Add(ctx.getIdContext());
		info.Add(isRequest);
		info.Add(keyLength);

		System.out.println("Info: " + StringUtil.byteArray2Hex(info.EncodeToBytes()));
		
		byte[] signatureEncryptionKey = ctx.getCommonCtx().getSignatureEncryptionKey();
		byte[] keystream = null;
		try {
			keystream = OSCoreCtx.deriveKey(signatureEncryptionKey, partialIV, keyLength, digest, info.EncodeToBytes());

		} catch (CoseException e) {
			System.err.println(e.getMessage());
		}
		
		System.out.println("Partial IV for keystream: " + StringUtil.byteArray2Hex(partialIV));
		

		System.out.println("===");
		System.out.println("E Signature keystream: " + Utils.toHexString(keystream));
		System.out.println("E signatureEncryptionKey: " + Utils.toHexString(signatureEncryptionKey));
		System.out.println("E partialIV: " + Utils.toHexString(partialIV));
		System.out.println("E kid: " + Utils.toHexString(kid));
		System.out.println("E IdContext: " + Utils.toHexString(ctx.getIdContext()));
		System.out.println("E isRequest: " + isRequest);
		System.out.println("===");

		// Now actually encrypt the signature
		byte[] countersignBytes = enc.getUnprotectedAttributes().get(HeaderKeys.CounterSignature0.AsCBOR())
				.GetByteString();

		byte[] encryptedCountersign = new byte[keystream.length];
		for (int i = 0; i < keystream.length; i++) {
			encryptedCountersign[i] = (byte) (countersignBytes[i] ^ keystream[i]);
		}

		// Replace the signature in the Encrypt0 object
		enc.getUnprotectedAttributes().set(HeaderKeys.CounterSignature0.AsCBOR(),
				CBORObject.FromObject(encryptedCountersign));
	}
}
