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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.cose.Encrypt0Message;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.CounterSign1;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.GroupDeterministicRecipientCtx;
import org.eclipse.californium.oscore.group.GroupRecipientCtx;
import org.eclipse.californium.oscore.group.GroupSenderCtx;

/**
 * 
 * Gathers generalized methods for decryption and decompression of OSCORE
 * protected messages. Also provides decoding of the encoded OSCORE option
 *
 */
public abstract class Decryptor {
	/**
	 * Java 1.6 compatibility.
	 */
	public static final int INTEGER_BYTES = Integer.SIZE / Byte.SIZE;

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(Decryptor.class);

	/**
	 * Empty option set
	 */
	protected static final OptionSet EMPTY = new OptionSet();

	/**
	 * Decrypts and decodes the message.
	 * 
	 * @param enc the COSE structure
	 * @param message the message
	 * @param ctx the OSCore context
	 * @param seqByToken the sequence number
	 * 
	 * @return the decrypted plaintext
	 *
	 * @throws OSException if decryption or decoding fails
	 */
	protected static byte[] decryptAndDecode(Encrypt0Message enc, Message message, OSCoreCtx ctx, Integer seqByToken)
			throws OSException {
		int seq = -2;
		boolean isRequest = message instanceof Request;
		byte[] nonce = null;
		byte[] partialIV = null;
		byte[] aad = null;
		
		// DET_REQ
		boolean isDetReq = false; // Will be set to true in case of a deterministic request
		byte[] hash = null; // Value of the Request-Hash option, if this is a deterministic request

		CBORObject piv = enc.findAttribute(HeaderKeys.PARTIAL_IV);

		if (isRequest) {

			if (piv == null) {
				LOGGER.error("Decryption failed: no partialIV in request");
				throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
			} else {

				partialIV = piv.GetByteString();
				partialIV = expandToIntSize(partialIV);
				seq = ByteBuffer.wrap(partialIV).getInt();

				// DET_REQ
				// Understand if the request is a deterministic request. This requires that:
				// 
				// 1. The retrieved recipient context is a deterministic recipient context.
				//    If that is the case, the context being retrieved already implies that
				//    the 'kid' in the OSCORE option is the Sender ID of the deterministic client.
				//
				// 2. The request is protected in pairwise mode.
				//
				// 3. The request has FETCH as outer method.
				//
				// 4. The hash option is present, and it has a value whose length is consistent with the
				//    size of a hash computed with the used hash algorithm for the deterministic client
				if (ctx instanceof GroupDeterministicRecipientCtx) {
					
					if (OptionJuggle.getGroupModeBit(message.getOptions().getOscore())) {
						LOGGER.error("Decryption failed: deterministic request not in pairwise mode");
						throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
					}
					if (message.getRawCode() != Code.FETCH.value) {
							LOGGER.error("Decryption failed: no FETCH outer method in deterministic request");
							throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
					}
					
					hash = message.getOptions().getRequestHash();
					 
					if (hash == null) {
						LOGGER.error("Decryption failed: no Request-Hash option in deterministic request");
						throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
					}
					
					int hashSize = ((GroupDeterministicRecipientCtx) ctx).getHashSize();
					
					if (hashSize == 0 || hashSize != hash.length) {
						
						LOGGER.error("Decryption failed: invalid hash from the Request-Hash option in deterministic request");
						throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
					}
					
					System.out.println("Deterministic Request - Hash value: " + Utils.toHexString(hash) + "\n");
					
					isDetReq = true;
					
				}		
						
				// DET_REQ
				// Skip the replay check if this is a deterministic request
				if (!isDetReq) {
					//Note that the code below can throw an OSException when replays are detected
					ctx.checkIncomingSeq(seq);
				}
				if (ctx.isGroupContext()) {
					assert ctx instanceof GroupRecipientCtx;
				}

				nonce = OSSerializer.nonceGeneration(partialIV, ctx.getRecipientId(), ctx.getCommonIV(),
						ctx.getIVLength());
				aad = OSSerializer.serializeAAD(CoAP.VERSION, ctx.getAlg(), seq, ctx.getRecipientId(), message.getOptions());				
			}
		} else {
			if (seqByToken == null) {
				LOGGER.error("Decryption failed: the arrived response is not connected to a request we sent");
				throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
			}

			//Sequence number taken from original request
			seq = seqByToken;

			if (piv == null) {
				//Use the partialIV that arrived in the original request (response has no partial IV)

				partialIV = ByteBuffer.allocate(INTEGER_BYTES).putInt(seq).array();
				nonce = OSSerializer.nonceGeneration(partialIV,	ctx.getSenderId(), ctx.getCommonIV(), 
						ctx.getIVLength());
			} else {
				//Since the response contains a partial IV use it for nonce calculation

				partialIV = piv.GetByteString();
				partialIV = expandToIntSize(partialIV);
				nonce = OSSerializer.nonceGeneration(partialIV, ctx.getRecipientId(), ctx.getCommonIV(),
						ctx.getIVLength());
			}

			// DET_REQ
			// Detect if this is a response to a deterministic request
			if (message.getOptions().getRequestHash() != null) {
				isDetReq = true;
			}
			
			byte[] senderId = null;
			
			// DET_REQ
			// If it is a response to a deterministic request, force the Sender ID
			// of the deterministic client in 'request_kid' of the external_aad
			if (isDetReq) {
				GroupCtx groupCtx = ((GroupRecipientCtx) ctx).getCommonCtx();
				senderId = groupCtx.getDeterministicSenderCtx().getSenderId();
			}
			else {
				senderId = ctx.getSenderId();
			}

			//Nonce calculation uses partial IV in response (if present).
			//AAD calculation always uses partial IV (seq. nr.) of original request.  
			aad = OSSerializer.serializeAAD(CoAP.VERSION, ctx.getAlg(), seq, senderId, message.getOptions());
				
		}

		byte[] plaintext = null;
		byte[] key = ctx.getRecipientKey();
		byte[] detRecipientKey = null;
		
		// Handle Group OSCORE messages
		CounterSign1 sign = null;
		boolean groupModeMessage = OptionJuggle.getGroupModeBit(message.getOptions().getOscore());
		if (ctx.isGroupContext() || isDetReq) {
			LOGGER.debug("Decrypting incoming " + message.getClass().getSimpleName()
					+ " using Group OSCORE. Pairwise mode: " + !groupModeMessage);

			// Update external AAD value for Group OSCORE
			aad = OSSerializer.updateAADForGroup(ctx, aad, message);

			System.out.println("Decrypting incoming " + message.getClass().getSimpleName() + ", using pairwise mode: "
					+ !groupModeMessage);
			System.out.println("Decrypting incoming " + message.getClass().getSimpleName() + " with AAD "
					+ Utils.toHexString(aad));
			System.out.println("Decrypting incoming " + message.getClass().getSimpleName() + " with nonce "
					+ Utils.toHexString(nonce));

			// If group mode is used prepare the signature checking
			if (groupModeMessage) {
				
				// DET_REQ
				// If this is a response to a deterministic request
				// update the external_aad to the Request-Hash option
				// as if it was a Class I option; then remove the
				// option from the response
				if (!isRequest && isDetReq) {
					hash = message.getOptions().getRequestHash();
					aad = OSSerializer.updateAADForDeterministicRequest(hash, aad);
					message.getOptions().removeRequestHash();
				}
				
				// Decrypt the signature.
				if (isRequest || piv != null) {
					byte[] pivFromMessage = enc.findAttribute(HeaderKeys.PARTIAL_IV).GetByteString();
					decryptSignature(enc, sign, (GroupRecipientCtx) ctx, pivFromMessage, ctx.getRecipientId(), isRequest);
				} else {
					byte[] pivFromOther = OSSerializer.stripZeroes(ByteBuffer.allocate(5).putInt(seq).array());
					decryptSignature(enc, sign, (GroupRecipientCtx) ctx, pivFromOther, ctx.getSenderId(), isRequest);
				}

				sign = prepareCheckSignature(enc, ctx, aad, message);
				
			} else {
				// DET_REQ (extended here)
				// This message is protected with the pairwise mode, and it is neither
				// a deterministic request nor a response to a deterministic request.
				// The decryption key is simply the pairwise recipient key.
				if (!isDetReq) {
					key = ((GroupRecipientCtx) ctx).getPairwiseRecipientKey();
				}
				else if (isDetReq && isRequest) {
					// Derive the deterministic decryption key, to use for decrypting the deterministic request

					int keyLength = key.length;
					detRecipientKey = key;
					
					CBORObject info = CBORObject.NewArray();
					info.Add(ctx.getRecipientId()); // Sender ID of the deterministic client
					info.Add(ctx.getIdContext());
					info.Add(ctx.getAlg().AsCBOR());
					info.Add(CBORObject.FromObject("Key"));
					info.Add(keyLength);
					
					try {
						key = GroupCtx.extractExpand(detRecipientKey, hash, info.EncodeToBytes(), keyLength);
					} catch (InvalidKeyException e) {
						LOGGER.error("Error when deriving the deterministic decryption key: " + e.getMessage());
						throw new OSException(e.getMessage());
					} catch (NoSuchAlgorithmException e) {
						LOGGER.error("Error when deriving the deterministic decryption key: " + e.getMessage());
						throw new OSException(e.getMessage());
					}
					
				}
				else if (isDetReq && !isRequest) {
					LOGGER.error("Received a response protected in pairwise mode as reply to a deterministic request");
					throw new OSException("Received a response protected in pairwise mode as reply to a deterministic request");
				}

			}
		}

		// DET_REQ (moved down here)
		System.out.println("Decrypting incoming " + message.getClass().getSimpleName());
		System.out.println("Key " + Utils.toHexString(key));
		System.out.println("PartialIV " + Utils.toHexString(partialIV));
		System.out.println("Nonce " + Utils.toHexString(nonce));
		System.out.println("AAD " + Utils.toHexString(aad));
		
		enc.setExternal(aad);

		// Check signature before decrypting
		if (groupModeMessage) {
			// Verify the signature
			boolean signatureCorrect = checkSignature(enc, sign);
			LOGGER.debug("Signature verification succeeded: " + signatureCorrect);
		}

		try {
			// TODO: Get and set Recipient ID (KID) here too?
			enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg().AsCBOR(), Attribute.DO_NOT_SEND);
			enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
			plaintext = enc.decrypt(key);

		} catch (CoseException e) {
			String details = ErrorDescriptions.DECRYPTION_FAILED + " " + e.getMessage();
			LOGGER.error(details);
			throw new OSException(details);
		}

		// DET_REQ
		// If this is a deterministic request, recompute the hash value,
		// and compare it against the one in the Request-Hash option
		if (!groupModeMessage && isRequest && isDetReq) {

			int hashInputLength = detRecipientKey.length + aad.length + plaintext.length;
			
			int index = 0;
			byte[] recomputedHash;
			byte[] hashInput = new byte[hashInputLength];
			System.arraycopy(detRecipientKey, 0, hashInput, index, detRecipientKey.length);
			index += detRecipientKey.length;
			System.arraycopy(aad, 0, hashInput, index, aad.length);
			index += aad.length;
			System.arraycopy(plaintext, 0, hashInput, index, plaintext.length);
			
			// Compute the hash value
			try {
				String hashAlg = ((GroupDeterministicRecipientCtx) ctx).getHashAlg();				
				recomputedHash = GroupCtx.computeHash(hashInput, hashAlg);
			} catch (NoSuchAlgorithmException e) {						
				System.err.println("Error while computing the hash for a deterministic request: " + e.getMessage());
				throw new OSException(e.getMessage());
			}

			// Debugging
			System.out.println("\n");
			System.out.println("Hash input - Sender Key Deterministic Client: " + Utils.toHexString(detRecipientKey));
			System.out.println("Hash input - Original aad : " + Utils.toHexString(aad));
			System.out.println("Hash input - COSE Plaintext : " + Utils.toHexString(plaintext));
			System.out.println("Deterministic Request - Recomputed hash value: " + Utils.toHexString(recomputedHash) + "\n");
			
			// Compare the hash from the Request-Hash option with the recomputed hash
			if (!Arrays.equals(hash, recomputedHash)) {
				LOGGER.error("Decryption failed: The recomputed hash for a deterministic request does not match"
						+ "with the hash from the Request-Hash option");
				throw new OSException(ErrorDescriptions.DECRYPTION_FAILED);
			}
		}
		
		return plaintext;
	}

	/**
	 * @param partialIV partial IV to expand
	 * @return partial IV as byte array length of int
	 * 
	 * @throws OSException if the partial IV is longer than length of int
	 */
	private static byte[] expandToIntSize(byte[] partialIV) throws OSException {
		if (partialIV.length > INTEGER_BYTES) {
			LOGGER.error("The partial IV is: {} long, {} was expected", partialIV.length, INTEGER_BYTES);
			throw new OSException("Partial IV too long");
		} else if (partialIV.length == INTEGER_BYTES) {
			return partialIV;
		}
		byte[] ret = new byte[INTEGER_BYTES];
		for (int i = 0; i < partialIV.length; i++) {
			ret[INTEGER_BYTES - partialIV.length + i] = partialIV[i];
		}
		return ret;

	}

	/**
	 * @param protectedData the protected data to decrypt
	 * @return the COSE structure
	 */
	protected static Encrypt0Message prepareCOSEStructure(byte[] protectedData) {
		Encrypt0Message enc = new Encrypt0Message(false, true);
		try {
			enc.DecodeFromCBORObject(CBORObject.DecodeFromBytes(protectedData));
		} catch (CoseException e) {
			e.printStackTrace();
		}
		return enc;
	}

	/**
	 * Decompress the message.
	 * 
	 * @param cipherText the encrypted data
	 * @param message the received message
	 * @return the Encrypt0Message
	 * @throws OSException if OSCORE option fails to decode
	 */
	protected static Encrypt0Message decompression(byte[] cipherText, Message message) throws OSException {
		Encrypt0Message enc = new Encrypt0Message(false, true);

		//Added try-catch for general Exception. The array manipulation can cause exceptions.
		try {
			decodeObjectSecurity(message, enc);
		} catch (OSException e) {
			LOGGER.error(e.getMessage());
			throw e;
		} catch (Exception e) {
			LOGGER.error("Failed to decode object security option.");
			throw new OSException("Failed to decode object security option.");
		}

		if (cipherText != null)
			enc.setEncryptedContent(cipherText);
		return enc;
	}

	/**
	 * Decodes and checks the Object-Security value.
	 * 
	 * @param message the received message
	 * @param enc the Encrypt0Message object
	 * @throws OSException if OSCORE option fails to decode
	 */
	private static void decodeObjectSecurity(Message message, Encrypt0Message enc) throws OSException {

		OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(message.getOptions().getOscore());

		int n = optionDecoder.getN();
		int k = optionDecoder.getK();
		int h = optionDecoder.getH();

		byte[] partialIV = optionDecoder.getPartialIV();
		byte[] kid = optionDecoder.getKid();
		byte[] kidContext = optionDecoder.getIdContext();

		// Check Partial IV
		if (n > 0 && partialIV == null) {
			LOGGER.error("Partial_IV is missing from message when it is expected.");
			throw new OSException(ErrorDescriptions.FAILED_TO_DECODE_COSE);
		}

		// Check KID Context
		if (h != 0 && kidContext == null) {
			LOGGER.error("Kid context is missing from message when it is expected.");
			throw new OSException(ErrorDescriptions.FAILED_TO_DECODE_COSE);
		}

		// Check KID
		if (k != 0 && kid == null && message instanceof Request) {
			LOGGER.error("Kid is missing from message when it is expected.");
			throw new OSException(ErrorDescriptions.FAILED_TO_DECODE_COSE);
		}

		// Adding parsed data to Encrypt0Message object
		try {
			if (partialIV != null) {
				enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(partialIV), Attribute.UNPROTECTED);
			}
			if (kid != null) {
				enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(kid), Attribute.UNPROTECTED);
			}

			// COSE Header parameter for KID Context defined as 10
			// https://www.iana.org/assignments/cose/cose.xhtml
			int kidContextKey = 10;
			if (kidContext != null) {
				enc.addAttribute(CBORObject.FromObject(kidContextKey), CBORObject.FromObject(kidContext),
						Attribute.UNPROTECTED);
			}
		} catch (CoseException e) {
			LOGGER.error("COSE processing of message failed.");
			e.printStackTrace();
		}
	}

	/**
	 * Replaces the message's options with a new OptionSet which doesn't contain
	 * any of the non-special E options as outer options
	 * 
	 * @param message the received message
	 */
	protected static void discardEOptions(Message message) {
		OptionSet newOptions = OptionJuggle.discardEOptions(message.getOptions());
		message.setOptions(newOptions);
	}

	// TODO: Remove unneeded lines
	private static boolean checkSignature(Encrypt0Message enc, CounterSign1 sign) throws OSException {

		boolean countersignatureValid = false;

		try {
			countersignatureValid = enc.validate(sign);
		} catch (CoseException e) {
			LOGGER.error("Countersignature checking procedure failed.");
			e.printStackTrace();
		}

		if (countersignatureValid == false) {
			LOGGER.error(ErrorDescriptions.COUNTERSIGNATURE_CHECK_FAILED);
			throw new OSException(ErrorDescriptions.COUNTERSIGNATURE_CHECK_FAILED);
		}

		return countersignatureValid;
	}

	// TODO: Remove unneeded lines
	private static CounterSign1 prepareCheckSignature(Encrypt0Message enc, OSCoreCtx ctx, byte[] aad, Message message) {

		CounterSign1 sign = null;
		GroupRecipientCtx recipientCtx = (GroupRecipientCtx) ctx;

		// First remove the countersignature from the payload
		byte[] full_payload = null;
		try {
			full_payload = enc.getEncryptedContent();

			// Set new truncated ciphertext
			int countersignatureLength = recipientCtx.getCountersignatureLen();
			byte[] countersignatureBytes = Arrays.copyOfRange(full_payload,
					full_payload.length - countersignatureLength, full_payload.length);
			byte[] ciphertext = Arrays.copyOfRange(full_payload, 0, full_payload.length - countersignatureLength);
			enc.setEncryptedContent(ciphertext);

			// Now actually prepare to check the countersignature
			OneKey recipientPublicKey = recipientCtx.getPublicKey();
			// countersignatureBytes[3] = (byte) 0xff; // Corrupt
			// countersignature
			sign = new CounterSign1(countersignatureBytes);
			sign.setKey(recipientPublicKey);

			CBORObject signAlg = recipientCtx.getAlgSign().AsCBOR();
			sign.addAttribute(HeaderKeys.Algorithm, signAlg, Attribute.DO_NOT_SEND);
			byte[] signAad = aad;

			sign.setExternal(signAad);

			System.out.println("Checking signature for incoming " + message.getClass().getSimpleName()
					+ " with sign AAD " + Utils.toHexString(signAad));
		} catch (Exception e) {
			LOGGER.error("Countersignature verification procedure failed.");
			e.printStackTrace();
		}

		return sign;
	}

	private static void decryptSignature(Encrypt0Message enc, CounterSign1 sign, GroupRecipientCtx ctx,
			byte[] partialIV,
			byte[] kid, boolean isRequest) {

		// The Partial IV needs to be padded to 5 bytes. This is because the
		// padding is not done until nonce generation which happens after this.
		int zeroes = 5 - partialIV.length;
		if (zeroes > 0) {
			partialIV = OSSerializer.leftPaddingZeroes(partialIV, zeroes);
		}

		// Derive the keystream
		String digest = "";
		if (ctx.getAlgKeyAgreement().toString().contains("HKDF_256")) {
			digest = "SHA256";
		} else if (ctx.getAlgKeyAgreement().toString().contains("HKDF_512")) {
			digest = "SHA512";
		}
		CBORObject info = CBORObject.NewArray();
		int keyLength = ctx.getCommonCtx().getCountersignatureLen();

		info = CBORObject.NewArray();
		info.Add(kid);
		info.Add(ctx.getIdContext());
		info.Add(isRequest);
		info.Add(keyLength);

		byte[] groupEncryptionKey = ctx.getCommonCtx().getGroupEncryptionKey();
		byte[] keystream = null;
		try {
			keystream = OSCoreCtx.deriveKey(groupEncryptionKey, partialIV, keyLength, digest, info.EncodeToBytes());

		} catch (CoseException e) {
			System.err.println(e.getMessage());
		}

		System.out.println("===");
		System.out.println("D Signature keystream: " + Utils.toHexString(keystream));
		System.out.println("D groupEncryptionKey: " + Utils.toHexString(groupEncryptionKey));
		System.out.println("D partialIV: " + Utils.toHexString(partialIV));
		System.out.println("D kid: " + Utils.toHexString(kid));
		System.out.println("D IdContext: " + Utils.toHexString(ctx.getIdContext()));
		System.out.println("D isRequest: " + isRequest);
		System.out.println("===");

		// Now actually decrypt the signature
		byte[] full_payload = null;
		try {
			full_payload = enc.getEncryptedContent();
		} catch (CoseException e) {
			LOGGER.error("Countersignature verification procedure failed.");
			e.printStackTrace();
		}
		byte[] countersignBytes = Arrays.copyOfRange(full_payload, full_payload.length - keyLength,
				full_payload.length);
		byte[] ciphertext = Arrays.copyOfRange(full_payload, 0, full_payload.length - keyLength);

		byte[] decryptedCountersign = new byte[keystream.length];
		for (int i = 0; i < keystream.length; i++) {
			decryptedCountersign[i] = (byte) (countersignBytes[i] ^ keystream[i]);
		}

		// Replace the signature in the Encrypt0 object
		enc.setEncryptedContent(Bytes.concatenate(ciphertext, decryptedCountersign));
	}

}
