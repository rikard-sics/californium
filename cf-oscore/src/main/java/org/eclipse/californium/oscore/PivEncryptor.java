package org.eclipse.californium.oscore;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.core.coap.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PivEncryptor {

	/**
	 * Length of the IV_KEYSTREAM
	 */
	private static final int IV_KEYSTREAM_LENGTH = 16;

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(PivEncryptor.class);

	/**
	 * Decrypt the OSCORE Partial IV in the OSCORE CoAP option
	 * https://datatracker.ietf.org/doc/html/draft-tiloca-core-oscore-piv-enc-00
	 * 
	 * @param message the CoAP message
	 * @param pivEncryptionKey the Partial IV encryption key
	 */
	static void decryptPiv(Message message, final byte[] pivEncryptionKey) {
		encryptDecryptPiv(message, pivEncryptionKey);
	}

	/**
	 * Encrypt the OSCORE Partial IV in the OSCORE CoAP option
	 * https://datatracker.ietf.org/doc/html/draft-tiloca-core-oscore-piv-enc-00
	 * 
	 * @param message the CoAP message
	 * @param pivEncryptionKey the Partial IV encryption key
	 */
	static void encryptPiv(Message message, final byte[] pivEncryptionKey) {
		encryptDecryptPiv(message, pivEncryptionKey);
	}

	/**
	 * Encrypt or decrypt the OSCORE Partial IV in the OSCORE CoAP option
	 * https://datatracker.ietf.org/doc/html/draft-tiloca-core-oscore-piv-enc-00
	 * 
	 * @param message the CoAP message
	 * @param pivEncryptionKey the Partial IV encryption key
	 */
	private static void encryptDecryptPiv(Message message, final byte[] pivEncryptionKey) {
		OscoreOptionDecoder optionDecoder = null;
		try {
			optionDecoder = new OscoreOptionDecoder(message.getOptions().getOscore());
		} catch (CoapOSException e) {
			LOGGER.error("Error parsing OSCORE CoAP option for Partial IV encryption/decryption.");
			e.printStackTrace();
		}

		// Do nothing if the OSCORE option does not contain a PIV
		if (optionDecoder.getPartialIV() == null || optionDecoder.getPartialIV().length == 0) {
			return;
		}

		// Extract input from the CoAP message
		byte[] input = composeInput(message);

		// Generate the IV_KEYSTREAM
		byte[] ivKeystream = computeKeystream(input, pivEncryptionKey);

		// Actually encrypt/decrypt the Partial IV
		byte[] plainPiv = optionDecoder.getPartialIV();
		byte[] encryptedPartialIV = new byte[plainPiv.length];

		if (ivKeystream.length < plainPiv.length) {
			LOGGER.error("Error IV_KEYSTREAM is too short when performing Partial IV encryption/decryption.");
		}

		for (int i = 0; i < plainPiv.length; i++) {
			encryptedPartialIV[i] = (byte) (plainPiv[i] ^ ivKeystream[i]);
		}

		// Replace the PIV in the OSCORE CoAP option
		OscoreOptionEncoder optionEncoder = new OscoreOptionEncoder();
		optionEncoder.setIdContext(optionDecoder.getIdContext());
		optionEncoder.setKid(optionDecoder.getKid());
		optionEncoder.setPartialIV(encryptedPartialIV);
		message.getOptions().setOscore(optionEncoder.getBytes());
	}

	/**
	 * Encrypt the OSCORE KID in the OSCORE CoAP option
	 * https://datatracker.ietf.org/doc/html/draft-tiloca-core-oscore-piv-enc-00
	 * 
	 * @param message the CoAP message
	 * @param pivEncryptionKey the Partial IV encryption key
	 */
	protected static void encryptKid(Message message, final byte[] pivEncryptionKey) {
		OscoreOptionDecoder optionDecoder = null;
		try {
			optionDecoder = new OscoreOptionDecoder(message.getOptions().getOscore());
		} catch (CoapOSException e) {
			LOGGER.error("Error parsing OSCORE CoAP option for KID encryption.");
			e.printStackTrace();
		}

		// Do nothing if the OSCORE option does not contain a KID
		if (optionDecoder.getKid() == null || optionDecoder.getKid().length == 0) {
			return;
		}
		// Warn if the OSCORE option does not contain a Partial IV (but a KID)
		if (optionDecoder.getPartialIV() == null || optionDecoder.getPartialIV().length == 0) {
			LOGGER.error("Error message contains KID but no Partial IV for KID encryption.");
			return;
		}

		// Extract input from the CoAP message
		byte[] input = composeInput(message);

		// Flip last bit in last byte
		input[input.length - 1] = (byte) (input[input.length - 1] & 0x01);

		// Generate the KID_KEYSTREAM
		byte[] kidKeystream = computeKeystream(input, pivEncryptionKey);

		// Actually encrypt/decrypt the KID
		byte[] encryptedPiv = optionDecoder.getPartialIV();
		byte[] encryptedKid = new byte[encryptedPiv.length];

		if (kidKeystream.length < encryptedPiv.length) {
			LOGGER.error("Error KID_KEYSTREAM is too short when performing KID encryption.");
		}

		for (int i = 0; i < encryptedPiv.length; i++) {
			encryptedKid[i] = (byte) (encryptedPiv[i] ^ kidKeystream[i]);
		}

		// Replace the KID in the OSCORE CoAP option
		OscoreOptionEncoder optionEncoder = new OscoreOptionEncoder();
		optionEncoder.setIdContext(optionDecoder.getIdContext());
		optionEncoder.setKid(encryptedKid);
		optionEncoder.setPartialIV(optionDecoder.getPartialIV());
		message.getOptions().setOscore(optionEncoder.getBytes());
	}

	/**
	 * Decrypt the OSCORE KID in the OSCORE CoAP option, relies on trying
	 * different OSCORE Security Contexts until one is found where the decrypted
	 * KID matches the encrypted PIV
	 * 
	 * https://datatracker.ietf.org/doc/html/draft-tiloca-core-oscore-kid-enc-00
	 * 
	 * @param message the CoAP message
	 * @param db the OSCORE context database
	 * @return the found OSCORE context
	 */
	protected static OSCoreCtx decryptKidFindContext(Message message, final HashMapCtxDB db) {

		OscoreOptionDecoder optionDecoder = null;
		try {
			optionDecoder = new OscoreOptionDecoder(message.getOptions().getOscore());
		} catch (CoapOSException e) {
			LOGGER.error("Error parsing OSCORE CoAP option for KID encryption.");
			e.printStackTrace();
		}

		// Do nothing if the OSCORE option does not contain a KID
		if (optionDecoder.getKid() == null || optionDecoder.getKid().length == 0) {
			return null;
		}
		// Warn if the OSCORE option does not contain a Partial IV (but a KID)
		if (optionDecoder.getPartialIV() == null || optionDecoder.getPartialIV().length == 0) {
			LOGGER.error("Error message contains KID but no Partial IV for KID encryption.");
			return null;
		}

		// Extract input from the CoAP message
		byte[] input = composeInput(message);

		// Flip last bit in last byte
		input[input.length - 1] = (byte) (input[input.length - 1] & 0x01);

		// === Loop through all OSCORE contexts and try decryption ===
		boolean contextFound = false;
		byte[] decryptedKid = null;
		OSCoreCtx ctx = null;
		for (Map.Entry<ByteId, HashMap<ByteId, OSCoreCtx>> outerEntry : db.contextMap.entrySet()) {

			if (contextFound) {
				break;
			}

			HashMap<ByteId, OSCoreCtx> innerMap = outerEntry.getValue();

			for (Map.Entry<ByteId, OSCoreCtx> innerEntry : innerMap.entrySet()) {
				ctx = innerEntry.getValue();

				// Generate the KID_KEYSTREAM
				if (ctx.getPivEncryptionKey() == null) {
					continue;
				}
				byte[] kidKeystream = computeKeystream(input, ctx.getPivEncryptionKey());

				// Actually encrypt/decrypt the KID
				byte[] encryptedPiv = optionDecoder.getPartialIV();
				byte[] encryptedKid = optionDecoder.getKid();
				decryptedKid = new byte[encryptedPiv.length];

				if (kidKeystream.length < encryptedPiv.length) {
					LOGGER.error("Error KID_KEYSTREAM is too short when performing KID encryption.");
				}

				for (int i = 0; i < encryptedKid.length; i++) {
					decryptedKid[i] = (byte) (encryptedKid[i] ^ kidKeystream[i]);
				}

				// Now compare the encrypted PIV with the decrypted KID
				if (Arrays.equals(encryptedPiv, decryptedKid)) {
					// Found the correct OSCORE context
					contextFound = true;
					break;
				}
			}
		}

		// Replace the KID in the OSCORE CoAP option
		if (contextFound) {
			OscoreOptionEncoder optionEncoder = new OscoreOptionEncoder();
			optionEncoder.setIdContext(optionDecoder.getIdContext());
			optionEncoder.setKid(decryptedKid);
			optionEncoder.setPartialIV(optionDecoder.getPartialIV());
			message.getOptions().setOscore(optionEncoder.getBytes());
			return ctx;
		}

		return null;
	}

	/**
	 * Compute the keystream to use for XOR encryption/decryption
	 * 
	 * @param input the input from the message
	 * @param encryptionKey the encryption key to use
	 * @return the computed keystream
	 */
	private static byte[] computeKeystream(byte[] input, final byte[] encryptionKey) {
		SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
		byte[] ivKeystream = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			ivKeystream = cipher.doFinal(input);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			LOGGER.error("Error failed to derive the IV_KEYSTREAM for Partial IV encryption/decryption.");
			e.printStackTrace();
		}
		return ivKeystream;
	}

	/**
	 * Prepare the sample and input from the message payload
	 * 
	 * @param message the CoAP message to take the input from
	 * 
	 * @return the 16 byte input
	 */
	private static byte[] composeInput(Message message) {
		byte[] payload = message.getPayload();
		int length = Math.min(payload.length, IV_KEYSTREAM_LENGTH);

		byte[] sample = new byte[length];
		System.arraycopy(payload, 0, sample, 0, length);

		byte[] input = new byte[IV_KEYSTREAM_LENGTH];
		if (length < IV_KEYSTREAM_LENGTH) {
			int padding = IV_KEYSTREAM_LENGTH - length;
			System.arraycopy(sample, 0, input, padding, length);
		} else {
			input = sample;
		}
		return input;
	}

}
