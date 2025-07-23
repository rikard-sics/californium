package org.eclipse.californium.oscore;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(PivEncryptor.class);

	/**
	 * Decrypt the OSCORE Partial IV in the OSCORE CoAP option
	 * https://datatracker.ietf.org/doc/html/draft-tiloca-core-oscore-piv-enc-00
	 * 
	 * @param message the CoAP message
	 * @param ctx the OSCORE Security Context
	 */
	static void decryptPiv(Message message, OSCoreCtx ctx) {
		encryptDecryptPiv(message, ctx);
	}

	/**
	 * Encrypt the OSCORE Partial IV in the OSCORE CoAP option
	 * https://datatracker.ietf.org/doc/html/draft-tiloca-core-oscore-piv-enc-00
	 * 
	 * @param message the CoAP message
	 * @param ctx the OSCORE Security Context
	 */
	static void encryptPiv(Message message, OSCoreCtx ctx) {
		encryptDecryptPiv(message, ctx);
	}

	/**
	 * Encrypt or decrypt the OSCORE Partial IV in the OSCORE CoAP option
	 * https://datatracker.ietf.org/doc/html/draft-tiloca-core-oscore-piv-enc-00
	 * 
	 * @param message the CoAP message
	 * @param ctx the OSCORE Security Context
	 */
	private static void encryptDecryptPiv(Message message, OSCoreCtx ctx) {
		OscoreOptionDecoder optionDecoder = null;
		try {
			optionDecoder = new OscoreOptionDecoder(message.getOptions().getOscore());
		} catch (CoapOSException e) {
			LOGGER.error("Error parsing OSCORE CoAP option for Partial IV decryption.");
			e.printStackTrace();
		}

		// Prepare the input from the message payload
		byte[] payload = message.getPayload();
		int length = Math.min(payload.length, 16);

		byte[] sample = new byte[length];
		System.arraycopy(payload, 0, sample, 0, length);

		byte[] input = new byte[16];
		if (length < 16) {
			// Left-pad SAMPLE with zeros
			int padding = 16 - length;
			System.arraycopy(sample, 0, input, padding, length);
		} else {
			input = sample;
		}

		// Generate the IV_KEYSTREAM
		byte[] pivEncryptionKey = ctx.getPivEncryptionKey();
		SecretKeySpec keySpec = new SecretKeySpec(pivEncryptionKey, "AES");
		byte[] ivKeystream = null;
		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			ivKeystream = cipher.doFinal(input);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			LOGGER.error("Error failed to derive the IV_KEYSTREAM for Partial IV decryption.");
			e.printStackTrace();
		}

		// Actually decrypt the Partial IV (if present)
		byte[] plainPiv = optionDecoder.getPartialIV();
		if (plainPiv == null || plainPiv.length == 0) {
			return;
		}
		byte[] encryptedPartialIV = new byte[plainPiv.length];

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
	
}
