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

		// Prepare the sample and input from the message payload
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

		// Generate the IV_KEYSTREAM
		SecretKeySpec keySpec = new SecretKeySpec(pivEncryptionKey, "AES");
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

}
