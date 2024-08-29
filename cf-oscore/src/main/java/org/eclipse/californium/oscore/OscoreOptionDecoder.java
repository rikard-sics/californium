/*******************************************************************************
 * Copyright (c) 2022 RISE and others.
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
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.Arrays;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.elements.util.DatagramReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class for decoding the bytes of an OSCORE CoAP option.
 * 
 * See the structure of the option:
 * https://datatracker.ietf.org/doc/html/rfc8613#section-6.1
 * 
 */
public class OscoreOptionDecoder {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OscoreOptionDecoder.class);

	private byte[] encodedBytes;

	private byte[] idContext;
	private byte[] partialIV;
	private byte[] kid;

	private byte[] nonce;

	private int n;
	private int k;
	private int h;

	private int m;
	private int d;
	private int x;
	private int nonceLength;

	private int z;
	private int b;
	private int p;

	private int y;
	private int w;
	private byte[] oldNonce;
	private int oldNonceLength;

	/**
	 * Initialize the OSCORE option with a certain array of bytes and decode
	 * them into the parameters of the option.
	 * 
	 * @param encodedBytes the encoded bytes of the option
	 * @throws CoapOSException if the option is malformed
	 */
	public OscoreOptionDecoder(byte[] encodedBytes) throws CoapOSException {
		this.encodedBytes = encodedBytes;
		decode();
	}

	/**
	 * Set the OSCORE option to a certain array of bytes and decode them into
	 * the parameters of the option.
	 * 
	 * @param encodedBytes the encoded bytes of the option
	 * @throws CoapOSException if the option is malformed
	 */
	public void setBytes(byte[] encodedBytes) throws CoapOSException {
		this.encodedBytes = encodedBytes;
		decode();
	}

	/**
	 * Performs the decoding of the option and stores the resulting parameters
	 * in this object.
	 * 
	 * @throws CoapOSException if the option is malformed
	 */
	private void decode() throws CoapOSException {
		byte[] total = encodedBytes;

		/**
		 * If the OSCORE option value is a zero length byte array it represents
		 * a byte array of length 1 with a byte 0x00 See
		 * https://tools.ietf.org/html/draft-ietf-core-object-security-16#section-2
		 */
		if (total.length == 0) {
			total = new byte[] { 0x00 };
		}

		byte flagByte = total[0];

		int n = flagByte & 0x07;
		int k = (flagByte & 0x08) >> 3;
		int h = (flagByte & 0x10) >> 4;
		int extension = (flagByte & 0x80);

		byte[] partialIV = null;
		byte[] kid = null;
		byte[] kidContext = null;
		byte[] nonce = null;
		int index = 1;

		int d = 0;
		int m = 0;
		int x = 0;

		int z = 0;
		int b = 0;
		int p = 0;
		int nonceLength = 0;

		int y = 0;
		int w = 0;
		int oldNonceLength = 0;
		byte[] oldNonce = null;

		if (extension != 0) {
			byte flagByte2 = total[1];
			d = (flagByte2 & 0x01);

			index = 2;
		}

		try {
			// Parsing Partial IV
			if (n > 0) {
				partialIV = Arrays.copyOfRange(total, index, index + n);
				index += n;
			}
		} catch (Exception e) {
			LOGGER.error("Failed to parse Partial IV in OSCORE option.");
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		try {
			// Parsing KID Context
			if (h != 0) {
				int s = total[index++];

				kidContext = Arrays.copyOfRange(total, index, index + s);

				index += s;
			}
		} catch (Exception e) {
			LOGGER.error("Failed to parse KID Context in OSCORE option.");
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		try {
			// Parsing x byte and KUDOS nonce
			if (d != 0) {
				x = total[index++];
				m = (x & 0x0F);

				z = (x & 0b01000000) >> 6;
				b = (x & 0b00100000) >> 5;
				p = (x & 0b00010000) >> 4;

				nonceLength = m + 1;
				nonce = Arrays.copyOfRange(total, index, index + nonceLength);

				index += nonceLength;

				// Parsing y byte and KUDOS old_nonce
				if (z != 0) {
					y = total[index++];
					w = (y & 0x0F);
					oldNonceLength = w + 1;
					oldNonce = Arrays.copyOfRange(total, index, index + oldNonceLength);
					index += oldNonceLength;
				}
			}
		} catch (Exception e) {
			LOGGER.error("Failed to parse KUDOS nonce in OSCORE option.");
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		try {
			// Parsing KID
			if (k != 0) {
				kid = Arrays.copyOfRange(total, index, total.length);
			}
		} catch (Exception e) {
			LOGGER.error("Failed to parse KID in OSCORE option.");
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		// Check option length consistency
		if (k == 0 && index != total.length) {
			// If KID is not present there should be no further data
			LOGGER.error("Extranous data at end of OSCORE option.");
			throw new CoapOSException(ErrorDescriptions.FAILED_TO_DECODE_COSE, ResponseCode.BAD_OPTION);
		}

		// Store parsed data in this object
		this.n = n;
		this.k = k;
		this.h = h;
		this.nonceLength = nonceLength;
		this.m = m;
		this.d = d;
		this.x = x;
		this.z = z;
		this.b = b;
		this.p = p;
		this.y = y;
		this.w = w;
		this.oldNonce = oldNonce;
		this.oldNonceLength = oldNonceLength;
		this.partialIV = partialIV;
		this.kid = kid;
		this.idContext = kidContext;
		this.nonce = nonce;
	}

	/**
	 * Retrieve the ID Context
	 * 
	 * @return the ID Context (kid context)
	 */
	public byte[] getIdContext() {
		return idContext;
	}

	/**
	 * Retrieve the Partial IV
	 * 
	 * @return the Partial IV
	 */
	public byte[] getPartialIV() {
		return partialIV;
	}

	/**
	 * Retrieve the sequence number
	 * 
	 * @return the sequence number (based on the Partial IV)
	 */
	public int getSequenceNumber() {
		if (partialIV == null) {
			return 0;
		}

		return new DatagramReader(partialIV, false).read(partialIV.length * Byte.SIZE);
	}

	/**
	 * Retrieve the KUDOS nonce
	 * 
	 * @return the KUDOS nonce
	 */
	public byte[] getNonce() {
		return nonce;
	}

	/**
	 * Retrieve the KID
	 * 
	 * @return the KID
	 */
	public byte[] getKid() {
		return kid;
	}

	/**
	 * Retrieve the n flag bit
	 * 
	 * @return the n bit (length of Partial IV)
	 */
	public int getN() {
		return n;
	}

	/**
	 * Retrieve the k flag bit
	 * 
	 * @return the k bit (if KID is present)
	 */
	public int getK() {
		return k;
	}

	/**
	 * Retrieve the h flag bit
	 * 
	 * @return the h bit (if ID Context is present)
	 */
	public int getH() {
		return h;
	}

	/**
	 * Return m value from KUDOS x byte
	 * 
	 * @return the m value (nonce length -1)
	 */
	public int getM() {
		return m;
	}

	/**
	 * Return nonce length from KUDOS x byte
	 * 
	 * @return the nonce length (m + 1)
	 */
	public int getNonceLength() {
		return nonceLength;
	}

	/**
	 * Return d value (KUDOS flag)
	 * 
	 * @return the d value (KUDOS flag)
	 */
	public int getD() {
		return d;
	}

	/**
	 * Return KUDOS x byte
	 * 
	 * @return the KUDOS x byte
	 */
	public byte getX() {
		return (byte) x;
	}

	/**
	 * Return p bit (No Forward Secrecy)
	 * 
	 * @return the p bit value
	 */
	public int getP() {
		return p;
	}

	/**
	 * Return b bit (Preserve Observations)
	 * 
	 * @return the b bit value
	 */
	public int getB() {
		return b;
	}

	/**
	 * Return z bit (presence of field 'y' and field 'old_nonce')
	 * 
	 * @return the z bit value
	 */
	public int getZ() {
		return z;
	}

	/**
	 * Return the y byte (contains the length of old_nonce)
	 * 
	 * @return the y value
	 */
	public byte getY() {
		return (byte) y;
	}

	/**
	 * Return the w value (the length of the old_nonce - 1)
	 * 
	 * @return the w value
	 */
	public int getW() {
		return w;
	}

	/**
	 * Return the value of oldNonce
	 * 
	 * @return the oldNonce value
	 */
	public byte[] getOldNonce() {
		return oldNonce;
	}

	/**
	 * Return the length of old_nonce (w + 1)
	 * 
	 * @return the oldNonceLength value
	 */
	public int getOldNonceLength() {
		return oldNonceLength;
	}

}
