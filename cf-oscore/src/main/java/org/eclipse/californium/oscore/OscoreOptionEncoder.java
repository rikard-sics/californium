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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.eclipse.californium.elements.util.Bytes;

/**
 * Class for encoding the bytes of an OSCORE CoAP option.
 * 
 * See the structure of the option:
 * https://datatracker.ietf.org/doc/html/rfc8613#section-6.1
 * 
 */
public class OscoreOptionEncoder {

	private boolean encoded;
	private byte[] encodedBytes;

	private byte[] idContext;
	private byte[] partialIV;
	private byte[] kid;

	private byte[] nonce;
	private byte[] oldNonce;

	private int p;
	private int b;

	/**
	 * Retrieve the encoded bytes of the OSCORE option.
	 * 
	 * @return the encoded OSCORE option bytes
	 */
	public byte[] getBytes() {
		if (!encoded) {
			encodedBytes = encode();
		}

		return encodedBytes;
	}

	/**
	 * Encode the set parameters into the bytes of the OSCORE option.
	 * 
	 * @return the bytes of the OSCORE option
	 */
	private byte[] encode() {
		int firstByte = 0x00;
		int secondByte = 0x00;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();

		boolean hasContextID = this.idContext != null;
		boolean hasPartialIV = this.partialIV != null;
		boolean hasKid = this.kid != null;
		boolean hasNonce = this.nonce != null;
		boolean hasOldNonce = this.oldNonce != null;

		// If the Context ID should be included, set its bit
		if (hasContextID) {
			firstByte = firstByte | 0x10;
		}

		// If the KID should be included, set its bit
		if (hasKid) {
			firstByte = firstByte | 0x08; // Set the KID bit
		}

		// If the KUDOS nonce should be included, set the extension and d bits
		if (hasNonce) {
			firstByte = firstByte | 0x80; // Set the extension bit
			secondByte = secondByte | 0x01; // Set the d bit
		}

		// If the Partial IV should be included, encode it
		if (hasPartialIV) {
			byte[] partialIV = this.partialIV;
			firstByte = firstByte | (partialIV.length & 0x07);

			bRes.write(firstByte);
			if (hasNonce) {
				bRes.write(secondByte);
			}

			try {
				bRes.write(partialIV);
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			bRes.write(firstByte);
		}

		// Encode the Context ID length and value if to be included
		if (hasContextID) {
			try {
				bRes.write(this.idContext.length);
				bRes.write(this.idContext);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		// Encode the x byte, KUDOS nonce and flags if to be included
		if (hasNonce) {
			int x = nonce.length - 1;

			// Set flags
			x |= b << 5;
			x |= p << 4;

			if (hasOldNonce) {
				x |= 1 << 6; // z bit
			}

			try {
				bRes.write(x);
				bRes.write(this.nonce);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		// Encode the y byte and KUDOS old_nonce
		if (hasOldNonce) {
			int y = oldNonce.length - 1;

			try {
				bRes.write(y);
				bRes.write(this.oldNonce);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		// Encode Sender ID (KID)
		if (hasKid) {
			try {
				bRes.write(this.kid);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		// Set the option as encoded
		encoded = true;

		// If the OSCORE option is length 1 and 0x00, it should be empty
		// https://tools.ietf.org/html/draft-ietf-core-object-security-16#section-2
		byte[] optionBytes = bRes.toByteArray();
		if (optionBytes.length == 1 && optionBytes[0] == 0x00) {
			return Bytes.EMPTY;
		} else {
			return optionBytes;
		}
	}

	/**
	 * Retrieve the set ID Context
	 * 
	 * @return the ID Context (kid context)
	 */
	public byte[] getIdContext() {
		return idContext;
	}

	/**
	 * Set the ID Context
	 * 
	 * @param idContext the ID Context (kid context) to set
	 */
	public void setIdContext(byte[] idContext) {
		encoded = false;
		this.idContext = idContext;
	}

	/**
	 * Retrieve the set Partial IV
	 * 
	 * @return the Partial IV
	 */
	public byte[] getPartialIV() {
		return partialIV;
	}

	/**
	 * Set the Partial IV
	 * 
	 * @param partialIV the Partial IV to set
	 */
	public void setPartialIV(byte[] partialIV) {
		encoded = false;
		this.partialIV = partialIV;
	}

	/**
	 * Set the Partial IV (based on an integer sequence number)
	 * 
	 * @param senderSeq the sequence number to set as Partial IV
	 */
	public void setPartialIV(int senderSeq) {
		encoded = false;
		this.partialIV = OSSerializer.processPartialIV(senderSeq);
	}

	/**
	 * Retrieve the set KID
	 * 
	 * @return the KID
	 */
	public byte[] getKid() {
		return kid;
	}

	/**
	 * Set the KID
	 * 
	 * @param kid the KID to set
	 */
	public void setKid(byte[] kid) {
		encoded = false;
		this.kid = kid;
	}

	/**
	 * Set the KUDOS nonce
	 * 
	 * @param nonce the KUDOS nonce to set
	 */
	public void setNonce(byte[] nonce) {
		encoded = false;
		this.nonce = nonce;
	}

	/**
	 * Retrieve the set KUDOS nonce
	 * 
	 * @return the KUDOS nonce
	 */
	public byte[] getNonce() {
		return nonce;
	}

	/**
	 * Set the KUDOS old_nonce
	 * 
	 * @param oldNonce the KUDOS old_nonce to set
	 */
	public void setOldNonce(byte[] oldNonce) {
		encoded = false;
		this.oldNonce = oldNonce;
	}

	/**
	 * Retrieve the set KUDOS old_nonce
	 * 
	 * @return the KUDOS old_nonce
	 */
	public byte[] getOldNonce() {
		return oldNonce;
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
	 * Return p bit (No Forward Secrecy)
	 * 
	 * @param p the p bit value to set
	 */
	public void setP(int p) {
		encoded = false;
		this.p = p;
	}

	/**
	 * Return b bit (Preserve Observations)
	 * 
	 * @param b the b bit value to set
	 */
	public void setB(int b) {
		encoded = false;
		this.b = b;
	}

}
