package org.eclipse.californium.oscore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.eclipse.californium.elements.util.Bytes;

// https://datatracker.ietf.org/doc/html/rfc8613#section-6.1
public class OscoreOptionEncoder {

	private boolean encoded;
	private byte[] encodedBytes;

	private byte[] idContext;
	private byte[] partialIV;
	private byte[] kid;

	// Add constructor/method for request and response?
	public OscoreOptionEncoder() {
	}

	public byte[] getBytes() {
		if (!encoded) {
			encodedBytes = encode();
			encoded = true;
		}

		return encodedBytes;
	}

	/**
	 * 
	 * @return
	 */
	private byte[] encode() {
		int firstByte = 0x00;
		ByteArrayOutputStream bRes = new ByteArrayOutputStream();

		boolean hasContextID = this.idContext != null;
		boolean hasPartialIV = this.partialIV != null;
		boolean hasKid = this.kid != null;

		// If the Context ID should be included, set its bit
		if (hasContextID) {
			firstByte = firstByte | 0x10;
		}

		// If the KID should be included, set its bit
		if (hasKid) {
			firstByte = firstByte | 0x08; // Set the KID bit
		}

		// If the Partial IV should be included, encode it
		if (hasPartialIV) {
			byte[] partialIV = this.partialIV;
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

		// Encode the Context ID length and value if to be included
		if (hasContextID) {
			try {
				bRes.write(this.idContext.length);
				bRes.write(this.idContext);
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
	 * @return the idContext
	 */
	public byte[] getIdContext() {
		return idContext;
	}

	/**
	 * @param idContext the idContext to set
	 */
	public void setIdContext(byte[] idContext) {
		encoded = false;
		this.idContext = idContext;
	}

	/**
	 * @return the partialIV
	 */
	public byte[] getPartialIV() {
		return partialIV;
	}

	/**
	 * @param partialIV the partialIV to set
	 */
	public void setPartialIV(byte[] partialIV) {
		encoded = false;
		this.partialIV = partialIV;
	}

	/**
	 * @param senderSeq
	 */
	public void setPartialIV(int senderSeq) {
		encoded = false;
		this.partialIV = OSSerializer.processPartialIV(senderSeq);
	}

	/**
	 * @return the kid
	 */
	public byte[] getKid() {
		return kid;
	}

	/**
	 * @param kid the kid to set
	 */
	public void setKid(byte[] kid) {
		encoded = false;
		this.kid = kid;
	}

}
