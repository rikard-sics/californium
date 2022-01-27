package org.eclipse.californium.oscore;

import java.math.BigInteger;
import java.util.Arrays;

// https://datatracker.ietf.org/doc/html/rfc8613#section-6.1
public class OscoreOptionDecoder {

	private boolean decoded;
	private byte[] encodedBytes;

	private byte[] idContext;
	private byte[] partialIV;
	private byte[] kid;

	private int n;
	private int k;
	private int h;

	// Add constructor/method for request and response?
	public OscoreOptionDecoder(byte[] encodedBytes) {
		this.encodedBytes = encodedBytes;
	}

	public void setBytes(byte[] encodedBytes) {
		this.encodedBytes = encodedBytes;
		decoded = false;
	}

	/**
	 * 
	 * @return
	 */
	private void decode() {
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
		int k = flagByte & 0x08;
		int h = flagByte & 0x10;

		byte[] partialIV = null;
		byte[] kid = null;
		byte[] kidContext = null;
		int index = 1;

		// Parsing Partial IV
		if (n > 0) {
			partialIV = Arrays.copyOfRange(total, index, index + n);
			index += n;
		}

		// Parsing KID Context
		if (h != 0) {
			int s = total[index];

			kidContext = Arrays.copyOfRange(total, index + 1, index + 1 + s);

			index += s + 1;
		}

		// Parsing KID
		kid = Arrays.copyOfRange(total, index, total.length);

		// Store parsed data in this object
		this.n = n;
		this.k = k;
		this.h = h;
		this.partialIV = partialIV;
		this.kid = kid;
		this.idContext = kidContext;
		decoded = true;
	}

	/**
	 * @return the idContext
	 */
	public byte[] getIdContext() {
		if (!decoded) {
			decode();
		}

		return idContext;
	}

	/**
	 * @return the partialIV
	 */
	public byte[] getPartialIV() {
		if (!decoded) {
			decode();
		}

		return partialIV;
	}

	/**
	 * 
	 * 
	 * @return the sequence number (based on the Partial IV)
	 */
	public int getSequenceNumber() {
		if (!decoded) {
			decode();
		}

		if (partialIV == null) {// FIXME
			return 0;
		}

		return (new BigInteger(partialIV).intValue()); // FIXME

		// if (Arrays.equals(partialIV, new byte[] { 0x00 })) {
		// return 0;
		// } else {
		// return ByteBuffer.wrap(partialIV).getInt();
		// }

	}

	/**
	 * @return the kid
	 */
	public byte[] getKid() {
		if (!decoded) {
			decode();
		}

		return kid;
	}

	/**
	 * @return the n
	 */
	public int getN() {
		if (!decoded) {
			decode();
		}

		return n;
	}

	/**
	 * @return the k
	 */
	public int getK() {
		if (!decoded) {
			decode();
		}

		return k;
	}

	/**
	 * @return the h
	 */
	public int getH() {
		if (!decoded) {
			decode();
		}

		return h;
	}

}
