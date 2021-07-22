package org.eclipse.californium.oscore.group;

import java.util.Arrays;

import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.Utils;

//TODO: Need clone?
public class MultiKey {

	private byte[] rawKeyBytes;
	private OneKey coseKey;

	public MultiKey(byte[] rawKeyBytes) {
		this.rawKeyBytes = rawKeyBytes.clone();
		coseKey = convertToCoseKey(rawKeyBytes, null);

	}

	public MultiKey(byte[] rawKeyBytes, byte[] privateKeyOnly) {
		this.rawKeyBytes = rawKeyBytes.clone();
		coseKey = convertToCoseKey(rawKeyBytes, privateKeyOnly);

	}

	public byte[] getRawKey() {
		return rawKeyBytes.clone();
	}

	public OneKey getCoseKey() {
		return coseKey;
	}

	private void addPrivate(byte[] privateKey) {
		coseKey.add(CBORObject.FromObject(-4), CBORObject.FromObject(privateKey));
	}

	private OneKey convertToCoseKey(byte[] rawKeyBytes, byte[] privateKeyOnly) {
		CBORObject cborKey = CBORObject.DecodeFromBytes(rawKeyBytes);
		OneKey keyy = null;

		// CWT claims set
		if (cborKey.get(8) != null && cborKey.get(8).get(1) != null) {

			// System.out.println("*CWT claims set");

			// System.out.println(cborKey.toString());

			CBORObject test2 = cborKey.get(8);

			// System.out.println(test2.toString());

			CBORObject test3 = test2.get(1);
			// Add private key
			if (privateKeyOnly != null) {
				test3.Add(CBORObject.FromObject(-4), CBORObject.FromObject(privateKeyOnly));
			}

			// System.out.println(test3.toString());

			try {
				keyy = new OneKey(test3);
			} catch (CoseException e) {
				System.err.println("Error converting CWT claims set key bytes to COSE Key");
				e.printStackTrace();
			}
		} else {
			// COSE Key

			// System.out.println("*COSE Key");
			// System.out.println(cborKey.toString());

			// Save private key and strip from byte array if present
			byte[] privateKey = null;
			if (cborKey.get(-4) != null) {

				// System.out.println("Has private part");

				privateKey = cborKey.get(-4).GetByteString();
				// cborKey.Remove(CBORObject.FromObject(-4));

				byte[] privateBytesHeader = new byte[] { 0x23, 0x58, 0x20 };
				byte[] privateBytes = Bytes.concatenate(privateBytesHeader, privateKey);

				int index = indexOf(rawKeyBytes, privateBytes);

				// System.out.println("index: " + index);

				byte[] part1 = Arrays.copyOf(rawKeyBytes, index);
				byte[] part2 = Arrays.copyOfRange(rawKeyBytes, index + privateBytes.length, rawKeyBytes.length);

				// System.out.println("Part 1: " + Utils.bytesToHex(part1));
				// System.out.println("Part 2: " + Utils.bytesToHex(part2));

				this.rawKeyBytes = Bytes.concatenate(part1, part2);
				this.rawKeyBytes[0]--; // Reduce array length
			}

			try {
				keyy = new OneKey(cborKey);
			} catch (CoseException e) {
				System.err.println("Error converting COSE Key key bytes to COSE Key");
				e.printStackTrace();
			}

			// if (cborKey.get(-4) != null) {
			// System.out.println("Adding private part");
			// if (privateKey == null) {
			// System.err.println("Error adding private part");
			// }
			// keyy.add(CBORObject.FromObject(-4),
			// CBORObject.FromObject(privateKey));
			// }

		}

		return keyy;
	}

	/**
	 * Search the data byte array for the first occurrence of the byte array
	 * pattern.
	 * 
	 * @param data data to search through
	 * @param pattern pattern to find
	 * @return index of found pattern
	 */
	public static int indexOf(byte[] data, byte[] pattern) {
		int[] failure = computeFailure(pattern);

		int j = 0;

		for (int i = 0; i < data.length; i++) {
			while (j > 0 && pattern[j] != data[i]) {
				j = failure[j - 1];
			}
			if (pattern[j] == data[i]) {
				j++;
			}
			if (j == pattern.length) {
				return i - pattern.length + 1;
			}
		}
		return -1;
	}

	/**
	 * Computes the failure function using a boot-strapping process, where the
	 * pattern is matched against itself.
	 */
	private static int[] computeFailure(byte[] pattern) {
		int[] failure = new int[pattern.length];

		int j = 0;
		for (int i = 1; i < pattern.length; i++) {
			while (j > 0 && pattern[j] != pattern[i]) {
				j = failure[j - 1];
			}
			if (pattern[j] == pattern[i]) {
				j++;
			}
			failure[i] = j;
		}

		return failure;
	}
}
