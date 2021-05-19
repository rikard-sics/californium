/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
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
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.Utils;

/**
 * Class with JUnits to test the extended EDHOC test vectors from:
 * 
 * https://github.com/lake-wg/edhoc/blob/master/test-vectors-05/vectors.txt
 *
 */
public class VectorsTxtTest {

	// Lists and headers for the test vector values
	static int numberOfVectors = 16;

	static String newVectorSectionLabel = "Test Vectors for EHDOC";

	static String methodCorrLabel = "METHOD_CORR (4 * method + corr) (int)";
	static List<Integer> methodCorrList = new ArrayList<Integer>();

	static String supportedCipherSuitesLabel = "Supported Cipher Suites";
	static List<Integer> supportedCipherSuitesList = new ArrayList<Integer>();

	static String initiatorEphemeralPrivateLabel = "X (Initiator's ephemeral private key)";
	static List<byte[]> initiatorEphemeralPrivateList = new ArrayList<byte[]>();

	static String initiatorEphemeralPublicLabel = "G_X (Initiator's ephemeral public key)";
	static List<byte[]> initiatorEphemeralPublicList = new ArrayList<byte[]>();

	static String connectionIdLabel = "Connection identifier chosen by Initiator";
	static List<byte[]> connectionIdList = new ArrayList<byte[]>();

	static String message1Label = "message_1 (CBOR Sequence)";
	static List<byte[]> message1List = new ArrayList<byte[]>();

	static String ad1Label = "AD_1";
	static List<byte[]> ad1List = new ArrayList<byte[]>();

	/**
	 * Parse the vectors.txt file and prepare lists with its contents for the
	 * JUnit tests.
	 * 
	 * @throws IOException on failure to read the test vector file
	 */
	@BeforeClass
	public static void parseVectorsTxt() throws IOException {
		File file = new File("vectors.txt");
		FileReader fr = new FileReader(file);
		BufferedReader br = new BufferedReader(fr);

		String line;
		int currentVector = -1;
		while ((line = br.readLine()) != null) {

			if (line.startsWith(methodCorrLabel)) {
				line = br.readLine();

				int methodCorr = Integer.valueOf(line);
				methodCorrList.add(currentVector, methodCorr);

			} else if (line.startsWith(supportedCipherSuitesLabel)) {
				line = br.readLine();

				int supportedCipherSuites = Integer.valueOf(line.replace(" ", ""), 16);
				supportedCipherSuitesList.add(currentVector, supportedCipherSuites);

			} else if (line.startsWith(initiatorEphemeralPrivateLabel)) {
				line = br.readLine() + br.readLine();

				byte[] initiatorEphemeralPrivate = Utils.hexToBytes(line.replace(" ", ""));
				initiatorEphemeralPrivateList.add(currentVector, initiatorEphemeralPrivate);

			} else if (line.startsWith(initiatorEphemeralPublicLabel)) {
				line = br.readLine() + br.readLine();

				byte[] initiatorEphemeralPublic = Utils.hexToBytes(line.replace(" ", ""));
				initiatorEphemeralPublicList.add(currentVector, initiatorEphemeralPublic);

			} else if (line.startsWith(connectionIdLabel)) {
				line = br.readLine();

				byte[] connectionId = Utils.hexToBytes(line.replace(" ", ""));
				connectionIdList.add(currentVector, connectionId);
			} else if (line.startsWith(message1Label)) {
				line = br.readLine() + br.readLine() + br.readLine();

				byte[] message1 = Utils.hexToBytes(line.replace(" ", ""));
				message1List.add(currentVector, message1);
			} else if (line.startsWith(ad1Label)) {
				line = br.readLine();

				byte[] ad1 = Utils.hexToBytes(line.replace(" ", ""));
				ad1List.add(currentVector, ad1);

			} else if (line.startsWith(newVectorSectionLabel)) {
				currentVector++;
			}

		}
		br.close();
		fr.close();

		// Check that all test vectors were read
		Assert.assertEquals(numberOfVectors, methodCorrList.size());
		Assert.assertEquals(numberOfVectors, supportedCipherSuitesList.size());
		Assert.assertEquals(numberOfVectors, initiatorEphemeralPrivateList.size());
		Assert.assertEquals(numberOfVectors, initiatorEphemeralPublicList.size());
		Assert.assertEquals(numberOfVectors, connectionIdList.size());
		Assert.assertEquals(numberOfVectors, message1List.size());
		Assert.assertEquals(numberOfVectors, ad1List.size());
	}

	/**
	 * Parse a byte array representing the uncompressed Suites_I and generate a
	 * list of integer values it contains. If it holds the same value duplicated
	 * twice it is added to the output list only once.
	 * 
	 * @param uncompressedSuitesI byte array of uncompressed Suites_I
	 * @return a list of integers contained
	 */
	private static List<Integer> parseUncompressedSuitesI(byte[] uncompressedSuitesI) {
		System.out.println("Suites: " + Utils.bytesToHex(uncompressedSuitesI));
		CBORObject cborArray = CBORObject.DecodeFromBytes(uncompressedSuitesI);
		List<Integer> outputList = new ArrayList<Integer>();

		// If there are only 2 identical elements add only that to list
		if (cborArray.size() == 2 && (cborArray.get(0) == cborArray.get(1))) {
			outputList.add(cborArray.get(0).AsInt32Value());
			return outputList;
		}

		// Else remove the duplicate value but make sure it is first in list
		for (int i = 0; i < cborArray.size(); i++) {
			outputList.add(cborArray.get(i).AsInt32());
		}

		// Here make sure to remove duplicates from the end
		Set<Integer> set = new LinkedHashSet<>(outputList);
		outputList = new ArrayList<Integer>(set);
		return outputList;
	}

	/**
	 * Test writing a message 1 from a specific value in the test vectors file.
	 * Compares the result with the output from that file.
	 */
	private void testWriteMessage1Vector(int index) {

		// Set up the session to use
		OneKey ltk = Util.generateKeyPair(KeyKeys.OKP_Ed25519.AsInt32()); // Dummy
		boolean initiator = true;
		int methodCorr = methodCorrList.get(index);
		byte[] connectionId = connectionIdList.get(index);
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(supportedCipherSuitesList.get(index)); // 1 suite only
		byte[] ead1 = ad1List.get(index);
		if (ead1.length == 0) { // Consider len 0 ad as null
			ead1 = null;
		}
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		byte[] idCredKid = new byte[] {(byte) 0x24};
		CBORObject idCred = Util.buildIdCredKid(idCredKid);
		byte[] cred = Util.buildCredRawPublicKey(ltk, "");

		// Set the applicability statement
		// - Supported correlation 1 and 2		
		// - Supported authentication methods
		// - Use of the CBOR simple value Null (i.e., the 0xf6 byte), as first element of message_1
		// - Use of message_4 as expected to be sent by the Responder
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++ )
			authMethods.add(i);
		AppStatement appStatement = new AppStatement(true, authMethods, false, false);
		
		// Specify the processor of External Authorization Data
		KissEDP epd = new KissEDP();
		
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionId, ltk,
				                                idCred, cred, cipherSuites, appStatement, epd);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = initiatorEphemeralPrivateList.get(index);
		byte[] publicEkeyBytes = initiatorEphemeralPublicList.get(index);
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		CBORObject[] ead1Array = null;
		if(ead1 != null) {
			try {
				ead1Array = CBORObject.DecodeSequenceFromBytes(ead1);
				if (ead1Array.length < 2) {
					ead1Array = null;
				}
			}
			catch (CBORException e) {
				System.out.println("Malformed or invalid CBOR sequence as EAD_1");
			}
		}
		byte[] message1 = MessageProcessor.writeMessage1(session, ead1Array);

		// Compare with the expected value from the test vectors
		byte[] expectedMessage1 = message1List.get(index);

		// Print parameters used
		System.out.println("methodCorr " + methodCorr);
		System.out.println("connectionId " + Utils.bytesToHex(connectionId));
		System.out.println("ead1 " + Utils.bytesToHex(ead1));
		System.out.println("privateEkeyBytes " + Utils.bytesToHex(privateEkeyBytes));
		System.out.println("publicEkeyBytes " + Utils.bytesToHex(publicEkeyBytes));
		System.out.print("Cipher suites: ");
		for (int i = 0; i < cipherSuites.size(); i++) {
			System.out.print(cipherSuites.get(i) + " ");
		}
		System.out.println("");

		System.out.println("Our message1      " + Utils.bytesToHex(message1));
		System.out.println("Expected message1 " + Utils.bytesToHex(expectedMessage1));

		Assert.assertArrayEquals("Failed on test vector " + index, expectedMessage1, message1);
	}

	@Test
	public void testWriteMessage1Vector00() {
		testWriteMessage1Vector(0);
	}

	@Test
	public void testWriteMessage1Vector01() {
		testWriteMessage1Vector(1);
	}

	@Test
	public void testWriteMessage1Vector02() {
		testWriteMessage1Vector(2);
	}

	@Test
	public void testWriteMessage1Vector03() {
		testWriteMessage1Vector(3);
	}

	@Test
	public void testWriteMessage1Vector04() {
		testWriteMessage1Vector(4);
	}

	@Test
	public void testWriteMessage1Vector05() {
		testWriteMessage1Vector(5);
	}

	@Test
	public void testWriteMessage1Vector06() {
		testWriteMessage1Vector(6);
	}

	@Test
	public void testWriteMessage1Vector07() {
		testWriteMessage1Vector(7);
	}

	@Test
	public void testWriteMessage1Vector08() {
		testWriteMessage1Vector(8);
	}

	@Test
	public void testWriteMessage1Vector09() {
		testWriteMessage1Vector(9);
	}

	@Test
	public void testWriteMessage1Vector10() {
		testWriteMessage1Vector(10);
	}

	@Test
	public void testWriteMessage1Vector11() {
		testWriteMessage1Vector(11);
	}

	@Test
	public void testWriteMessage1Vector12() {
		testWriteMessage1Vector(12);
	}

	@Test
	@Ignore
	public void testWriteMessage1Vector13() {
		testWriteMessage1Vector(13);
	}

	@Test
	public void testWriteMessage1Vector14() {
		testWriteMessage1Vector(14);
	}

	@Test
	public void testWriteMessage1Vector15() {
		testWriteMessage1Vector(15);
	}

}
