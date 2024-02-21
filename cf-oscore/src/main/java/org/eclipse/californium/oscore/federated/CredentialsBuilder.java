package org.eclipse.californium.oscore.federated;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.StringUtil;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * File for generating a Credentials.java for a specific number of servers.
 *
 */
public class CredentialsBuilder {

	/**
	 * Build a CCS including including both a public and private key
	 * 
	 * @param id the subject id to use
	 * 
	 * @return the CCS
	 */
	private static CBORObject buildCcs(int id) {

		// Build the CCS structure
		byte[] ccsBaseBytes = StringUtil.hex2ByteArray(
				"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B");
		CBORObject ccs = CBORObject.DecodeFromBytes(ccsBaseBytes);

		// Set a different subject for each key
		ccs.set(2, CBORObject.FromObject(Integer.toString(id)));

		// Generate a COSE OneKey
		OneKey key = null;
		try {
			key = OneKey.generateKey(AlgorithmID.EDDSA);
		} catch (CoseException e) {
			System.err.println("Failed to generate COSE OneKey");
			e.printStackTrace();
		}

		// Set the OneKey in the CCS
		ccs.get(8).set(1, key.AsCBOR());

		// Print the entire CCS
		// printWriter.println(ccs);
		// printWriter.println(Utils.toHexString(ccs.EncodeToBytes()));

		return ccs;
	}

	/**
	 * Build a Credentials Java source file
	 */
	private static void buildCredentialsFile() {
		// Number of servers to consider
		int SERVER_COUNT = 100;

		// Initialize file for writing
		FileWriter fileWriter = null;
		try {
			fileWriter = new FileWriter("Credentials-new.java");
		} catch (IOException e) {
			System.err.println("Error: Failed to open credentials file for writing");
			e.printStackTrace();
		}
		PrintWriter printWriter = new PrintWriter(fileWriter);

		// Create file header
		printWriter.println("package org.eclipse.californium.oscore.federated;");
		printWriter.println();
		printWriter.println("import java.util.HashMap;");
		printWriter.println("import java.util.Map;");
		printWriter.println();
		printWriter.println("import org.eclipse.californium.elements.util.StringUtil;");
		printWriter.println();
		printWriter.println("public class Credentials {");
		printWriter.println();

		// Build server ID map
		printWriter.println("/**");
		printWriter.println("* Map with the Sender IDs of the servers");
		printWriter.println("*/");
		printWriter.println("public static Map<Integer, byte[]> serverSenderIds;");
		printWriter.println("static {");
		printWriter.println("serverSenderIds = new HashMap<>();");
		for (int i = 0; i < SERVER_COUNT; i++) {
			Integer id = i;
			byte[] idArray = new byte[] { id.byteValue() };
			String idString = StringUtil.byteArray2Hex(idArray);
			printWriter.println("serverSenderIds.put(" + i + ", new byte[] { (byte) 0x" + idString + " });");
		}
		printWriter.println("}");
		printWriter.println();

		// Build CCS map
		printWriter.println("/**");
		printWriter.println("* Map with public keys (CCS) for the servers");
		printWriter.println("*/");
		printWriter.println("public static Map<Integer, byte[]> serverPublicKeys;");
		printWriter.println("static {");
		printWriter.println("serverPublicKeys = new HashMap<>();");

		Map<Integer, byte[]> privateKeys = new HashMap<>();
		for (int i = 0; i < SERVER_COUNT; i++) {

			// Create CCS without private key (but saving it)
			CBORObject ccsToAdd = buildCcs(i);

			// Save the private key for later
			byte[] privateKeyBytes = ccsToAdd.get(8).get(1).get(-4).GetByteString();
			privateKeys.put(i, privateKeyBytes);

			ccsToAdd.get(8).get(1).Remove(CBORObject.FromObject(-4));
			String ccsString = StringUtil.byteArray2Hex(ccsToAdd.EncodeToBytes());
			printWriter.println("serverPublicKeys.put(" + i + ", StringUtil.hex2ByteArray(\"" + ccsString + "\"));");
		}
		printWriter.println("}");
		printWriter.println();

		// Build private keys map
		printWriter.println("/**");
		printWriter.println("* Map with private keys for the servers");
		printWriter.println("*/");
		printWriter.println("public static Map<Integer, byte[]> serverPrivateKeys;");
		printWriter.println("static {");
		printWriter.println("serverPrivateKeys = new HashMap<>();");
		for (int i = 0; i < SERVER_COUNT; i++) {
			String privateKeyString = StringUtil.byteArray2Hex(privateKeys.get(i));
			printWriter.println(
					"serverPrivateKeys.put(" + i + ", StringUtil.hex2ByteArray(\"" + privateKeyString + "\"));");
		}
		printWriter.println("}");
		printWriter.println();

		// Build dataset map
		printWriter.println("/**");
		printWriter.println("* Map with the Dataset ID of the servers");
		printWriter.println("*/");
		printWriter.println("public static Map<Integer, String> serverDatasets;");
		printWriter.println("static {");
		printWriter.println("serverDatasets = new HashMap<>();");
		for (int i = 0; i < SERVER_COUNT; i++) {
			int datasetId = (i % 5) + 1;
			String filename = "dataset_c" + datasetId + ".csv";
			printWriter.println("serverDatasets.put(" + i + ", \"" + filename + "\");");
		}
		printWriter.println("}");
		printWriter.println();

		// End the file contents
		printWriter.println("}");
		printWriter.println();

		// Close the file
		printWriter.close();

	}

	public static void main(String args[]) throws Exception {
		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		// buildCcsString(1);
		buildCredentialsFile();
	}

}
