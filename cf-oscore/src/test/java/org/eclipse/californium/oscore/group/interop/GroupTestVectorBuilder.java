package org.eclipse.californium.oscore.group.interop;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.security.Provider;
import java.security.Security;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.UdpEndpointContext;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.ByteId;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.RequestDecryptor;
import org.eclipse.californium.oscore.RequestEncryptor;
import org.eclipse.californium.oscore.ResponseEncryptor;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.GroupRecipientCtx;
import org.eclipse.californium.oscore.group.GroupSenderCtx;
import org.eclipse.californium.oscore.group.MultiKey;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

/**
 * Class to produce test vectors for Group OSCORE.
 * 
 * 
 */
public class GroupTestVectorBuilder {

	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;
	private static boolean pairwiseResponse = true;

	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	private final static AlgorithmID algSignEnc = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] id_context = new byte[] { (byte) 0xdd, (byte) 0x11 };

	private static byte[] sid = new byte[] { 0x25 };
	private static byte[] sid_public_key_bytes;
	private static byte[] sid_private_key_bytes;
	private static MultiKey sid_full_key;

	private final static byte[] rid1 = new byte[] { 0x52 };
	private static byte[] rid1_public_key_bytes;
	private static byte[] rid1_private_key_bytes;
	private static MultiKey rid1_full_key;

	private final static byte[] rid2 = new byte[] { 0x77 };
	private static byte[] rid2_public_key_bytes;
	private static byte[] rid2_private_key_bytes;
	private static MultiKey rid2_full_key;

	private static byte[] gm_public_key_bytes;

	private static final int REPLAY_WINDOW = 32;

	static int initial_seq = 0;

	/**
	 * Main method for test vector generator. Generates test vectors according
	 * to configuration in to a text file.
	 * 
	 * @param args input arguments
	 * @throws OSException on failure
	 * @throws FileNotFoundException on failure to write output file
	 */
	public static void main(String[] args) throws OSException, FileNotFoundException {

		// Redirect println
		// https://www.tutorialspoint.com/redirecting-system-out-println-output-to-a-file-in-java
		String mode = "groupResp";
		if (pairwiseResponse) {
			mode = "pairwiseResp";
		}
		String fileName = "vectors-" + algCountersign + "-" + mode + ".txt";
		File theFile = new File(fileName);
		PrintStream stream = new PrintStream(theFile);
		System.out.println("From now on " + theFile.getAbsolutePath() + " will be your console");
		System.setOut(stream);
		System.setErr(stream);

		// Set keys depending on algorithm (ECDSA P-256/EdDSA Ed25519)
		if (algCountersign == AlgorithmID.EDDSA) {

			sid_public_key_bytes = StringUtil.hex2ByteArray(
					"a501781b636f6170733a2f2f746573746572312e6578616d706c652e636f6d02666d796e616d6503781a636f6170733a2f2f68656c6c6f312e6578616d706c652e6f7267041a70004b4f08a101a4010103272006215820069e912b83963acc5941b63546867dec106e5b9051f2ee14f3bc5cc961acd43a");
			sid_private_key_bytes = net.i2p.crypto.eddsa.Utils
					.hexToBytes("64714d41a240b61d8d823502717ab088c9f4af6fc9844553e4ad4c42cc735239");

			rid1_public_key_bytes = StringUtil.hex2ByteArray(
					"a501781a636f6170733a2f2f7365727665722e6578616d706c652e636f6d026673656e64657203781a636f6170733a2f2f636c69656e742e6578616d706c652e6f7267041a70004b4f08a101a401010327200621582077ec358c1d344e41ee0e87b8383d23a2099acd39bdf989ce45b52e887463389b");
			rid1_private_key_bytes = net.i2p.crypto.eddsa.Utils
					.hexToBytes("857eb61d3f6d70a278a36740d132c099f62880ed497e27bdfd4685fa1a304f26");

			rid2_public_key_bytes = StringUtil.hex2ByteArray(
					"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026773656E6465723203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A40101032720062158202430471D8D1D60F739DBD6F9B080E08A67CACBF811FE42537E03A8C9ABBDFD06");
			rid2_private_key_bytes = net.i2p.crypto.eddsa.Utils
					.hexToBytes("CAA31F0CF65A10208C79EB4E9D82A43D9352C0B9D67DFDE0D18561F7CAC1D726");

			gm_public_key_bytes = StringUtil.hex2ByteArray(
					"a501781a636f6170733a2f2f6d79736974652e6578616d706c652e636f6d026c67726f75706d616e6167657203781a636f6170733a2f2f646f6d61696e2e6578616d706c652e6f7267041aab9b154f08a101a4010103272006215820cde3efd3bc3f99c9c9ee210415c6cba55061b5046e963b8a58c9143a61166472");

		} else if (algCountersign == AlgorithmID.ECDSA_256) {
			sid_public_key_bytes = StringUtil.hex2ByteArray(
					"A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A5010202412522582064CE3DD128CC4EFA6DE209BE8ABD111C7272F612C2DB654057B6EC00FBFB06842158201ADB2AB6AF48F17C9877CF77DB4FA39DC0923FBE215E576FE6F790B1FF2CBC962001");
			sid_private_key_bytes = net.i2p.crypto.eddsa.Utils
					.hexToBytes("FEA2190084748436543C5EC8E329D2AFBD7068054F595CA1F987B9E43E2205E6");

			rid1_public_key_bytes = StringUtil.hex2ByteArray(
					"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A501020241522258201897A28666FE1CC4FACEF79CC7BDECDC271F2A619A00844FCD553A12DD679A4F2158200EB313B4D314A1001244776D321F2DD88A5A31DF06A6EEAE0A79832D39408BC12001");
			rid1_private_key_bytes = net.i2p.crypto.eddsa.Utils
					.hexToBytes("DA2593A6E0BCC81A5941069CB76303487816A2F4E6C0F21737B56A7C90381597");

			rid2_public_key_bytes = StringUtil.hex2ByteArray(
					"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026773656E6465723203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A501020241522258202B123F25C5AF78614BDCC39AF89DC61D3177E063E7BB0FEC3475CC18CFE6BF1F215820E24E9B1564CF6FB5D35C8146531241733684810B5CC4FEE36C66B4B96F0DA33F2001");
			rid2_private_key_bytes = net.i2p.crypto.eddsa.Utils
					.hexToBytes("B811BDBD3E8F03BF03C5F2763FC5BE560109E45B7392740C76E90210CB324B96");

			gm_public_key_bytes = StringUtil.hex2ByteArray(
					"A501781A636F6170733A2F2F6D79736974652E6578616D706C652E636F6D026C67726F75706D616E6167657203781A636F6170733A2F2F646F6D61696E2E6578616D706C652E6F7267041AAB9B154F08A101A5010202402258205694315AD17A4DA5E3F69CA02F83E9C3D594712137ED8AFB748A70491598F9CD215820FAD4312A45F45A3212810905B223800F6CED4BC8D5BACBC8D33BB60C45FC98DD2001");

		} else {
			System.err.println("Invalid algCountersign!");
		}

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		sid_full_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);

		System.out.println();
		System.out.println("The CoAP client C and the CoAP server S1 and S2 are member of an OSCORE group." + "\n");

		System.out.println();
		System.out.println("[Setup]" + "\n");

		System.out.println("AEAD Algorithm: " + alg.AsCBOR() + " (" + alg + ")" + "\n");

		System.out.println("HKDF Algorithm: " + kdf + "\n");

		System.out.println("Signature Encryption Algorithm: " + algSignEnc.AsCBOR() + " (" + algSignEnc + ")" + "\n");

		System.out.println("Signature Algorithm: " + algCountersign);
		if (algCountersign == AlgorithmID.ECDSA_256) {
			System.out.println("Note that since ECDSA is used, signatures are NOT deterministic");
		}
		System.out.println();

		System.out.println("Pairwise Key Agreement Algorithm: " + algKeyAgreement + "\n");

		System.out.println("\n");

		System.out.println();
		System.out.println("Master Secret: " + Utils.bytesToHex(master_secret) + "\n");

		System.out.println("Master Salt: " + Utils.bytesToHex(master_salt) + "\n");

		System.out.println("ID Context: " + Utils.bytesToHex(id_context) + "\n");

		System.out.println("\n");

		// Client #1

		System.out.println("Client's Sender ID: " + Utils.bytesToHex(sid) + "\n");

		System.out.println("Client's authentication credential as CCS (diagnostic notation): " + "\n"
				+ printDiagnostic(sid_public_key_bytes) + "\n");

		System.out.println("Client's authentication credential as CCS (serialization): "
				+ Utils.bytesToHex(sid_public_key_bytes) + "\n");

		System.out.println("Client's private key: " + Utils.bytesToHex(sid_private_key_bytes) + "\n");

		// Server #1

		System.out.println();
		System.out.println("Server #1's Sender ID: " + Utils.bytesToHex(rid1) + "\n");

		System.out.println("Server #1's authentication credential as CCS (diagnostic notation): " + "\n"
				+ printDiagnostic(rid1_public_key_bytes) + "\n");

		System.out.println("Server #1's authentication credential as CCS (serialization): "
				+ Utils.bytesToHex(rid1_public_key_bytes) + "\n");

		System.out
				.println("Server #1's private key (serialization): " + Utils.bytesToHex(rid1_private_key_bytes) + "\n");

		// Server #2

		System.out.println();
		System.out.println("Server #2's Sender ID: " + Utils.bytesToHex(rid2) + "\n");

		System.out.println("Server #2's authentication credential as CCS (diagnostic notation): " + "\n"
				+ printDiagnostic(rid2_public_key_bytes) + "\n");

		System.out.println("Server #2's authentication credential as CCS (serialization): "
				+ Utils.bytesToHex(rid2_public_key_bytes) + "\n");

		System.out
				.println("Server #2's private key (serialization): " + Utils.bytesToHex(rid2_private_key_bytes) + "\n");

		// GM

		System.out.println("Group Manager's authentication credential as CCS (diagnostic notation): " + "\n"
				+ printDiagnostic(gm_public_key_bytes) + "\n");

		System.out.println("Group Manager's authentication credential as CCS (serialization): "
				+ Utils.bytesToHex(gm_public_key_bytes) + "\n");

		// === Build context

		// Create client context
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, id_context, algCountersign,
				gm_public_key_bytes);
		commonCtx.addSenderCtxCcs(sid, sid_full_key);

		commonCtx.senderCtx.setSenderSeq(initial_seq);

		// === Send request

		System.out.println();
		System.out.println("[Request]: " + "\n");

		// Create request message from raw byte array
		// byte[] requestBytes = Utils.hexToBytes(
		// "48019483f0aeef1c796812a0ba68656c6c6f576f726c64ed010c13404b3a7c9f8c878a0b5246cca71e3926f0a8cebefdcabbc80e79579d5a1ee17d");
		byte[] requestBytes = Utils.hexToBytes("48019483f0aeef1c796812a0ba68656c6c6f576f726c64");

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(requestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}

		System.out.println("Unprotected CoAP request: " + Utils.bytesToHex(requestBytes) + "\n");

		HashMapCtxDB db = new HashMapCtxDB();
		Assert.assertNotNull(r);
		db.addContext(r.getURI(), commonCtx);

		// Encrypt the request message
		Request encrypted = RequestEncryptor.encrypt(db, r);

		System.out.println("Encrypted request: ");
		byte[] requestOscoreOption = encrypted.getOptions().getOscore();
		System.out.println("OSCORE option: " + Utils.bytesToHex(requestOscoreOption));
		System.out.println("Payload: " + Utils.bytesToHex(encrypted.getPayload()));

		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedReqBytes = serializer.getByteArray(encrypted);

		System.out.println("Full content: " + Utils.bytesToHex(encryptedReqBytes));

		// Receive request and produce response (Server #1)

		db.purge();

		rid1_full_key = new MultiKey(rid1_public_key_bytes, rid1_private_key_bytes);
		GroupCtx commonCtxSrv1 = new GroupCtx(master_secret, master_salt, alg, kdf, id_context, algCountersign,
				gm_public_key_bytes);
		commonCtxSrv1.addSenderCtxCcs(rid1, rid1_full_key);
		commonCtxSrv1.addRecipientCtxCcs(sid, REPLAY_WINDOW, sid_full_key);

		db.addContext("", commonCtxSrv1);

		encrypted.setSourceContext(new UdpEndpointContext(new InetSocketAddress(0)));
		GroupRecipientCtx recipientCtx = commonCtxSrv1.recipientCtxMap.get(new ByteId(sid));
		db.addContext(recipientCtx);

		// Decrypt the request message
		Request decrypted = RequestDecryptor.decrypt(db, encrypted, recipientCtx);
		decrypted.getOptions().removeOscore();

		serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(decrypted);

		System.out.println("Decrypted request: " + Utils.bytesToHex(decryptedBytes));

		// === Prepare and send response (Server #1)

		System.out.println("");
		System.out.println("[Server #1] [Response to Request]" + "\n");
		System.out.println("[Server #1] Response using pairwise mode: " + pairwiseResponse);

		byte[] responseBytes = new byte[] { 0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, (byte) 0xff, 0x48, 0x65,
				0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };

		parser = new UdpDataParser();
		Message respMess = parser.parseMessage(responseBytes);

		Response resp = null;
		if (respMess instanceof Response) {
			resp = (Response) respMess;
		}

		// Encrypt the response message (Server #1)

		GroupSenderCtx senderCtx = commonCtxSrv1.senderCtx;
		senderCtx.setSenderSeq(initial_seq);
		senderCtx.setResponsesIncludePartialIV(false);
		commonCtxSrv1.setPairwiseModeResponses(pairwiseResponse);

		boolean newPartialIV = false;
		boolean outerBlockwise = false;
		Response encryptedResp = ResponseEncryptor.encrypt(db, resp, senderCtx, newPartialIV, outerBlockwise,
				initial_seq, requestOscoreOption);

		serializer = new UdpDataSerializer();
		byte[] encryptedRespBytes = serializer.getByteArray(encryptedResp);

		System.out.println("[Server #1] Bytes of encrypted response: " + Utils.bytesToHex(encryptedRespBytes));

		// Receive request and produce response (Server #2)

		parser = new UdpDataParser();
		encrypted = (Request) parser.parseMessage(encryptedReqBytes);

		db.purge();

		rid2_full_key = new MultiKey(rid2_public_key_bytes, rid2_private_key_bytes);
		GroupCtx commonCtxSrv2 = new GroupCtx(master_secret, master_salt, alg, kdf, id_context, algCountersign,
				gm_public_key_bytes);
		commonCtxSrv2.addSenderCtxCcs(rid2, rid2_full_key);
		commonCtxSrv2.addRecipientCtxCcs(sid, REPLAY_WINDOW, sid_full_key);

		db.addContext("", commonCtxSrv2);

		encrypted.setSourceContext(new UdpEndpointContext(new InetSocketAddress(0)));
		recipientCtx = commonCtxSrv2.recipientCtxMap.get(new ByteId(sid));
		db.addContext(recipientCtx);

		// Decrypt the request message
		decrypted = RequestDecryptor.decrypt(db, encrypted, recipientCtx);
		decrypted.getOptions().removeOscore();

		serializer = new UdpDataSerializer();
		decryptedBytes = serializer.getByteArray(decrypted);

		System.out.println("Decrypted request: " + Utils.bytesToHex(decryptedBytes));

		// === Prepare and send response (Server #2)

		System.out.println("");
		System.out.println("[Server #2] [Response to Request]" + "\n");
		System.out.println("[Server #2] Response using pairwise mode: " + pairwiseResponse);

		responseBytes = new byte[] { 0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, (byte) 0xff, 0x48, 0x65,
				0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };

		parser = new UdpDataParser();
		respMess = parser.parseMessage(responseBytes);

		resp = null;
		if (respMess instanceof Response) {
			resp = (Response) respMess;
		}

		// Encrypt the response message (Server #2)

		senderCtx = commonCtxSrv2.senderCtx;
		senderCtx.setSenderSeq(initial_seq);
		senderCtx.setResponsesIncludePartialIV(false);
		commonCtxSrv2.setPairwiseModeResponses(pairwiseResponse);

		newPartialIV = false;
		outerBlockwise = false;
		encryptedResp = ResponseEncryptor.encrypt(db, resp, senderCtx, newPartialIV, outerBlockwise,
				initial_seq, requestOscoreOption);

		serializer = new UdpDataSerializer();
		encryptedRespBytes = serializer.getByteArray(encryptedResp);

		System.out.println("[Server #2] Bytes of encrypted response: " + Utils.bytesToHex(encryptedRespBytes));

		stream.close();
	}

	private static String printDiagnostic(byte[] input) {
		String temp = CBORObject.DecodeFromBytes(input).toString();

		return temp.replace(",", ",\n") + "\n\n\n\n\n\n\n";
	}

}
