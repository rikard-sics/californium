package org.eclipse.californium.oscore.group.interop;

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

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

/**
 * Class to produce test vectors for Group OSCORE.
 * 
 * 
 */
public class GroupTestVectorBuilder {

	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	private final static AlgorithmID algSignEnc = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;
	private final static AlgorithmID algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] id_context = new byte[] { (byte) 0xdd, (byte) 0x11 };

	private static byte[] sid = new byte[] { 0x25 };
	private static byte[] sid_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"a501781b636f6170733a2f2f746573746572312e6578616d706c652e636f6d02666d796e616d6503781a636f6170733a2f2f68656c6c6f312e6578616d706c652e6f7267041a70004b4f08a101a4010103272006215820069e912b83963acc5941b63546867dec106e5b9051f2ee14f3bc5cc961acd43a");
	private static byte[] sid_private_key_bytes = net.i2p.crypto.eddsa.Utils
			.hexToBytes("64714d41a240b61d8d823502717ab088c9f4af6fc9844553e4ad4c42cc735239");
	private static MultiKey sid_full_key;

	private final static byte[] rid = new byte[] { 0x52 };
	private final static byte[] rid_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"a501781a636f6170733a2f2f7365727665722e6578616d706c652e636f6d026673656e64657203781a636f6170733a2f2f636c69656e742e6578616d706c652e6f7267041a70004b4f08a101a401010327200621582077ec358c1d344e41ee0e87b8383d23a2099acd39bdf989ce45b52e887463389b");
	private static byte[] rid_private_key_bytes = net.i2p.crypto.eddsa.Utils
			.hexToBytes("857eb61d3f6d70a278a36740d132c099f62880ed497e27bdfd4685fa1a304f26");
	private static MultiKey rid_full_key;

	private final static byte[] gm_public_key_bytes = net.i2p.crypto.eddsa.Utils.hexToBytes(
			"a501781a636f6170733a2f2f6d79736974652e6578616d706c652e636f6d026c67726f75706d616e6167657203781a636f6170733a2f2f646f6d61696e2e6578616d706c652e6f7267041aab9b154f08a101a4010103272006215820cde3efd3bc3f99c9c9ee210415c6cba55061b5046e963b8a58c9143a61166472");

	private static final int REPLAY_WINDOW = 32;

	static int initial_seq = 0;

	public static void main(String[] args) throws OSException {

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 0);

		sid_full_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);

		System.out.println();
		System.out.println("The CoAP client C and the CoAP server S are member of an OSCORE group." + "\n");

		System.out.println();
		System.out.println("[Setup]" + "\n");

		System.out.println("AEAD Algorithm: " + alg.AsCBOR() + " (" + alg + ")" + "\n");

		System.out.println("HKDF Algorithm: " + kdf + "\n");

		System.out.println("Signature Encryption Algorithm: " + algSignEnc.AsCBOR() + " (" + algSignEnc + ")" + "\n");

		System.out.println("Signature Algorithm: " + algCountersign + "\n");

		System.out.println("Pairwise Key Agreement Algorithm: " + algKeyAgreement + "\n");

		System.out.println("\n");

		System.out.println();
		System.out.println("Master Secret: " + Utils.bytesToHex(master_secret) + "\n");

		System.out.println("Master Salt: " + Utils.bytesToHex(master_salt) + "\n");

		System.out.println("ID Context: " + Utils.bytesToHex(id_context) + "\n");

		System.out.println("\n");

		System.out.println("Client's Sender ID: " + Utils.bytesToHex(sid) + "\n");

		System.out.println("Client's authentication credential as CCS (diagnostic notation): "
				+ printDiagnostic(sid_public_key_bytes) + "\n");

		System.out.println("Client's authentication credential as CCS (serialization): "
				+ Utils.bytesToHex(sid_public_key_bytes) + "\n");

		System.out.println("Client's private key: " + Utils.bytesToHex(sid_private_key_bytes) + "\n");

		System.out.println();
		System.out.println("Server's Sender ID: " + Utils.bytesToHex(rid) + "\n");

		System.out.println("Server's authentication credential as CCS (diagnostic notation): "
				+ printDiagnostic(rid_public_key_bytes) + "\n");

		System.out.println("Server's authentication credential as CCS (serialization): "
				+ Utils.bytesToHex(rid_public_key_bytes) + "\n");

		System.out.println("Server's private key (serialization): " + Utils.bytesToHex(rid_private_key_bytes) + "\n");

		System.out.println("Group Manager's authentication credential as CCS (diagnostic notation): "
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
		byte[] requestBytes = Utils.hexToBytes(
				"48019483f0aeef1c796812a0ba68656c6c6f576f726c64ed010c13404b3a7c9f8c878a0b5246cca71e3926f0a8cebefdcabbc80e79579d5a1ee17d");
		// Good byte[] requestBytes =
		// Utils.hexToBytes("48019483f0aeef1c796812a0ba68656c6c6f576f726c64");

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(requestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}

		System.out.println("Unprotected CoAP request: " + Utils.bytesToHex(requestBytes) + "\n");

		HashMapCtxDB db = new HashMapCtxDB();
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

		// Receive request and produce response

		db.purge();

		rid_full_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);
		GroupCtx commonCtxSrv = new GroupCtx(master_secret, master_salt, alg, kdf, id_context, algCountersign,
				gm_public_key_bytes);
		commonCtxSrv.addSenderCtxCcs(rid, rid_full_key);
		commonCtxSrv.addRecipientCtxCcs(sid, REPLAY_WINDOW, sid_full_key);

		db.addContext("", commonCtxSrv);

		encrypted.setSourceContext(new UdpEndpointContext(new InetSocketAddress(0)));
		GroupRecipientCtx recipientCtx = commonCtxSrv.recipientCtxMap.get(new ByteId(sid));
		db.addContext(recipientCtx);

		// Decrypt the request message
		Request decrypted = RequestDecryptor.decrypt(db, encrypted, recipientCtx);
		decrypted.getOptions().removeOscore();

		serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(decrypted);

		System.out.println("Decrypted request: " + Utils.bytesToHex(decryptedBytes));

		// === Prepare and send response

		System.out.println("");
		System.out.println("[Response to Deterministic Request]" + "\n");

		byte[] responseBytes = new byte[] { 0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, (byte) 0xff, 0x48, 0x65,
				0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };

		parser = new UdpDataParser();
		Message respMess = parser.parseMessage(responseBytes);

		Response resp = null;
		if (respMess instanceof Response) {
			resp = (Response) respMess;
		}

		// Encrypt the response message

		GroupSenderCtx senderCtx = commonCtxSrv.senderCtx;
		senderCtx.setSenderSeq(initial_seq);
		senderCtx.setResponsesIncludePartialIV(false);
		commonCtxSrv.setPairwiseModeResponses(true);

		boolean newPartialIV = false;
		boolean outerBlockwise = false;
		Response encryptedResp = ResponseEncryptor.encrypt(db, resp, senderCtx, newPartialIV, outerBlockwise,
				initial_seq, requestOscoreOption);

		serializer = new UdpDataSerializer();
		byte[] encryptedRespBytes = serializer.getByteArray(encryptedResp);

		System.out.println("Bytes of encrypted response: " + Utils.bytesToHex(encryptedRespBytes));

	}

	private static String printDiagnostic(byte[] input) {
		String temp = CBORObject.DecodeFromBytes(sid_public_key_bytes).toString();

		return temp.replace(",", ",\n") + "\n\n\n\n\n\n\n";
	}

}
