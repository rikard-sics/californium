/*******************************************************************************
 * Copyright (c) 2020 RISE SICS and others.
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
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 * 
 * Contributors: 
 *    Rikard Höglund (RISE SICS) - testing Group OSCORE messages
 ******************************************************************************/
package org.eclipse.californium.oscore.group.interop;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.UdpEndpointContext;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.RequestDecryptor;
import org.eclipse.californium.oscore.RequestEncryptor;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.GroupRecipientCtx;
import org.eclipse.californium.oscore.group.GroupSenderCtx;
import org.eclipse.californium.oscore.group.OneKeyDecoder;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import net.i2p.crypto.eddsa.Utils;

/**
 * Tests key derivation for Group OSCORE for both ECDSA_256 and EdDSA
 * countersignature algorithms. The AEAD algorithm used is the default
 * AES-CCM-16-64-128 and the HKDF algorithm the default HKDF SHA-256.
 * 
 * 
 */
public class GroupInteropRikardEcdsaTests {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	// OSCORE context information database
	private final static HashMapCtxDB db = new HashMapCtxDB();

	// Define AEAD and HKDF algorithms
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Imagined multicast addresses for recipient groups
	private static String groupEcdsa = "coap://224.0.1.187";

	// Define context information (based on OSCORE RFC section C.3.2. Server)
	static byte[] sid = new byte[] { 0x01 };
	static byte[] rid1 = Bytes.EMPTY;
	static byte[] rid2 = new byte[] { (byte) 0xAA };

	private final static byte[] master_secret = Utils.hexToBytes("0102030405060708090a0b0c0d0e0f10");
	private final static byte[] master_salt = Utils.hexToBytes("9e7ca92223786340");
	private final static byte[] context_id = Utils.hexToBytes("37cbf3210017a2d3");

	// Keys for sender and recipients
	// For the public keys only the public part will be added to the context
	private static String senderFullKeyEcdsa256 = "{1: 2, 2: h'01', -4: h'FEA2190084748436543C5EC8E329D2AFBD7068054F595CA1F987B9E43E2205E6', -3: h'64CE3DD128CC4EFA6DE209BE8ABD111C7272F612C2DB654057B6EC00FBFB0684', -2: h'1ADB2AB6AF48F17C9877CF77DB4FA39DC0923FBE215E576FE6F790B1FF2CBC96', -1: 1}";
	private static String recipient1PublicKeyEcdsa256 = "{1: 2, 2: h'', -4: h'DA2593A6E0BCC81A5941069CB76303487816A2F4E6C0F21737B56A7C90381597', -3: h'1897A28666FE1CC4FACEF79CC7BDECDC271F2A619A00844FCD553A12DD679A4F', -2: h'0EB313B4D314A1001244776D321F2DD88A5A31DF06A6EEAE0A79832D39408BC1', -1: 1}";
	private static String recipient2PublicKeyEcdsa256 = "{1: 2, 2: h'AA', -4: h'BF31D3F9670A7D1342259E700F48DD9983A5F9DF80D58994C667B6EBFD23270E', -3: h'5694315AD17A4DA5E3F69CA02F83E9C3D594712137ED8AFB748A70491598F9CD', -2: h'FAD4312A45F45A3212810905B223800F6CED4BC8D5BACBC8D33BB60C45FC98DD', -1: 1}";

	private static final int REPLAY_WINDOW = 32;

	// The contexts generated for use in the tests
	private static GroupSenderCtx senderCtxEcdsa;

	private static GroupRecipientCtx recipient1CtxEcdsa;
	private static GroupRecipientCtx recipient2CtxEcdsa;


	/* --- Tests follow --- */


	@Test
	public void testECDSA256Keys() throws Exception {

		OneKey senderKey = OneKeyDecoder.parseDiagnostic(senderFullKeyEcdsa256);
		OneKey recipient1Key = OneKeyDecoder.parseDiagnostic(recipient1PublicKeyEcdsa256);
		OneKey recipient2Key = OneKeyDecoder.parseDiagnostic(recipient2PublicKeyEcdsa256);

		// Check the properties of the decoded keys

		// Key ID is set
		assertNotNull(senderKey.get(KeyKeys.KeyId));
		assertNotNull(recipient1Key.get(KeyKeys.KeyId));
		assertNotNull(recipient2Key.get(KeyKeys.KeyId));

		// Check that Key IDs are correct
		assertArrayEquals(sid, senderKey.get(KeyKeys.KeyId).GetByteString());
		assertArrayEquals(rid1, recipient1Key.get(KeyKeys.KeyId).GetByteString());
		assertArrayEquals(rid2, recipient2Key.get(KeyKeys.KeyId).GetByteString());

		// Key type
		assertEquals(KeyKeys.KeyType_EC2, senderKey.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_EC2, recipient1Key.get(KeyKeys.KeyType));
		assertEquals(KeyKeys.KeyType_EC2, recipient2Key.get(KeyKeys.KeyType));

		// Curve
		assertEquals(KeyKeys.EC2_P256, senderKey.get(KeyKeys.EC2_Curve));
		assertEquals(KeyKeys.EC2_P256, recipient1Key.get(KeyKeys.EC2_Curve));
		assertEquals(KeyKeys.EC2_P256, recipient2Key.get(KeyKeys.EC2_Curve));

		// Attempt to sign using the keys to see that it works
		byte[] signatureBytes = OneKeyDecoderTest.doCountersign(senderKey);
		assertEquals(64, signatureBytes.length);
		signatureBytes = OneKeyDecoderTest.doCountersign(recipient1Key);
		assertEquals(64, signatureBytes.length);
		signatureBytes = OneKeyDecoderTest.doCountersign(recipient2Key);
		assertEquals(64, signatureBytes.length);
	}

	@Test
	public void testContextsAlgCountersign() throws OSException {
		// Check that the contexts use the correct countersignature algorithms

		assertEquals(AlgorithmID.ECDSA_256, senderCtxEcdsa.getAlgCountersign());
		assertEquals(AlgorithmID.ECDSA_256, recipient1CtxEcdsa.getAlgCountersign());
		assertEquals(AlgorithmID.ECDSA_256, recipient2CtxEcdsa.getAlgCountersign());

	}

	@Test
	public void testSenderKeys() throws OSException {

		// Check that they match expected value
		byte[] expectedSenderKey = Utils.hexToBytes("e39a0c7c77b43f03b4b39ab9a268699f");
		assertArrayEquals(expectedSenderKey, senderCtxEcdsa.getSenderKey());
	}

	@Test
	public void testRecipientKeys() throws OSException {

		// Check that they match expected value
		byte[] expectedRecipient1Key = Utils.hexToBytes("af2a1300a5e95788b356336eeecd2b92");
		assertArrayEquals(expectedRecipient1Key, recipient1CtxEcdsa.getRecipientKey());

		byte[] expectedRecipient2Key = Utils.hexToBytes("4d9eabdba0f97f044fc0ee5313b1ebc6");
		assertArrayEquals(expectedRecipient2Key, recipient2CtxEcdsa.getRecipientKey());
	}

	@Test
	@Ignore // FIXME
	public void testPairwiseRecipientKeys() throws OSException {
		byte[] recipient1EcdsaPairwiseKey = recipient1CtxEcdsa.getPairwiseRecipientKey();
		byte[] recipient2EcdsaPairwiseKey = recipient2CtxEcdsa.getPairwiseRecipientKey();

		// And different from each other for the same algorithm
		assertFalse(Arrays.equals(recipient1EcdsaPairwiseKey, recipient2EcdsaPairwiseKey));

		System.out.println("ECDSA: Recipient 1 Pairwise Key: " + Utils.bytesToHex(recipient1EcdsaPairwiseKey));
		System.out.println("ECDSA: Recipient 2 Pairwise Key: " + Utils.bytesToHex(recipient2EcdsaPairwiseKey));


		// Check that they match expected value
		assertArrayEquals(Utils.hexToBytes("a5d7fc4a84675d4a1ef9bf6ed6ce0cae"), recipient1EcdsaPairwiseKey);
		assertArrayEquals(Utils.hexToBytes("874fc9f08cd0ccc2930b856e4e8a8dc1"), recipient2EcdsaPairwiseKey);

	}

	@Test
	@Ignore // FIXME
	public void testPairwiseSenderKeys() throws OSException {
		byte[] senderEcdsaPairwiseKey1 = senderCtxEcdsa.getPairwiseSenderKey(rid1);
		byte[] senderEcdsaPairwiseKey2 = senderCtxEcdsa.getPairwiseSenderKey(rid2);

		// And different from each other for the same algorithm
		assertFalse(Arrays.equals(senderEcdsaPairwiseKey1, senderEcdsaPairwiseKey2));

		System.out.println("ECDSA: Sender Pairwise Key 1: " + Utils.bytesToHex(senderEcdsaPairwiseKey1));
		System.out.println("ECDSA: Sender Pairwise Key 2: " + Utils.bytesToHex(senderEcdsaPairwiseKey2));

		// Check that they match expected value
		assertArrayEquals(Utils.hexToBytes("286fb4560cc4219594a1d341e2620265"), senderEcdsaPairwiseKey1);
		assertArrayEquals(Utils.hexToBytes("b8cf3bd127678a63d0bd1abfe80e6362"), senderEcdsaPairwiseKey2);

	}

	@Test
	public void testSharedSecretsEcdsa()
			throws CoseException, NoSuchAlgorithmException, InvalidKeyException, IllegalStateException {

		ECPublicKey recipientPubKey = (ECPublicKey) recipient1CtxEcdsa.getPublicKey().AsPublicKey();
		ECPrivateKey senderPrivKey = (ECPrivateKey) senderCtxEcdsa.getPrivateKey().AsPrivateKey();
		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(senderPrivKey);
		keyAgreement.doPhase(recipientPubKey, true);
		byte[] sharedSecret1 = keyAgreement.generateSecret();

		recipientPubKey = (ECPublicKey) recipient2CtxEcdsa.getPublicKey().AsPublicKey();
		senderPrivKey = (ECPrivateKey) senderCtxEcdsa.getPrivateKey().AsPrivateKey();
		keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(senderPrivKey);
		keyAgreement.doPhase(recipientPubKey, true);
		byte[] sharedSecret2 = keyAgreement.generateSecret();

		// Check that they do not match each other
		assertFalse(Arrays.equals(sharedSecret1, sharedSecret2));

		System.out.println("ECDSA: Shared secret 1 " + Utils.bytesToHex(sharedSecret1));
		System.out.println("ECDSA: Shared secret 2 " + Utils.bytesToHex(sharedSecret2));

		// Check that they match expected value
		assertArrayEquals(Utils.hexToBytes("56ede6c59e919031cfc8afa3e74a7b7615c2e7a08494cf3638c78757293adc80"),
				sharedSecret1);
		assertArrayEquals(Utils.hexToBytes("f568ec5f7df45db137fc79a27595eba737b62e8ee385c7309e316dd409de6953"),
				sharedSecret2);
	}

	@Test
	@Ignore // TODO: Recalculate
	public void testMessage2Reception() throws OSException {

		db.purge();

		int seq = 0;

		// --- Try decryption ---
		String destinationUri = "coap://127.0.0.1/test";

		GroupCtx groupCtxRikard = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.ECDSA_256);
		// Dummy values for pretend sender
		OneKey senderFullKey = OneKeyDecoder.parseDiagnostic(InteropParametersOld.JIM_ENTITY_1_KEY_ECDSA);
		groupCtxRikard.addSenderCtx(new byte[] { 0x11, 0x22 }, senderFullKey);

		groupCtxRikard.addRecipientCtx(sid, REPLAY_WINDOW, OneKeyDecoder.parseDiagnostic(senderFullKeyEcdsa256));
		db.addContext(destinationUri, groupCtxRikard);
		GroupRecipientCtx recipientCtx = (GroupRecipientCtx) db.getContext(sid,
				context_id);

		// Create request message from raw byte array
		byte[] requestBytes = Utils.hexToBytes(
				"5402FFFF347312119C39000837CBF3210017A2D301FF963FFA3CDF9ED8FAC09E33E6FF8291CD3CCA52383B7E24B1474EAC7C63D32C8C30EADB5D9870A91D679E9F148297F70B62D94B3B192C4C067187208646D27D26099482C043D4F9AD00");

		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(requestBytes);

		Request r = null;
		if (mess instanceof Request) {
			r = (Request) mess;
		}

		// Set up some state information simulating an incoming request
		OSCoreCtxDB db = new HashMapCtxDB();
		recipientCtx.setReceiverSeq(seq - 1);
		db.addContext(recipientCtx);
		r.setSourceContext(new UdpEndpointContext(new InetSocketAddress(0)));

		System.out.println("Common IV: " + Utils.bytesToHex(recipientCtx.getCommonIV()));
		System.out.println("Recipient Key: " + Utils.bytesToHex(recipientCtx.getRecipientKey()));

		// Decrypt the request message
		Request decrypted = RequestDecryptor.decrypt(db, r, recipientCtx);
		decrypted.getOptions().removeOscore();

		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedBytes = serializer.getByteArray(decrypted);

		System.out.println("Decrypted: " + Utils.bytesToHex(encryptedBytes));
	}

	@Test
	public void testMessage2Generation() throws OSException {
		senderCtxEcdsa.setSenderSeq(0);

		Request request = Request.newGet();
		request.setMID(1000); // ?
		request.setType(Type.NON);
		request.getOptions().setOscore(Bytes.EMPTY);
		request.setURI(groupEcdsa);
		request.setToken(new byte[] { 0x34, 0x73, 0x12, 0x11 });
		
		
		// encrypt
		Request encrypted = RequestEncryptor.encrypt(db, request);

		System.out.println(encrypted);

		System.out.println("Common IV: " + hexPrintDash(senderCtxEcdsa.getCommonIV()));
		System.out.println("Sender Key: " + hexPrintDash(senderCtxEcdsa.getSenderKey()));

		System.out.println("Payload: " + hexPrintDash(encrypted.getPayload()));

		// Serialize the request message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(encrypted);

		System.out.println("Full request: " + hexPrintDash(decryptedBytes));

	}

	private static String hexPrintDash(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X-", b));
		}
		return sb.toString();
	}

	/* --- End of tests --- */

	/**
	 * Derives OSCORE context information for tests
	 *
	 * @throws OSException on failure to create the contexts
	 * @throws CoseException on failure to create the contexts
	 */
	@BeforeClass
	public static void deriveContexts() throws OSException, CoseException {

		// Create context using ECDSA_256

		GroupCtx groupCtxEcdsa = new GroupCtx(master_secret, master_salt, alg, kdf, context_id, AlgorithmID.ECDSA_256);

		OneKey senderFullKey = OneKeyDecoder.parseDiagnostic(senderFullKeyEcdsa256);
		groupCtxEcdsa.addSenderCtx(sid, senderFullKey);

		OneKey recipient1PublicKey = OneKeyDecoder.parseDiagnostic(recipient1PublicKeyEcdsa256).PublicKey();
		OneKey recipient2PublicKey = OneKeyDecoder.parseDiagnostic(recipient2PublicKeyEcdsa256).PublicKey();
		groupCtxEcdsa.addRecipientCtx(rid1, REPLAY_WINDOW, recipient1PublicKey);
		groupCtxEcdsa.addRecipientCtx(rid2, REPLAY_WINDOW, recipient2PublicKey);

		db.addContext(groupEcdsa, groupCtxEcdsa);

		// Save the generated sender and recipient contexts

		senderCtxEcdsa = (GroupSenderCtx) db.getContext(groupEcdsa);
		recipient1CtxEcdsa = (GroupRecipientCtx) db.getContext(rid1, context_id);
		recipient2CtxEcdsa = (GroupRecipientCtx) db.getContext(rid2, context_id);


	}

}
