package org.eclipse.californium.edhoc;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.junit.Assert;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.Utils;

public class MessageProcessorTest {

	/**
	 * Tests identification of EDHOC messages. Based on messages from the EDHOC
	 * test vectors.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.1.1
	 */
	@Test
	public void testMessageType() {
		byte[] message1 = Utils
				.hexToBytes("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40");
		byte[] message2 = Utils.hexToBytes(
				"582071a3d599c21da18902a1aea810b2b6382ccd8d5f9bf0195281754c5ebcaf301e13585099d53801a725bfd6a4e71d0484b755ec383df77a916ec0dbc02bba7c21a200807b4f585f728b671ad678a43aacd33b78ebd566cd004fc6f1d406f01d9704e705b21552a9eb28ea316ab65037d717862e");
		byte[] message3 = Utils.hexToBytes(
				"846a5369676e6174757265314ea11822822e485b786988439ebcf258895820a239a627ada3802db8dae51ec392bfeb926d393ef6eee4ddb32e4a27ce9358da5865fa34b22a9ca4a1e12924eae1d1766088098449cb848ffc795f88afc49cbe8afdd1ba009f21675e8f6c77a4a2c30195601f6f0a0852978bd43d28207d44486502ff7bdda632c788370016b8965bdb2074bff82e5a20e09bec21f8406e86442b87ec3ff245b7485eefb885983c22d9");

		Assert.assertEquals(Constants.EDHOC_MESSAGE_1, MessageProcessor.messageType(message1));
		Assert.assertEquals(Constants.EDHOC_MESSAGE_2, MessageProcessor.messageType(message2));
		Assert.assertEquals(Constants.EDHOC_MESSAGE_3, MessageProcessor.messageType(message3));

		// Error message is not from test vectors
		CBORObject cx = CBORObject.FromObject(new byte[] { (byte) 0x59, (byte) 0xe9 });
		CBORObject errMsg = CBORObject.FromObject("Something went wrong");
		CBORObject suitesR = CBORObject.FromObject(1);
		
		List<CBORObject> errorMessageList = new ArrayList<CBORObject>();
		errorMessageList.add(cx);
		errorMessageList.add(errMsg);
		errorMessageList.add(suitesR);
		byte[] errorMessage = Util.buildCBORSequence(errorMessageList);
		
		Assert.assertEquals(Constants.EDHOC_ERROR_MESSAGE, MessageProcessor.messageType(errorMessage));
	}

	/**
	 * Test writing of message 1 and compare to the test vector in B.2.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.2.1
	 */
	@Test
	public void testWriteMessage1B2() {
		// First set up the session to use
		boolean initiator = true;
		int methodCorr = 13;
		byte[] connectionId = new byte[] { 0x16 };
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(0);
		OneKey ltk = Util.generateKeyPair(KeyKeys.OKP_Ed25519.AsInt32());
		byte[] ad = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		byte[] idCredKid = new byte[] {(byte) 0x24};
		CBORObject idCred = CBORObject.NewMap();
		idCred.Add(HeaderKeys.KID, idCredKid);

		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionId, ltk, idCred, "", cipherSuites);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("ae11a0db863c0227e53992feb8f5924c50d0a7ba6eeab4ad1ff24572f4f57cfa");
		byte[] publicEkeyBytes = Utils.hexToBytes("8d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ad);

		// Compare with the expected value from the test vectors
		byte[] expectedMessage1 = Utils
				.hexToBytes("0d0058208d3ef56d1b750a4351d68ac250a0e883790efc80a538a444ee9e2b57e2441a7c21");

		Assert.assertArrayEquals(expectedMessage1, message1);
	}

	/**
	 * Test writing of message 1 and compare to the test vector in B.1.
	 * 
	 * See: https://tools.ietf.org/html/draft-ietf-lake-edhoc-02#appendix-B.1.1
	 */
	@Test
	public void testWriteMessage1B1() {
		// First set up the session to use
		boolean initiator = true;
		int methodCorr = 1;
		byte[] connectionId = Bytes.EMPTY;
		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(0);
		OneKey ltk = Util.generateKeyPair(KeyKeys.OKP_Ed25519.AsInt32());
		byte[] idCredKid = new byte[] {(byte) 0x24};
		byte[] ad = null;
		
		// Just for method compatibility; it is not used for EDHOC Message 1
		CBORObject idCred = CBORObject.NewMap();
		CBORObject idCredElem = CBORObject.NewArray();
		idCredElem.Add(-15);
		byte[] truncatedHash = new byte[] {(byte) 0xFC, (byte) 0x79, (byte) 0x99, (byte) 0x0F,
		                                   (byte) 0x24, (byte) 0x31, (byte) 0xA3, (byte) 0xF5 };
		idCredElem.Add(CBORObject.FromObject(truncatedHash));
		idCred.Add(34, idCredElem);
		
		EdhocSession session = new EdhocSession(initiator, methodCorr, connectionId, ltk, idCred, "", cipherSuites);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = Utils.hexToBytes("8f781a095372f85b6d9f6109ae422611734d7dbfa0069a2df2935bb2e053bf35");
		byte[] publicEkeyBytes = Utils.hexToBytes("898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// Now write EDHOC message 1
		byte[] message1 = MessageProcessor.writeMessage1(session, ad);

		// Compare with the expected value from the test vectors
		byte[] expectedMessage1 = Utils
				.hexToBytes("01005820898ff79a02067a16ea1eccb90fa52246f5aa4dd6ec076bba0259d904b7ec8b0c40");

		Assert.assertArrayEquals(expectedMessage1, message1);
	}
}
