// lucas 
package org.eclipse.californium.oscore;

import java.util.Arrays;
import java.util.concurrent.Executors;

import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.InstructionIDRegistry;
import org.eclipse.californium.oscore.group.OptionEncoder;
import org.junit.Assert;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;



public class OptionEncoderTest {

	private final static byte[][] rids = {
			new byte[] { 0x05 }, 
			new byte[] { 0x02 }
	};

	private final static byte[][] idcontexts = {
			new byte[] { 0x01 }, 
			new byte[] { 0x02 }
	};

	private final static int[][] optionSetsPre = {
			{}, 
			{OptionNumberRegistry.URI_PORT, OptionNumberRegistry.URI_HOST, OptionNumberRegistry.PROXY_SCHEME}
	};

	private final static boolean[] URIPORTAnswer = {true, true, true, true, false};

	private final static boolean[] URIHostAnswer = {true, true, true, true, false};

	private final static boolean[] ProxySchemeAnswer = {true, true, true, true, false};

	private final static boolean[][][] answerSetsPre = {
			{},
			{URIPORTAnswer, URIHostAnswer, ProxySchemeAnswer}
	};

	private final static CBORObject[][] postValues =  {
			{CBORObject.FromObject("coap"), CBORObject.FromObject("localhost"),CBORObject.FromObject(5683)},
			{}
	};

	private final static int[][] optionSetsPost = {
			{OptionNumberRegistry.PROXY_SCHEME, OptionNumberRegistry.URI_HOST, OptionNumberRegistry.URI_PORT}, 
			{}
	};


	@Test
	public void testDecodeCBORSequence() {
		CBORObject[] CBORSequence = OptionEncoder.decodeCBORSequence(null);
		Assert.assertNull(CBORSequence);

		byte[] oscoreopt = CBORObject.FromObject(new byte[0]).EncodeToBytes();
		byte[] index = CBORObject.FromObject(2).EncodeToBytes();

		byte[] instruction = Bytes.concatenate(oscoreopt, index);

		CBORSequence = OptionEncoder.decodeCBORSequence(instruction);
		Assert.assertNull(CBORSequence);

		CBORObject option = CBORObject.NewMap();

		option.Add(InstructionIDRegistry.KID, new byte[] {(byte) 0x01 });
		option.Add(InstructionIDRegistry.IDContext, new byte[] {(byte) 0x03 });

		instruction = Bytes.concatenate(instruction, option.EncodeToBytes());

		CBORSequence = OptionEncoder.decodeCBORSequence(instruction);
		Assert.assertNotNull(CBORSequence);

		Assert.assertEquals(3, CBORSequence.length);

		oscoreopt = CBORSequence[InstructionIDRegistry.Header.OscoreOptionValue].ToObject(byte[].class);
		Assert.assertArrayEquals((new byte[0]), oscoreopt);

		int indexseq = CBORSequence[InstructionIDRegistry.Header.Index].ToObject(int.class);
		Assert.assertEquals(2, indexseq);

		CBORObject CBORInstruction = CBORSequence[indexseq];
		byte[] RID       = CBORInstruction.get(InstructionIDRegistry.KID).ToObject(byte[].class);
		byte[] IDCONTEXT = CBORInstruction.get(InstructionIDRegistry.IDContext).ToObject(byte[].class);
		Assert.assertArrayEquals(new byte[] {(byte) 0x01 }, RID );
		Assert.assertArrayEquals(new byte[] {(byte) 0x03 }, IDCONTEXT);		
	}

	@Test
	public void testSetRidAndIDContext() {
		byte[] rid = new byte[] {(byte) 0x01 };
		byte[] idcontext = new byte[] {(byte) 0x03 };

		byte[] instruction = OptionEncoder.set(rid, idcontext);
		CBORObject CBORInstruction = CBORObject.DecodeFromBytes(instruction);

		byte[] RID       = CBORInstruction.get(InstructionIDRegistry.KID).ToObject(byte[].class);
		byte[] IDCONTEXT = CBORInstruction.get(InstructionIDRegistry.IDContext).ToObject(byte[].class);

		Assert.assertArrayEquals(rid, RID);
		Assert.assertArrayEquals(idcontext, IDCONTEXT);
	}

	@Test
	public void testSetRequestSequenceNumber() {
		byte[] rid = new byte[] {(byte) 0x01 };
		byte[] idcontext = new byte[] {(byte) 0x03 };
		int requestSequenceNumber = 10;

		byte[] instruction = OptionEncoder.set(rid, idcontext, requestSequenceNumber);

		CBORObject CBORInstruction = CBORObject.DecodeFromBytes(instruction);

		int REQUESTSEQUENCENUMBER = CBORInstruction.get(InstructionIDRegistry.RequestSequenceNumber).ToObject(int.class);

		Assert.assertEquals(requestSequenceNumber, REQUESTSEQUENCENUMBER);

		requestSequenceNumber = -1;

		instruction = OptionEncoder.set(rid, idcontext, requestSequenceNumber);

		CBORInstruction = CBORObject.DecodeFromBytes(instruction);

		CBORObject object = CBORInstruction.get(InstructionIDRegistry.RequestSequenceNumber);

		Assert.assertNull(object);
	}

	@Test
	public void testSetPreSet() {		
		byte[] instruction = OptionEncoder.set(rids[0], idcontexts[0], optionSetsPre[0], answerSetsPre[0]);

		CBORObject CBORInstruction = CBORObject.DecodeFromBytes(instruction);
		CBORObject PreSet = CBORInstruction.get(InstructionIDRegistry.PreSet);

		Assert.assertNull(PreSet);

		instruction = OptionEncoder.set(rids[1], idcontexts[1], optionSetsPre[1], answerSetsPre[1]);

		CBORInstruction = CBORObject.DecodeFromBytes(instruction);
		PreSet = CBORInstruction.get(InstructionIDRegistry.PreSet);

		Assert.assertNotNull(PreSet);
		Assert.assertEquals(3, PreSet.size());
		Assert.assertArrayEquals(URIPORTAnswer, PreSet.get(OptionNumberRegistry.URI_PORT).ToObject(boolean[].class));
		Assert.assertArrayEquals(URIHostAnswer, PreSet.get(OptionNumberRegistry.URI_HOST).ToObject(boolean[].class));
		Assert.assertArrayEquals(ProxySchemeAnswer, PreSet.get(OptionNumberRegistry.PROXY_SCHEME).ToObject(boolean[].class));


	}

	@Test
	public void testSetMalformedPreSet() {		
		int[] malformedOptionSetsPre = {1,2,3};
		boolean[][] malformedAnswerSetsPre = {{true}} ;

		try {
			byte[] instruction = OptionEncoder.set(rids[0], idcontexts[0], malformedOptionSetsPre, answerSetsPre[0]);
			Assert.fail();
		}
		catch (RuntimeException e) {
			Assert.assertTrue(true);
		}

		try {
			byte[] instruction = OptionEncoder.set(rids[0], idcontexts[0], optionSetsPre[0], malformedAnswerSetsPre);
			Assert.fail();
		}
		catch (RuntimeException e) {
			Assert.assertTrue(true);
		}

		try {
			byte[] instruction = OptionEncoder.set(rids[0], idcontexts[0], malformedOptionSetsPre, malformedAnswerSetsPre);
			Assert.fail();
		}
		catch (RuntimeException e) {
			Assert.assertTrue(true);
		}
	}

	@Test
	public void testSetPostSet() {		
		byte[] instruction = OptionEncoder.set(rids[0], idcontexts[0], optionSetsPost[0], postValues[0]);

		CBORObject CBORInstruction = CBORObject.DecodeFromBytes(instruction);
		CBORObject PostSet = CBORInstruction.get(InstructionIDRegistry.PostSet);

		Assert.assertNotNull(PostSet);
		Assert.assertEquals(3, PostSet.size());
		Assert.assertEquals("coap", PostSet.get(OptionNumberRegistry.PROXY_SCHEME).ToObject(String.class));
		Assert.assertEquals("localhost", PostSet.get(OptionNumberRegistry.URI_HOST).ToObject(String.class));
		Assert.assertEquals(5683, (int) PostSet.get(OptionNumberRegistry.URI_PORT).ToObject(int.class));


		instruction = OptionEncoder.set(rids[1], idcontexts[1], optionSetsPost[1], postValues[1]);

		CBORInstruction = CBORObject.DecodeFromBytes(instruction);
		PostSet = CBORInstruction.get(InstructionIDRegistry.PostSet);

		Assert.assertNull(PostSet);
	}

	@Test
	public void testExtractPromotionAnswers() {
		byte[] instruction = OptionEncoder.set(rids[1], idcontexts[1], optionSetsPre[1], answerSetsPre[1]);

		CBORObject CBORInstruction = CBORObject.DecodeFromBytes(instruction);
		
		boolean[] promotionAnswers = OptionEncoder.extractPromotionAnswers(OptionNumberRegistry.URI_PORT, CBORInstruction);
		
		Assert.assertNotNull(promotionAnswers);
		Assert.assertArrayEquals(URIPORTAnswer, promotionAnswers);
	}
}