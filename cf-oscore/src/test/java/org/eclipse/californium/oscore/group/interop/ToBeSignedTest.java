/*******************************************************************************
 * Copyright (c) 2023 RISE SICS and others.
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
 *    Rikard Höglund (RISE SICS)
 ******************************************************************************/
package org.eclipse.californium.oscore.group.interop;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Field;
import java.util.Random;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CounterSign1;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.OneKeyDecoder;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

/**
 * Test the To-Be-Signed data for countersignatures.
 * 
 * https://stackoverflow.com/questions/735230/java-reflection-access-protected-field
 *
 */
public class ToBeSignedTest {

	// Initialize with static seed
	static Random rand = new Random(1000);

	/**
	 * Test the To-Be-Signed data for a countersignature.
	 * 
	 * @throws Exception on test failure
	 */
	@Test
	public void testToBeSigned() throws Exception {

		// Define a COSE OneKey to use
		OneKey signKey = OneKeyDecoder.parseDiagnostic(
				"{1: 2, -1: 1, -2: h’E2A7DC0C5D23831A4F52FBFF759EF01A6B3A7D58694774D6E8505B31A351D6C4’, -3: h’F8CA44FEDC6C322D0946FC69AE7482CD066AD11F34AA5F5C63F4EADB320FD941’, -4: h’469C76F26B8D9F286449F42566AB8B8BA1B3A8DC6E711A1E2A6B548DBE2A1578’}");

		/* Set up to do a countersignature */

		Encrypt0Message enc = new Encrypt0Message(false, true);

		byte[] confidential = Bytes.createBytes(rand, 20);
		enc.SetContent(confidential);

		byte[] aad = Bytes.createBytes(rand, 10);
		enc.setExternal(aad);

		byte[] nonce = Bytes.createBytes(rand, 13);
		enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
		enc.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_64_128.AsCBOR(), Attribute.DO_NOT_SEND);

		OneKey senderPrivateKey = signKey;
		CounterSign1 sign = new CounterSign1(senderPrivateKey);

		CBORObject signAlg = OneKeyDecoder.getAlgFromCurve(signKey).AsCBOR();
		sign.addAttribute(HeaderKeys.Algorithm, signAlg, Attribute.DO_NOT_SEND);

		enc.setCountersign1(sign);

		byte[] signAad = Bytes.createBytes(rand, 15);
		sign.setExternal(signAad); // Set external AAD for signing

		byte[] key = Bytes.createBytes(rand, 16);
		enc.encrypt(key);

		CBORObject mySignature = enc.getUnprotectedAttributes().get(HeaderKeys.CounterSignature0.AsCBOR());
		byte[] countersignBytes = mySignature.GetByteString();

		// Check the countersignature
		assertNotNull(countersignBytes);
		assertEquals(64, countersignBytes.length);

		/* Use reflection to extract needed parameters */

		Object myEncObj = enc;
		Class<? extends Object> myEncClass = myEncObj.getClass();

		Object mySignObj = sign;
		Class<? extends Object> mySignClass = mySignObj.getClass();

		// contextString
		Field contextStringField = getField(mySignClass, "contextString");
		contextStringField.setAccessible(true);
		Object contextStringValue = contextStringField.get(mySignObj);

		// objProtected
		Field objProtectedField = getField(myEncClass, "objProtected");
		objProtectedField.setAccessible(true);
		Object objProtectedValue = objProtectedField.get(myEncObj);

		// rgbProtected
		Field rgbProtectedField = getField(myEncClass, "rgbProtected");
		rgbProtectedField.setAccessible(true);
		Object rgbProtectedValue = rgbProtectedField.get(myEncObj);

		// externalData
		Field externalDataField = getField(myEncClass, "externalData");
		externalDataField.setAccessible(true);
		Object externalDataValue = externalDataField.get(myEncObj);

		// rgbContent
		Field rgbContentField = getField(myEncClass, "rgbContent");
		rgbContentField.setAccessible(true);
		Object rgbContentValue = rgbContentField.get(myEncObj);

		/* Parse objects */
		String contextString = (String) contextStringValue;
		byte[] rgbProtected = (byte[]) rgbProtectedValue;
		byte[] externalData = (byte[]) externalDataValue;
		byte[] rgbContent = (byte[]) rgbContentValue;
		CBORObject objProtected = (CBORObject) objProtectedValue;

		byte[] rgbBodyProtected;
		if (objProtected.size() > 0)
			rgbBodyProtected = objProtected.EncodeToBytes();
		else
			rgbBodyProtected = new byte[0];

		/* Build ToBeSigned object */

		CBORObject obj = CBORObject.NewArray();
		obj.Add(contextString);
		obj.Add(rgbBodyProtected);
		obj.Add(rgbProtected);
		obj.Add(externalData);
		obj.Add(rgbContent);
		byte[] rgbToBeSigned = obj.EncodeToBytes();

		/* Perform checks */

		byte[] expectedRgbToBeSigned = new byte[] { (byte) 0x85, (byte) 0x71, (byte) 0x43, (byte) 0x6F, (byte) 0x75,
				(byte) 0x6E, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6E,
				(byte) 0x61, (byte) 0x74, (byte) 0x75, (byte) 0x72, (byte) 0x65, (byte) 0x30, (byte) 0x40, (byte) 0x40,
				(byte) 0x4A, (byte) 0x7A, (byte) 0xD5, (byte) 0x13, (byte) 0x04, (byte) 0x32, (byte) 0x82, (byte) 0x16,
				(byte) 0x0A, (byte) 0xEB, (byte) 0xEA, (byte) 0x54, (byte) 0xAF, (byte) 0xAD, (byte) 0xCE, (byte) 0xB5,
				(byte) 0x2F, (byte) 0xDA, (byte) 0x35, (byte) 0x3F, (byte) 0xB8, (byte) 0x79, (byte) 0x28, (byte) 0x93,
				(byte) 0x88, (byte) 0x70, (byte) 0xD5, (byte) 0x75, (byte) 0xA0, (byte) 0x87, (byte) 0x48,
				(byte) 0xF2 };

		// Check that nothing in the to-be-signed object is null
		for (int i = 0; i < obj.size(); i++) {
			assertNotEquals(CBORObject.Null, obj.get(i));
		}

		// Check that the exact value is correct
		assertArrayEquals(expectedRgbToBeSigned, rgbToBeSigned);

	}

	private static Field getField(Class<?> clazz, String fieldName) throws NoSuchFieldException {
		try {
			return clazz.getDeclaredField(fieldName);
		} catch (NoSuchFieldException e) {
			Class<?> superClass = clazz.getSuperclass();
			if (superClass == null) {
				throw e;
			} else {
				return getField(superClass, fieldName);
			}
		}
	}
}
