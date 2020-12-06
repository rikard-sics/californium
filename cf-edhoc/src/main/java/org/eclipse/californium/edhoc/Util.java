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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.Message;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.cose.Sign1Message;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.Utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Util {

    /**
     *  Compute a ciphertext using the COSE Encrypt0 object
     * @param idCredX   The ID of the public credential of the encrypter, as a CBOR map 
     * @param externalData   The data to use as external_aad
     * @param payload   The payload to encrypt
     * @param alg   The encryption algorithm to use
     * @param iv   The IV to use for encrypting
     * @param key   The symmetric key to use for encrypting
     * @return  the computed ciphertext, or null in case of invalid input
     */
	public static byte[] encrypt (CBORObject idCredX, byte[] externalData, byte[] payload, AlgorithmID alg, byte[] iv, byte[] key)
			                               throws CoseException {
        
		if(idCredX == null || externalData == null || payload == null || iv == null || key == null)
        	return null;       
		
        // The ID of the public credential has to be a CBOR map ...
        if(idCredX.getType() != CBORType.Map)
        	return null;
        
        // ... and it cannot be empty
        if(idCredX.size() == 0)
        	return null;
        
        Encrypt0Message msg = new Encrypt0Message();
        
        // Set the protected header of the COSE object
        for(CBORObject label : idCredX.getKeys()) {
            // All good if the map has only one element, otherwise it needs to be rebuilt deterministically
        	msg.addAttribute(label, idCredX.get(label), Attribute.PROTECTED);
        }
        
        msg.addAttribute(HeaderKeys.Algorithm, alg.AsCBOR(), Attribute.UNPROTECTED);
        msg.addAttribute(HeaderKeys.IV, iv, Attribute.UNPROTECTED);
        
        // Set the external_aad to use for the encryption process
        msg.setExternal(externalData);
       
        // Set the payload of the COSE object
        msg.SetContent(payload);
        
        // Debug print
        /*
        System.out.println("Protected attributes: " + msg.getProtectedAttributes().toString());
        System.out.println("aad                 : " + Utils.bytesToHex(msg.getExternal()));
        System.out.println("payload             : " + Utils.bytesToHex(msg.GetContent()));
        */
        
        // Perform the encryption
        msg.encrypt(key);
        
        System.out.println("Encrypted content: " + Utils.bytesToHex(msg.getEncryptedContent()));
        
        return msg.getEncryptedContent();
        
	}
	
    /**
     *  Decrypt a ciphertext using the COSE Encrypt0 object
     * @param idCredX   The ID of the public credential of the decrypter, as a CBOR map 
     * @param externalData   The data to use as external_aad
     * @param payload   The ciphertext to decrypt
     * @param alg   The encryption algorithm to use
     * @param iv   The IV to use for decrypting
     * @param key   The symmetric key to use for decrypting
     * @return  the computed plaintext, or null in case of invalid input
     */
	public static byte[] decrypt (CBORObject idCredX, byte[] externalData, byte[] payload, AlgorithmID alg, byte[] iv, byte[] key)
			                               throws CoseException {
        
		if(idCredX == null || externalData == null || payload == null || iv == null || key == null)
        	return null;       
		
        // The ID of the public credential has to be a CBOR map ...
        if(idCredX.getType() != CBORType.Map)
        	return null;
        
        // ... and it cannot be empty
        if(idCredX.size() == 0)
        	return null;
        
        Encrypt0Message msg = new Encrypt0Message();
        
        // Set the protected header of the COSE object
        for(CBORObject label : idCredX.getKeys()) {
            // All good if the map has only one element, otherwise it needs to be rebuilt deterministically
        	msg.addAttribute(label, idCredX.get(label), Attribute.PROTECTED);
        }
        
        msg.addAttribute(HeaderKeys.Algorithm, alg.AsCBOR(), Attribute.UNPROTECTED);
        msg.addAttribute(HeaderKeys.IV, iv, Attribute.UNPROTECTED);
        
        // Set the external_aad to use for the signing process
        msg.setExternal(externalData);
       
        // Set the payload of the COSE object
        msg.setEncryptedContent(payload);
        
        // Debug print
        /*
        System.out.println("Protected attributes: " + msg.getProtectedAttributes().toString());
        System.out.println("aad                 : " + Utils.bytesToHex(msg.getExternal()));
        System.out.println("payload             : " + Utils.bytesToHex(msg.GetContent()));
        */
        
        // Perform the encryption
        msg.decrypt(key);
        
        System.out.println("Decrypted content: " + Utils.bytesToHex(msg.GetContent()));
        
        return msg.GetContent();
        
	}
	
    /**
     *  Compute a signature using the COSE Sign1 object
     * @param idCredX   The ID of the public credential of the signer, as a CBOR map 
     * @param externalData   The data to use as external_aad
     * @param payload   The payload to sign
     * @param signKey   The private key to use for signing
     * @return  the computed signature, or null in case of invalid input
     */
	public static byte[] computeSignature (CBORObject idCredX, byte[] externalData, byte[] payload, OneKey signKey)
			                               throws CoseException {
        
		if(idCredX == null || externalData == null || payload == null || signKey == null)
        	return null;       
		
        // The ID of the public credential has to be a CBOR map ...
        if(idCredX.getType() != CBORType.Map)
        	return null;
        
        // ... and it cannot be empty
        if(idCredX.size() == 0)
        	return null;
        
        Sign1Message msg = new Sign1Message();
        
        // Set the protected header of the COSE object
        for(CBORObject label : idCredX.getKeys()) {
            // All good if the map has only one element, otherwise it needs to be rebuilt deterministically
        	msg.addAttribute(label, idCredX.get(label), Attribute.PROTECTED);
        }
        
        msg.addAttribute(HeaderKeys.Algorithm, signKey.get(KeyKeys.Algorithm), Attribute.UNPROTECTED);
        
        // Set the external_aad to use for the signing process
        msg.setExternal(externalData);
       
        // Set the payload of the COSE object
        msg.SetContent(payload);
        
        // Debug print
        /*
        System.out.println("Protected attributes: " + msg.getProtectedAttributes().toString());
        System.out.println("aad                 : " + Utils.bytesToHex(msg.getExternal()));
        System.out.println("payload             : " + Utils.bytesToHex(msg.GetContent()));
        */
        
        // Compute the signature
        msg.sign(signKey);
        
        // Serialize the COSE Sign1 object as a CBOR array
        CBORObject myArray = msg.EncodeToCBORObject();
		
        // Debug print
        /*
        System.out.println("\nCBOR array with signature: " + myArray.toString() + "\n");
        */
        
        // Return the actual signature, as fourth element of the CBOR array
		return myArray.get(3).GetByteString();
		
	}
	
    /**
     *  Verify a signature using the COSE Sign1 object
     * @param signature   The signature to verify
     * @param idCredX   The ID of the public credential of the signer, as a CBOR map
     * @param externalData   The data to use as external_aad
     * @param payload   The payload to sign
     * @param publicKey   The private key to use for verifying the signature
     * @return  true is the signature is valid, false if the signature is not valid or the input is not valid 
     */
	public static boolean verifySignature (byte[] signature, CBORObject idCredX, byte[] externalData, byte[] payload, OneKey publicKey)
			                               throws CoseException {
	    
        if(signature == null || idCredX == null || externalData == null || payload == null || publicKey == null)
        	return false;
        
        // The ID of the public credential has to be a CBOR map ...
        if (idCredX.getType() != CBORType.Map)
        	return false;
        
        // ... and it cannot be empty
        if (idCredX.size() == 0)
        	return false;
        
        // Prepare the raw COSE Sign1 object as a CBOR array
        CBORObject myArray = CBORObject.NewArray();
        
        // Add the Protected header, i.e. the provided CBOR map wrapped into a CBOR byte string
        myArray.Add(idCredX.EncodeToBytes());
        
        // Add the Unprotected, i.e. a CBOR map specifying the signature algorithm
        CBORObject myMap = CBORObject.NewMap();
        myMap.Add(KeyKeys.Algorithm, publicKey.get(KeyKeys.Algorithm));
        myArray.Add(myMap);
        
        // Add the signed payload
        myArray.Add(payload);
        
        // Add the signature to verify
        myArray.Add(signature);
                
        myArray = CBORObject.FromObjectAndTag(myArray, MessageTag.Sign1.value);
  
        // Debug print
        /*
        System.out.println("\nCBOR array with signature: " + myArray.toString() + "\n");
        */
        
        // Build the COSE Sign1 object from the raw version
        Sign1Message msg = (Sign1Message) Message.DecodeFromBytes(myArray.EncodeToBytes(), MessageTag.Sign1);
        
        // Set the external_aad to use for the signing process
        msg.setExternal(externalData);
        
        // Debug print
        /*
        System.out.println("Protected attributes: " + msg.getProtectedAttributes().toString());
        System.out.println("aad                 : " + Utils.bytesToHex(msg.getExternal()));
        System.out.println("payload             : " + Utils.bytesToHex(msg.GetContent()));
        */
        
        // Verify the signature
        return msg.validate(publicKey);
       
	}
	
    /**
     *  Compute a hash value using the specified algorithm 
     * @param input   The content to hash
     * @param algorithm   The name of the hash algorithm to use
     * @return  the computed hash, or null in case of invalid input
     */
	public static byte[] computeHash (byte[] input, String algorithm) throws NoSuchAlgorithmException {
		
		if (input == null)
			return null;
		
		MessageDigest myDigest;
		
		if (algorithm.equals("SHA-256"))
			myDigest = MessageDigest.getInstance("SHA-256");
		else if (algorithm.equals("SHA-512"))
			myDigest = MessageDigest.getInstance("SHA-512");
		else
			return null;
		
		myDigest.reset();
		myDigest.update(input);
		return myDigest.digest();
		
	}
	
    /**
     *  Prepare a CBOR sequence, given a list of CBOR Objects as input
     * @param objectList   The CBOR Objects to compose the CBOR sequence
     * @return  the CBOR sequence, as an array of bytes
     */
	public static byte[] buildCBORSequence (List<CBORObject> objectList) {
		
		int sequenceLength = 0;
		byte[] mySequence = new byte[0];
		
		List<CBORObject> serializationList = new ArrayList<CBORObject>();
		
		for (int i = 0; i < objectList.size(); i++) {
			byte[] objBytes = objectList.get(i).EncodeToBytes();			
			serializationList.add(CBORObject.FromObject(objBytes));
			sequenceLength += objBytes.length;
		}
		
		int offset = 0;
		mySequence = new byte[sequenceLength];
		
		for (int i = 0; i < serializationList.size(); i++) {
			byte[] objBytes = serializationList.get(i).GetByteString();
			System.arraycopy(objBytes, 0, mySequence, offset, objBytes.length);
			offset += objBytes.length;
		}
		
		return mySequence;
		
	}
	
    /**
     *  Build a CBOR map, ensuring the exact order of its entries
     * @param labelList   The labels of the CBOR map entries, already prepared as CBOR objects (uint or tstr)
     * @param valueList   The CBOR Objects to include as values of the CBOR map entries
     * @return  the binary serialization of the CBOR map, or null in case of invalid input
     */
	public static byte[] buildDeterministicCBORMap (List<CBORObject> labelList, List<CBORObject> valueList) {
		
		if (labelList.size() != valueList.size())
			return null;
		
		int numEntries = labelList.size(); 
		
		if (numEntries == 0) {
			CBORObject emptyMap = CBORObject.NewMap();
			return emptyMap.EncodeToBytes();
		}
		
		byte[] mapContent = new byte[0];
		List<CBORObject> pairList = new ArrayList<CBORObject>();
		
		for(int i = 0; i < numEntries; i++) {
			if(labelList.get(i) == null || valueList.get(i) == null)
				return null;
			
			if(labelList.get(i).getType() != CBORType.Integer ||
			   labelList.get(i).getType() != CBORType.TextString) {
				return null;
			}
			
			pairList.add(labelList.get(i));
			pairList.add(valueList.get(i));
		}
		mapContent = buildCBORSequence(pairList);
		
		// Encode the number N of map entries as a CBOR integer
		CBORObject numEntriesCBOR = CBORObject.FromObject(numEntries);
		byte[] mapHeader = numEntriesCBOR.EncodeToBytes();
		// Change the first byte so that the result is the header of a CBOR map with N entries
		// 0b000_xxxxx & 0b000_11111 --> 0b101_xxxxx  , x ={0,1}
		mapHeader[0] = (byte) (mapHeader[0] & intToBytes(31)[0]);
		
		byte[] serializedMap = new byte[mapHeader.length + mapContent.length];
		System.arraycopy(mapHeader, 0, serializedMap, 0, mapHeader.length);
		System.arraycopy(mapContent, 0, serializedMap, mapHeader.length, mapContent.length);
		
		return serializedMap;
		
	}
	
    /**
     *  Encode a CBOR byte string as a bstr_identifier, i.e.:
     *  - A CBOR byte string with length 0, 2 or greater than 2 bytes remains as is
     *  - A CBOR byte string with length 1 byte becomes a CBOR integer, with
     *    value the byte-encoded integer value from the byte string - 24
     * @param byteString   The CBOR byte string to encode as bstr_identifier
     * @return  the bstr_identifier, as a CBOR byte string or a CBOR integer
     */
	public static CBORObject encodeToBstrIdentifier (CBORObject byteString) {
		
		if(byteString.getType() != CBORType.ByteString)
			return null;
		
		byte[] rawByteString = byteString.GetByteString();
		
		if (rawByteString.length == 1) {
			int value = bytesToInt(rawByteString) - 24;
			return CBORObject.FromObject(value);
		}
		
		return byteString;
		
	}
	
    /**
     *  Produce a CBOR byte string from a bstr_identifier, i.e.:
     *  - If the bstr_identifier is a CBOR integer, take its value + 24 and encode the result as a 1-byte CBOR byte string
     *  - If the bstr_identifier is a CBOR byte string with length 0, 2 or more than 2 bytes, return it as is
     * @param inputObject   The CBOR object to convert back into a CBOR byte string
     * @return  the CBOR byte string corresponding to the input bstr_identifier, or null in case of invalid input
     */
	public static CBORObject decodeFromBstrIdentifier (CBORObject inputObject) {
		
		if(inputObject.getType() != CBORType.ByteString || inputObject.getType() != CBORType.Integer)
			return null;
		
		if(inputObject.getType() != CBORType.ByteString) {
			if(inputObject.GetByteString().length == 1) {
				return null;
			}
			return inputObject;
		}
		
		// The CBOR object is of Major Type "Integer"
		int value = inputObject.AsInt32() + 24;
		
		if(value < 0 || value > 255)
			return null;
		
		byte[] rawByteString = intToBytes(value);
		return CBORObject.FromObject(rawByteString);
		
	}
	
    /**
     *  Compute the bitwise xor between two byte arrays of equal length
     * @param arg1   The first byte array
     * @param arg2   The second byte array
     * @return  a byte including the xor result, or null in case of invalid input
     */
	public static byte[] arrayXor (byte[] arg1, byte[] arg2) {
		
		if(arg1 == null || arg2 == null)
			return null;
		
		if(arg1.length != arg2.length)
			return null;
		
		if(arg1.length == 0)
			return null;
		
		int length = arg1.length;
		byte[] result = new byte[length];
		
		for (int i = 0; i < length; i ++) {
			result[i] = (byte) (arg1[i] ^ arg2[i]);
		}
		
		return result;
		
	}
	
    /**
     *  Convert a positive integer into a byte array of minimal size.
     *  The positive integer can be up to 2,147,483,647 
     * @param num
     * @return  the byte array
     */
    public static byte[] intToBytes(final int num) {

    	// Big-endian
    	if (num < 0)
    		return null;
        else if (num < 256) {
            return new byte[] { (byte) (num) };
        } else if (num < 65536) {
            return new byte[] { (byte) (num >>> 8), (byte) num };
        } else if (num < 16777216) {
            return new byte[] { (byte) (num >>> 16), (byte) (num >>> 8), (byte) num };
        } else { // up to 2,147,483,647
            return new byte[]{ (byte) (num >>> 24), (byte) (num >>> 16), (byte) (num >>> 8), (byte) num };
        }
    	
    	// Little-endian
    	/*
    	if (num < 0)
    		return null;
        else if (num < 256) {
            return new byte[] { (byte) (num) };
        } else if (num < 65536) {
            return new byte[] { (byte) num, (byte) (num >>> 8) };
        } else if (num < 16777216){
            return new byte[] { (byte) num, (byte) (num >>> 8), (byte) (num >>> 16) };
        } else{ // up to 2,147,483,647
            return new byte[] { (byte) num, (byte) (num >>> 8), (byte) (num >>> 16), (byte) (num >>> 24) };
        }
    	*/
    	
    }
	
    /**
     * Convert a byte array into an equivalent unsigned integer.
     * The input byte array can be up to 4 bytes in size.
     *
     * N.B. If the input array is 4 bytes in size, the returned integer may be negative! The calling method has to check, if relevant!
     * 
     * @param bytes 
     * @return   the converted integer
     */
    public static int bytesToInt(final byte[] bytes) {
    	
    	if (bytes.length > 4)
    		return -1;
    	
    	int ret = 0;

    	// Big-endian
    	for (int i = 0; i < bytes.length; i++)
    		ret = ret + (bytes[bytes.length - 1 - i] & 0xFF) * (int) (Math.pow(256, i));

    	/*
    	// Little-endian
    	for (int i = 0; i < bytes.length; i++)
    		ret = ret + (bytes[i] & 0xFF) * (int) (Math.pow(256, i));
    	*/
    	
    	return ret;
    	
    }
    
}
