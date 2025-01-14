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
 *    Rikard H��glund (RISE)
 *    
 ******************************************************************************/

package org.eclipse.californium.edhoc;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.util.Set;

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
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.CoapOSException;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

public class Util {

    /**
     *  Compute a ciphertext using the COSE Encrypt0 object
     * @param pretectedHeader   The elements to include in the COSE protected header, as a CBOR map
     * @param externalData   The data to use as external_aad
     * @param plaintext   The plaintext to encrypt
     * @param alg   The encryption algorithm to use
     * @param iv   The IV to use for encrypting
     * @param key   The symmetric key to use for encrypting
     * @return  the computed ciphertext, or null in case of invalid input
     */
	public static byte[] encrypt (CBORObject pretectedHeader, byte[] externalData, byte[] plaintext,
			                      AlgorithmID alg, byte[] iv, byte[] key) throws CoseException {
        
		if(pretectedHeader == null || externalData == null || plaintext == null || iv == null || key == null)
        	return null;       
		
        // The elements to include in the COSE protected header must be provided as a CBOR map 
        if(pretectedHeader.getType() != CBORType.Map)
        	return null;
                
        Encrypt0Message msg = new Encrypt0Message();
        
        // Set the protected header of the COSE object
        for(CBORObject label : pretectedHeader.getKeys()) {
        	msg.addAttribute(label, pretectedHeader.get(label), Attribute.PROTECTED);
        }
        
        msg.addAttribute(HeaderKeys.Algorithm, alg.AsCBOR(), Attribute.DO_NOT_SEND);
        msg.addAttribute(HeaderKeys.IV, iv, Attribute.DO_NOT_SEND);
        
        // Set the external_aad to use for the encryption process
        msg.setExternal(externalData);
       
        // Set the payload of the COSE object
        msg.SetContent(plaintext);
        
        // Debug print
        /*
        System.out.println("Protected attributes: " + msg.getProtectedAttributes().toString());
        System.out.println("aad                 : " + StringUtil.byteArray2HexString(msg.getExternal()));
        System.out.println("plaintext           : " + StringUtil.byteArray2HexString(msg.GetContent()));
        */
        
        // Perform the encryption
        msg.encrypt(key);
        
        // Debug print
        /*
        System.out.println("Encrypted content: " + StringUtil.byteArray2HexString(msg.getEncryptedContent()));
        */
        
        return msg.getEncryptedContent();
        
	}
	
    /**
     *  Decrypt a ciphertext using the COSE Encrypt0 object
     * @param pretectedHeader   The elements to include in the COSE protected header, as a CBOR map 
     * @param externalData   The data to use as external_aad
     * @param ciphertext   The ciphertext to decrypt
     * @param alg   The encryption algorithm to use
     * @param iv   The IV to use for decrypting
     * @param key   The symmetric key to use for decrypting
     * @return  the computed plaintext, or null in case of invalid input
     */
	public static byte[] decrypt (CBORObject pretectedHeader, byte[] externalData, byte[] ciphertext,
								  AlgorithmID alg, byte[] iv, byte[] key) throws CoseException {
        
		if(pretectedHeader == null || externalData == null || ciphertext == null || iv == null || key == null)
        	return null;       
		
        // The elements to include in the COSE protected header must be provided as a CBOR map
        if(pretectedHeader.getType() != CBORType.Map)
        	return null;
        
        Encrypt0Message msg = new Encrypt0Message();
        
        // Set the protected header of the COSE object
        for(CBORObject label : pretectedHeader.getKeys()) {
        	msg.addAttribute(label, pretectedHeader.get(label), Attribute.PROTECTED);
        }
        
        msg.addAttribute(HeaderKeys.Algorithm, alg.AsCBOR(), Attribute.DO_NOT_SEND);
        msg.addAttribute(HeaderKeys.IV, iv, Attribute.DO_NOT_SEND);
        
        // Set the external_aad to use for the signing process
        msg.setExternal(externalData);
       
        // Set the payload of the COSE object
        msg.setEncryptedContent(ciphertext);
        
        // Debug print
        /*
        System.out.println("Protected attributes: " + msg.getProtectedAttributes().toString());
        System.out.println("aad                 : " + StringUtil.byteArray2HexString(msg.getExternal()));
        System.out.println("payload             : " + StringUtil.byteArray2HexString(msg.GetContent()));
        */
        
        // Perform the encryption
        msg.decrypt(key);
        
        // Debug print
        /*
        System.out.println("Decrypted content: " + StringUtil.byteArray2HexString(msg.GetContent()));
        */
        
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
        
		// Identify algorithm used from values in the key
		CBORObject alg = signKey.get(KeyKeys.Algorithm);
		if (alg == null) {
			alg = determineKeyAlgorithm(signKey).AsCBOR();
		}
		msg.addAttribute(HeaderKeys.Algorithm, alg, Attribute.DO_NOT_SEND);
        
        // Set the external_aad to use for the signing process
        msg.setExternal(externalData);
       
        // Set the payload of the COSE object
        msg.SetContent(payload);
        
        // Debug print
        /*
        System.out.println("Protected attributes: " + msg.getProtectedAttributes().toString());
        System.out.println("aad                 : " + StringUtil.byteArray2HexString(msg.getExternal()));
        System.out.println("payload             : " + StringUtil.byteArray2HexString(msg.GetContent()));
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
	 * Identifies the algorithm used by a key from the curve parameters.
	 * 
	 * @param key the key
	 * @return the algorithm used
	 */
	static AlgorithmID determineKeyAlgorithm(OneKey key) {

		if (key.get(KeyKeys.OKP_Curve) == KeyKeys.OKP_Ed25519) {
			return AlgorithmID.EDDSA;
		} else if (key.get(KeyKeys.EC2_Curve) == KeyKeys.EC2_P256) {
			return AlgorithmID.ECDSA_256;
		} else if (key.get(KeyKeys.EC2_Curve) == KeyKeys.EC2_P384) {
			return AlgorithmID.ECDSA_384;
		} else if (key.get(KeyKeys.EC2_Curve) == KeyKeys.EC2_P521) {
			return AlgorithmID.ECDSA_512;
		} else {
			return null;
		}
	}

    /**
     *  Verify a signature using the COSE Sign1 object
     * @param signature   The signature to verify
     * @param idCredX   The ID of the public credential of the signer, as a CBOR map
     * @param externalData   The data to use as external_aad
     * @param payload   The payload to sign
     * @param publicKey   The public key to use for verifying the signature
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
        System.out.println("aad                 : " + StringUtil.byteArray2HexString(msg.getExternal()));
        System.out.println("payload             : " + StringUtil.byteArray2HexString(msg.GetContent()));
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
     *  Concatenate byte arrays, each of which wrapped as a CBOR byte strings
     * @param objectList   The list of CBOR byte strings wrapping the byte arrays to concatenate
     * @return  the concatenation of all the byte arrays taken as input
     */
	public static byte[] concatenateByteArrays (List<CBORObject> byteStrings) {
		
		int outputLength = 0;
		byte[] myOutput = new byte[0];
		
		if (byteStrings == null || byteStrings.size() == 0)
			return null;
		
		for (int i = 0; i < byteStrings.size(); i++) {
			if (byteStrings.get(i).getType() != CBORType.ByteString)
				return null;
			outputLength += byteStrings.get(i).GetByteString().length;
		}
		
		int offset = 0;
		myOutput = new byte[outputLength];
		
		for (int i = 0; i < byteStrings.size(); i++) {
			byte[] objBytes = byteStrings.get(i).GetByteString();
			System.arraycopy(objBytes, 0, myOutput, offset, objBytes.length);
			offset += objBytes.length;
		}
		
		return myOutput;
		
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
			if (labelList.get(i) == null || valueList.get(i) == null)
				return null;
			
			if (labelList.get(i).getType() != CBORType.Integer &&
					labelList.get(i).getType() != CBORType.TextString)
				return null;
			
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
		byte mapTypeValue = (byte) 0b10100000;
		mapHeader[0] |= mapTypeValue;
		
		byte[] serializedMap = new byte[mapHeader.length + mapContent.length];
		System.arraycopy(mapHeader, 0, serializedMap, 0, mapHeader.length);
		System.arraycopy(mapContent, 0, serializedMap, mapHeader.length, mapContent.length);
		
		return serializedMap;
		
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
    
    /**
     *  Check whether two byte arrays are equal, in constant time
     * @param array1   The first byte array to compare 
     * @param array2   The second byte array to compare
     * @return  True if the two arrays are equal, or false otherwise
     */
	public static boolean compareByteArrays(byte[] array1, byte[] array2) {

		if (array1 == null) {
			return (array2 == null);
		}
		else if (array2 == null) {
			return false;
		}
		
		int length = array1.length;
		if (length != array2.length) {
			return false;
		}

		byte[] result = new byte[] {0x00};
		
		for (int i = 0; i < length; i++) {
			result[0] |= (array1[i] ^ array2[i]);
		}

		return Arrays.equals(new byte[] {0x00}, result);

	}
    
    /**
     * Get an available Connection Identifier to offer to the other peer
     *  
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @param db   The database of OSCORE security contexts when using EDHOC to key OSCORE, it can be null
     * @param forbiddenIdentifier   The connection identifier C_I, it is null when the caller is the Initiator
     * @return   the newly allocated connection identifier, or null in case of errors or if no connection identifier is available
     */
    public static byte[] getConnectionId(Set<CBORObject> usedConnectionIds, OSCoreCtxDB db, byte[] forbiddenIdentifier) {
    	
    	if (usedConnectionIds == null)
    		return null;
    
    	synchronized(usedConnectionIds) {
    		
    		return allocateConnectionId(usedConnectionIds, db, forbiddenIdentifier);
    		
    	}
    	
    }
        
    /**
     * Actually allocate an available Connection Identifier to offer to the other peer
     *  
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @param db   The database of OSCORE security contexts when using EDHOC to key OSCORE, it can be null
     * @param forbiddenIdentifier   The connection identifier C_I, it is null when the caller is the Initiator
     * @return   the newly allocated connection identifier, or null in case of errors or if no connection identifiers are available
     */
     static byte[] allocateConnectionId(Set<CBORObject> usedConnectionIds,
    										   OSCoreCtxDB db, byte[] forbiddenIdentifier) {

        byte[] identifier = null;
         
        /* Check if the empty connection identifier 0x is available */
        
	    identifier = new byte[0];
	    identifier = checkAndCommitConnectionId(identifier, usedConnectionIds, db, forbiddenIdentifier);
        if (identifier != null)
        	return identifier;
        
    	
        /* Check if a 1-byte connection identifier is available */
        
    	// Check the range encoding the values 0..23. These connection identifiers
    	// encode on the wire as a CBOR integer C_X, with numeric value 0..23
        for (int i = 0; i <= 23; i++) {
        	
        	identifier = new byte[1];
        	identifier[0] = (byte) (i & 0xff);
    	    identifier = checkAndCommitConnectionId(identifier, usedConnectionIds, db, forbiddenIdentifier);
            if (identifier != null)
            	return identifier;
        	
    	}
        
    	// Check the range encoding the values 32..55. These connection identifiers
    	// encode on the wire as a CBOR integer C_X, with numeric value -24..-1
        for (int i = 32; i <= 55; i++) {
        	
        	identifier = new byte[1];
        	identifier[0] = (byte) (i & 0xff);
    	    identifier = checkAndCommitConnectionId(identifier, usedConnectionIds, db, forbiddenIdentifier);
            if (identifier != null)
            	return identifier;
        	
    	}

    	// Check the remaining ranges 24..31 and 56..255
        for (int i = 24; i <= 255; i++) {
        	
        	// Skip this range as it was already checked before
        	if (i >= 32 && i <= 55)
        		continue;
        	
        	identifier = new byte[1];
        	identifier[0] = (byte) (i & 0xff);
    	    identifier = checkAndCommitConnectionId(identifier, usedConnectionIds, db, forbiddenIdentifier);    	    	
            if (identifier != null)
            	return identifier;
        	
    	}
    	
    	
    	/* Check if a 2-byte connection identifier is available */
        
        for (int i = 0; i <= 255; i++) {
        	
            identifier = new byte[2];
        	identifier[0] = (byte) (i & 0xff);
        	
        	for (int j = 0; j <= 255; j++) {
        		identifier[1] = (byte) (j & 0xff);
        	    byte[] retIdentifier = checkAndCommitConnectionId(identifier, usedConnectionIds, db, forbiddenIdentifier);
                if (retIdentifier != null) {
                	return retIdentifier;
                }
		    	
        	}
        	
    	}
      
    	/* Check if a 3-byte connection identifier is available */
        
        for (int i = 0; i <= 255; i++) {

        	identifier = new byte[3];
        	identifier[0] = (byte) (i & 0xff);
        	
        	for (int j = 0; j <= 255; j++) {
        		
        		identifier[1] = (byte) (j & 0xff);
            	
            	for (int k = 0; k <= 255; k++) {
            		
            		identifier[2] = (byte) (k & 0xff);
            	    byte[] retIdentifier = checkAndCommitConnectionId(identifier, usedConnectionIds, db, forbiddenIdentifier);
                    if (retIdentifier != null)
                    	return retIdentifier;
        		}
		    	
        	}
        	
    	}
        
        return null;
    	
    }
    
    /**
     * Check if a Connection Identifier is available to offer to the other peer
     *
     * @param identifier   The candidate connection identifier to use as OSCORE Recipient ID
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @param db   The database of OSCORE security contexts when using EDHOC to key OSCORE, it can be null
     * @param forbiddenIdentifier   The connection identifier C_I, it is null when the caller is the Initiator
     * @return   the newly allocated connection identifier, or null in case it is not available
     */
    private static byte[] checkAndCommitConnectionId(byte[] identifier, Set<CBORObject> usedConnectionIds,
    												 OSCoreCtxDB db, byte[] forbiddenIdentifier) {
    	
        if (db != null) {
        	// EDHOC is used for keying OSCORE
        	synchronized (db) {
        		return commitConnectionIdForOSCORE(identifier, db, usedConnectionIds, forbiddenIdentifier);
        	}
        }
        else {
    	    CBORObject identifierCbor = CBORObject.FromObject(identifier);
        	
        	if (usedConnectionIds.contains(identifierCbor) == false) {
	    		usedConnectionIds.add(identifierCbor);
	    		return identifier;
        	}
        }
        
        return null;
    	
    }
    
    /**
     * Check for the availability of an OSCORE Recipient ID and the corresponding, identical EDHOC Connection Identifier.
     * If they are both available, mark them as used and return the Connection Identifier. Otherwise, return null.
     *  
     * @param recipientID   The candidate connection identifier to use as OSCORE Recipient ID
     * @param db   The database of OSCORE security contexts when using EDHOC to key OSCORE
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @param forbiddenIdentifier   The connection identifier to avoid, it can be null if there is no constraint
     * @return   the newly allocated connection identifier, or null in case of errors or unavailability
     */
    private static byte[] commitConnectionIdForOSCORE(byte[] recipientId, OSCoreCtxDB db,
    												  Set<CBORObject> usedConnectionIds, byte[] forbiddenIdentifier) {
    
    	OSCoreCtx ctx = null;
    	
    	if (recipientId == null || db == null)
    		return null;
        try {
            ctx = db.getContext(recipientId, null);
        } catch (CoapOSException e) {
        	// Found multiple OSCORE Security Contexts with the same Recipient ID
        	return null;
        }
    	if (ctx == null) {
    		// The Recipient ID is available for OSCORE, i.e., it is
    		// currently not used in the sets of all the Recipient Contexts
    		
        	// The EDHOC Connection Identifier coincides with the one to avoid (i.e., C_I offered by the Initiator) 
        	if (forbiddenIdentifier != null && Arrays.equals(recipientId, forbiddenIdentifier) == true)
        		return null;
        	CBORObject identifierCbor = CBORObject.FromObject(recipientId);
        	if (usedConnectionIds.contains(identifierCbor) == false) {
	        	// The corresponding EDHOC Connection Identifier is also available
        		
        		usedConnectionIds.add(identifierCbor);
        		
        		// Allocate a non-finalized OSCORE Security Context, to have the Recipient ID as taken
        		try {
        			byte[] emptyArray = new byte[0];
    				ctx = new OSCoreCtx(emptyArray, true, null, null, recipientId, AlgorithmID.HKDF_HMAC_SHA_256, 0, null, null, 0);
    				db.addContext(ctx);
    			} catch (OSException | NullPointerException e) {
    				System.err.println("Error when allocating an EDHOC Connection Identifier to use as "
    						           + "OSCORE Recipient ID" + e.getMessage());
    				
    				// Rollback
    				usedConnectionIds.remove(identifierCbor);
    				if (ctx != null) {
    					db.removeContext(ctx);
    				}
    				
    				return null;
    			}
        		
        		return recipientId;
        	}
    	}
    	
    	return null;
    	
    }
    
    /**
     * Deallocate a Connection Identifier previously locked to offer to a peer
     * Note that, if this was an OSCORE Recipient ID, the Recipient ID itself will not be deallocated
     *  
     * @param connectionId   The Connection Identifier to release
     * @param usedConnectionIds   The set of already allocated Connection Identifiers
     * @param db   The database of OSCORE security contexts when using EDHOC to key OSCORE, it can be null
     */
    public static void releaseConnectionId (byte[] connectionId, Set<CBORObject> usedConnectionIds, OSCoreCtxDB db) {
    	
    	if (connectionId == null)
    		return;
    	
    	synchronized (usedConnectionIds) {
    		CBORObject connectionIdCbor = CBORObject.FromObject(connectionId); 
    		usedConnectionIds.remove(connectionIdCbor);
    	}
    	
    	if (db != null) {
        	// EDHOC is used for keying OSCORE. The EDHOC connection identifier is the OSCORE Recipient ID.
    		
    		synchronized (db) {
	    		OSCoreCtx ctx = null;
				try {
					ctx = db.getContext(connectionId, null);
				} catch (CoapOSException e) {
					System.err.println("Found multiple OSCORE Security Contexts with the same Recipient ID " +
									   StringUtil.byteArray2HexString(connectionId) + "\n" + e.getMessage());
				}
	    		if (ctx != null) {
	    			db.removeContext(ctx);
	    		}
    		}
    			
    	}
    	
    }
    
	/**
	 * Remove an EDHOC session from the list of active sessions; release the used Connection Identifier; invalidate the session
	 * @param session   The EDHOC session to invalidate
	 * @param connectionIdentifier   The Connection Identifier used for the session to invalidate
	 * @param edhocSessions   The set of active EDHOC sessions of the recipient
     * @param usedConnectionIds   The collection of already allocated Connection Identifiers
	 */
	public static void purgeSession(EdhocSession session, byte[] connectionIdentifier,
									HashMap<CBORObject, EdhocSession> edhocSessions, Set<CBORObject> usedConnectionIds) {
		if (session != null) {
			CBORObject connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
		    edhocSessions.remove(connectionIdentifierCbor);
		    releaseConnectionId(connectionIdentifier, usedConnectionIds, session.getOscoreDb());
		    
		    session.deleteTemporaryMaterial();
		    if(session.getSideProcessor() != null) {
		    	session.getSideProcessor().removeResults();
		    	session.getSideProcessor().setEdhocSession(null);
		    }
		    
		    session = null;
		}
	}
    
    /**
     * Generate an asymmetric key pair, according to the specified elliptic curve
     *  
     * @param keyCurve   The elliptic curve
     * @return    The generated asymmetric key pair, or null in case of error
     */
    public static OneKey generateKeyPair (int keyCurve) {
    	
    	OneKey keyPair = null;
    	
		// Generate the new long-term asymmetric key pair 
		try {
	 		if (keyCurve == KeyKeys.EC2_P256.AsInt32()) {
	 			keyPair = OneKey.generateKey(AlgorithmID.ECDSA_256);
	 		}
	 		else if (keyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	    		Provider EdDSA = new EdDSASecurityProvider();
	        	Security.insertProviderAt(EdDSA, 1);
	    		keyPair = OneKey.generateKey(AlgorithmID.EDDSA);
	    	}
	 		else if (keyCurve == KeyKeys.OKP_X25519.AsInt32()) {
				keyPair = SharedSecretCalculation.generateCurve25519OneKey();
	    	}
			
		} catch (CoseException e) {
			System.err.println("Error while generating the key pair");
			return null;
		}
		
		// Print out the base64 serialization of the key pair
		/*
		byte[] keyPairBytes = keyPair.EncodeToBytes();
    	String testKeyBytesBase64 = Base64.encodeBytes(keyPairBytes);
    	System.out.println(testKeyBytesBase64);
    	
    	System.out.println(keyCurve);
    	System.out.println(keyPair.AsCBOR());
    	*/
		
		// Print out the base64 serialization of the public key only
		/*
    	OneKey testPublicKey = keyPair.PublicKey();
    	byte[] testPublicKeyBytes = testPublicKey.EncodeToBytes();
    	String testPublicKeyBytesBase64 = Base64.encodeBytes(testPublicKeyBytes);
    	System.out.println(testPublicKeyBytesBase64);
    	
    	System.out.println(keyCurve);
    	System.out.println(testPublicKey.AsCBOR());
    	*/
    	
    	return keyPair;
    	
    }
    
    /**
     * Print out a byte string in a convenient diagnostic way
     *  
     * @param header   First readable part of the output
     * @param bstr   Actual binary content to print
     */
    public static void nicePrint(String header, byte[] content) {
    	
    	System.out.println(header + " (" + (content.length) + " bytes):");
    	
    	String contentStr = StringUtil.byteArray2HexString(content).toLowerCase();
    	for (int i = 0; i < (content.length * 2); i++) {
    		if ((i != 0) && (i % 20) == 0)
    	    	System.out.println();
    		
        	System.out.print(contentStr.charAt(i));
    		if ((i % 2) == 1)
    	    	System.out.print(" ");
    	}
    	
    	System.out.println("\n");

    }
    
	public static OneKey makeSingleKey(OneKey keyPair, boolean isPrivate) {
		
	    CBORObject key = CBORObject.NewMap();
        OneKey coseKey = null;
	    
        key.Add(KeyKeys.KeyType.AsCBOR(), keyPair.get(KeyKeys.KeyType));
        
	    if (isPrivate) {
	    	if(keyPair.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2) {	    		
		        key.Add(KeyKeys.EC2_Curve.AsCBOR(), keyPair.get(KeyKeys.EC2_Curve));
		        key.Add(KeyKeys.EC2_D.AsCBOR(), keyPair.get(KeyKeys.EC2_D));

	    	}
	    	else if(keyPair.get(KeyKeys.KeyType) == KeyKeys.KeyType_OKP) {	    		
		        key.Add(KeyKeys.OKP_Curve.AsCBOR(), keyPair.get(KeyKeys.OKP_Curve));
		        key.Add(KeyKeys.OKP_D.AsCBOR(), keyPair.get(KeyKeys.OKP_D));
	    	}
	        
	    }
	    else {
	    	if(keyPair.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2) {
		        key.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
		        key.Add(KeyKeys.EC2_X.AsCBOR(), keyPair.get(KeyKeys.EC2_X));
		        key.Add(KeyKeys.EC2_Y.AsCBOR(), keyPair.get(KeyKeys.EC2_Y));
	    	}
	    	else if(keyPair.get(KeyKeys.KeyType) == KeyKeys.KeyType_OKP) {	    		
		        key.Add(KeyKeys.OKP_Curve.AsCBOR(), keyPair.get(KeyKeys.OKP_Curve));
		        key.Add(KeyKeys.OKP_X.AsCBOR(), keyPair.get(KeyKeys.OKP_X));
	    	}
	    }
	    
        try {
        	coseKey = new OneKey(key);
		} catch (CoseException e) {
			System.err.println(e.getMessage());
			System.err.println("Error while generating the COSE key");
		}
	    return coseKey;
		
	}
	
    /**
     * Build SUITES_R
     *  
     * @param cipherSuites   The list of supported cipher suites for this peer to include in SUITES_R
     * @return SUITES_R, as a CBOR object
     */
	public static CBORObject buildSuitesR(List<Integer> cipherSuites) {
		
		CBORObject suitesR;
		
		if (cipherSuites.size() == 1) {
			int suite = cipherSuites.get(0).intValue();
			suitesR = CBORObject.FromObject(suite);
		}
		// This peer supports multiple cipher suites
		else {
			suitesR = CBORObject.NewArray();
			for (Integer i : cipherSuites) {
				suitesR.Add(i.intValue());
			}
		}
		
		return suitesR;
		
	}
	
    /**
     * Build an ID_CRED using 'kcwt', with value a CWT as a CBOR array,
     *  
     * @param cwt   The CWT to use
     * @return The ID_CRED, as a CBOR map
     */
	public static CBORObject buildIdCredKcwt(CBORObject cwt) {
		
		CBORObject idCred = CBORObject.NewMap();
		idCred.Add(Constants.COSE_HEADER_PARAM_KCWT, cwt);
		return idCred;
		
	}
	
    /**
     * Build an ID_CRED using 'kccs', with value a CWT Claims Set (CCS) as a CBOR map
     *  
     * @param claimSet   The CWT Claims Set to use, as a CBOR map
     * @return The ID_CRED, as a CBOR map
     */
	public static CBORObject buildIdCredKccs(CBORObject claimSet) {
		
		CBORObject idCred = CBORObject.NewMap();
		idCred.Add(Constants.COSE_HEADER_PARAM_KCCS, claimSet);
		return idCred;
		
	}
	
    /**
     * Build an ID_CRED using 'kid'
     *  
     * @param kid   The kid to use
     * @return The ID_CRED, as a CBOR map
     */
	public static CBORObject buildIdCredKid(byte[] kid) {
		
		CBORObject idCred = CBORObject.NewMap();
		idCred.Add(HeaderKeys.KID.AsCBOR(), kid);
		return idCred;
		
	}
	
    /**
     * Build an ID_CRED using 'x5chain'
     *  
     * @param cert   The binary serialization of the x509 certificate
     * @return The ID_CRED, as a CBOR map
     */
	public static CBORObject buildIdCredX5chain(byte[] cert) {
		
		CBORObject idCred = CBORObject.NewMap();
		
		// Since a single certificate is specified,
		// the map element encodes it as a CBOR byte string
		idCred.Add(Constants.COSE_HEADER_PARAM_X5CHAIN, cert);
		return idCred;
		
	}
	
    /**
     * Build an ID_CRED using 'x5t'
     *  
     * @param cert   The binary serialization of the x509 certificate
     * @return The ID_CRED, as a CBOR map
     */
	public static CBORObject buildIdCredX5t(byte[] cert) {
		
		CBORObject idCred = CBORObject.NewMap();
		
		CBORObject idCredElem = CBORObject.NewArray();
		idCredElem.Add(-15); // SHA-2 256-bit Hash truncated to 64-bits
		byte[] hash = null;
		try {
			hash = Util.computeHash(cert, "SHA-256");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error while hashing the x509 certificate: " + e.getMessage());
			return null;
		}
		if (hash == null) {
			return null;
		}
		byte[] truncatedHash = new byte[8];
		System.arraycopy(hash, 0, truncatedHash, 0, 8);
		idCredElem.Add(truncatedHash);
		
		idCred.Add(Constants.COSE_HEADER_PARAM_X5T, idCredElem);
				
		return idCred;
		
	}
	
    /**
     * Build an ID_CRED using 'x5u'
     *  
     * @param uri   The URI pointing to the certificate
     * @return The ID_CRED, as a CBOR map
     */
	public static CBORObject buildIdCredX5u(String uri) {
		
		CBORObject idCred = CBORObject.NewMap();
		idCred.Add(Constants.COSE_HEADER_PARAM_X5U, uri);
		return idCred;
		
	}
	
    /**
     * Build an ID_CRED to use with 'kid'
     *  
     * @param identityKey   The identity key to encode as CRED
     * @param subjectName   The subject name associated to this key, it can be an empty string
     * @return The CRED, as a byte serialization of a deterministic CBOR map
     */
	public static byte[] buildCredRawPublicKey(OneKey identityKey, String subjectName) {
		
		if (identityKey  == null || subjectName == null)
			return null;
		
        List<CBORObject> labelList = new ArrayList<>();
        List<CBORObject> valueList = new ArrayList<>();
        labelList.add(KeyKeys.KeyType.AsCBOR());
        valueList.add(identityKey.get(KeyKeys.KeyType));
        if (identityKey.get(KeyKeys.KeyType) == KeyKeys.KeyType_OKP) {
            labelList.add(KeyKeys.OKP_Curve.AsCBOR());
            valueList.add(identityKey.get(KeyKeys.OKP_Curve));
            labelList.add(KeyKeys.OKP_X.AsCBOR());
            valueList.add(identityKey.get(KeyKeys.OKP_X));
		}
		else if (identityKey.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2) {
            labelList.add(KeyKeys.EC2_Curve.AsCBOR());
            valueList.add(identityKey.get(KeyKeys.EC2_Curve));
            labelList.add(KeyKeys.EC2_X.AsCBOR());
            valueList.add(identityKey.get(KeyKeys.EC2_X));
            labelList.add(KeyKeys.EC2_Y.AsCBOR());
            valueList.add(identityKey.get(KeyKeys.EC2_Y));
		}
		else {
			return null;
		}
        labelList.add(CBORObject.FromObject("subject name"));
        valueList.add(CBORObject.FromObject(subjectName));
        return Util.buildDeterministicCBORMap(labelList, valueList);
		
	}
	
    /**
     * Build an ID_CRED to use with 'kid2', with value a CWT Claims Set (CCS) 
     *  
     * @param identityKey   The identity key to encode as CRED
     * @param subjectName   The subject name associated to this key. It can also be an empty string, or null if none is provided
     * @param kid   The key identifier associated to this key
     * @return The CRED, as a byte serialization of a CBOR map
     */
	public static byte[] buildCredRawPublicKeyCcs(OneKey identityKey, String subjectName, CBORObject kid) {
		
		if (identityKey  == null)
			return null;
		
		CBORObject coseKeyMap = CBORObject.NewOrderedMap();
		coseKeyMap.Add(KeyKeys.KeyType.AsCBOR(), identityKey.get(KeyKeys.KeyType));
		coseKeyMap.Add(KeyKeys.KeyId.AsCBOR(), kid);
		if (identityKey.get(KeyKeys.KeyType) == KeyKeys.KeyType_OKP) {
			coseKeyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), identityKey.get(KeyKeys.OKP_Curve));
			coseKeyMap.Add(KeyKeys.OKP_X.AsCBOR(), identityKey.get(KeyKeys.OKP_X));
		}
		else if (identityKey.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2) {
			coseKeyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), identityKey.get(KeyKeys.EC2_Curve));
			coseKeyMap.Add(KeyKeys.EC2_X.AsCBOR(), identityKey.get(KeyKeys.EC2_X));
			coseKeyMap.Add(KeyKeys.EC2_Y.AsCBOR(), identityKey.get(KeyKeys.EC2_Y));
		}
		else {
			return null;
		}
		
		CBORObject cnfMap = CBORObject.NewOrderedMap();
		cnfMap.Add(Constants.CWT_CNF_COSE_KEY, coseKeyMap);
		
		CBORObject claimSetMap = CBORObject.NewOrderedMap();
		
		if (subjectName != null) {
			claimSetMap.Add(Constants.CWT_CLAIMS_SUB, subjectName);
		}
		
		claimSetMap.Add(Constants.CWT_CLAIMS_CNF, cnfMap);

		System.out.println("CCS serialization: " + StringUtil.byteArray2HexString(claimSetMap.EncodeToBytes()));
		
        return claimSetMap.EncodeToBytes();
		
	}
    
    /**
     * Check that a signature key is compliant with the selected cipher suite
     *  
     * @param identityKey   The signature key to check against the selected cipher suite
     * @param selectedCipherSuite   The selected cipher suite used in an EDHOC session
     * @return True in case the key complies with the selected cipher suite, or false otherwise
     */
	public static boolean checkSignatureKeyAgainstCipherSuite(OneKey key, int selectedCipherSuite) {
			
		
		if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_0 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_1) {
			
				if (key.get(KeyKeys.KeyType) != KeyKeys.KeyType_OKP) {
					System.err.println("Invalid key type - Expected key type: OKP");
					return false;
				}
				
			if (key.get(KeyKeys.OKP_Curve) != KeyKeys.OKP_Ed25519) {
				System.err.println("Invalid OKP curve - Expected curve: Ed25519");
				return false;
			}
			
		}
		if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_2 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_3) {
				
			if (key.get(KeyKeys.KeyType) != KeyKeys.KeyType_EC2) {
				System.err.println("Invalid key type - Expected key type: EC2");
				return false;
			}
				
			if (key.get(KeyKeys.EC2_Curve) != KeyKeys.EC2_P256) {
				System.err.println("Invalid EC2 curve - Expected curve: P-256");
				return false;
			}
				
		}
				
		return true;
		
	}
	
    /**
     * Check that a Diffie-Hellman key is compliant with the selected cipher suite
     *  
     * @param identityKey   The signature key to check against the selected cipher suite
     * @param selectedCipherSuite   The selected cipher suite used in an EDHOC session
     * @return True in case the key complies with the selected cipher suite, or false otherwise
     */
	public static boolean checkDiffieHellmanKeyAgainstCipherSuite(OneKey key, int selectedCipherSuite) {
			
		if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_0 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_1) {
		    
			if (key.get(KeyKeys.KeyType) != KeyKeys.KeyType_OKP) {
				System.err.println("Invalid key type - Expected key type: OKP");
				return false;
			}
				
			if (key.get(KeyKeys.OKP_Curve) != KeyKeys.OKP_X25519) {
				System.err.println("Invalid OKP curve - Expected curve: Ed25519");
				return false;
			}
			
		}
		if (selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_2 || selectedCipherSuite == Constants.EDHOC_CIPHER_SUITE_3) {
				
			if (key.get(KeyKeys.KeyType) != KeyKeys.KeyType_EC2) {
				System.err.println("Invalid key type - Expected key type: EC2");
				return false;
			}
				
			if (key.get(KeyKeys.EC2_Curve) != KeyKeys.EC2_P256) {
				System.err.println("Invalid EC2 curve - Expected curve: P-256");
				return false;
			}
				
		}
		
		return true;
		
	}

	
    /**
     * Check if a CBOR integer complies with deterministic CBOR encoding
     *  
     * @param obj   The CBOR integer to check
     * @return True in case the CBOR integer complies with deterministic CBOR encoding, or false otherwise
     */
	public static boolean isDeterministicCborInteger (CBORObject obj) {
		
		if (obj.getType() != CBORType.Integer)
			return false;
		
		byte[] objBytes = obj.EncodeToBytes();
		
		switch (objBytes.length) {
			case 1:
				return true;
			case 2:
				if (obj.AsInt32() >= -24 && obj.AsInt32() <= 23)
					return false;
				else
					return true;
			case 3:
				if (obj.AsInt32() >= -256 && obj.AsInt32() <= 255)
					return false;
				else
					return true;
			case 5:
				if (obj.AsInt32() >= -65536 && obj.AsInt32() <= 65535)
					return false;
				else
					return true;
			case 9:
				if (obj.AsInt64Value() >= -4294967296L && obj.AsInt64Value() <= 4294967295L)
					return false;
				else
					return true;
			default:
				return false;
		}
		
	}
	
}
