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
import java.util.List;
import java.util.Map;
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
import org.eclipse.californium.oscore.OSCoreCtxDB;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

public class Util {

    /**
     *  Compute a ciphertext using the COSE Encrypt0 object
     * @param idCredX   The ID of the public credential of the encrypter as a CBOR map, or null for computing MAC_4 
     * @param externalData   The data to use as external_aad
     * @param plaintext   The plaintext to encrypt
     * @param alg   The encryption algorithm to use
     * @param iv   The IV to use for encrypting
     * @param key   The symmetric key to use for encrypting
     * @return  the computed ciphertext, or null in case of invalid input
     */
	public static byte[] encrypt (CBORObject idCredX, byte[] externalData, byte[] plaintext,
			                      AlgorithmID alg, byte[] iv, byte[] key) throws CoseException {
        
		if(externalData == null || plaintext == null || iv == null || key == null)
        	return null;       
		
        // The ID of the public credential has to be a CBOR map, except for computing MAC_4
        if(idCredX != null && idCredX.getType() != CBORType.Map)
        	return null;
                
        Encrypt0Message msg = new Encrypt0Message();
        
        // Set the protected header of the COSE object
        
        // The ID of the public credential is a CBOR map, except for computing MAC_4 in which case the Protected bucket is empty
        if(idCredX != null) {        
	        for(CBORObject label : idCredX.getKeys()) {
	            // All good if the map has only one element, otherwise it needs to be rebuilt deterministically
	        	msg.addAttribute(label, idCredX.get(label), Attribute.PROTECTED);
	        }
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
        System.out.println("aad                 : " + Utils.bytesToHex(msg.getExternal()));
        System.out.println("plaintext           : " + Utils.bytesToHex(msg.GetContent()));
        */
        
        // Perform the encryption
        msg.encrypt(key);
        
        // Debug print
        /*
        System.out.println("Encrypted content: " + Utils.bytesToHex(msg.getEncryptedContent()));
        */
        
        return msg.getEncryptedContent();
        
	}
	
    /**
     *  Decrypt a ciphertext using the COSE Encrypt0 object
     * @param idCredX   The ID of the public credential of the decrypter, as a CBOR map 
     * @param externalData   The data to use as external_aad
     * @param ciphertext   The ciphertext to decrypt
     * @param alg   The encryption algorithm to use
     * @param iv   The IV to use for decrypting
     * @param key   The symmetric key to use for decrypting
     * @return  the computed plaintext, or null in case of invalid input
     */
	public static byte[] decrypt (CBORObject idCredX, byte[] externalData, byte[] ciphertext, AlgorithmID alg, byte[] iv, byte[] key)
			                               throws CoseException {
        
		if(idCredX == null || externalData == null || ciphertext == null || iv == null || key == null)
        	return null;       
		
        // The ID of the public credential has to be a CBOR map ...
        if(idCredX.getType() != CBORType.Map)
        	return null;
        
        Encrypt0Message msg = new Encrypt0Message();
        
        // Set the protected header of the COSE object
        for(CBORObject label : idCredX.getKeys()) {
            // All good if the map has only one element, otherwise it needs to be rebuilt deterministically
        	msg.addAttribute(label, idCredX.get(label), Attribute.PROTECTED);
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
        System.out.println("aad                 : " + Utils.bytesToHex(msg.getExternal()));
        System.out.println("payload             : " + Utils.bytesToHex(msg.GetContent()));
        */
        
        // Perform the encryption
        msg.decrypt(key);
        
        // Debug print
        /*
        System.out.println("Decrypted content: " + Utils.bytesToHex(msg.GetContent()));
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
	 * Identifies the algorithm used by a key from the curve parameters.
	 * 
	 * @param key the key
	 * @return the algorithm used
	 */
	private static AlgorithmID determineKeyAlgorithm(OneKey key) {

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
			if (value >= -24 && value <= 23)
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
		
		if (inputObject == null ||  inputObject.getType() != CBORType.ByteString && inputObject.getType() != CBORType.Integer)
			return null;
		
		if (inputObject.getType() == CBORType.ByteString) {
			if(inputObject.GetByteString().length == 1) {
				return null;
			}
			return inputObject;
		}
		
		// The CBOR object is of Major Type "Integer"
		int value = inputObject.AsInt32() + 24;
		
		if(value < 0 || value > 47)
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
    
    /**
     * Get an available Connection Identifier to offer to the other peer
     *  
     * @param usedConnectionIds   The collection of already allocated Connection Identifiers
     * @param db   The database of OSCORE security contexts when using EDHOC to key OSCORE, it can be null
     * @return   the newly allocated connection identifier, or null in case of errors
     */
    public static byte[] getConnectionId (List<Set<Integer>> usedConnectionIds, OSCoreCtxDB db) {
    	
    	if (usedConnectionIds == null)
    		return null;
    
    	synchronized(usedConnectionIds) {
    		
    		if (db != null) {
    			synchronized(db) {
        			return allocateConnectionId(usedConnectionIds, db);	
    			}
    		}
    		else
    			return allocateConnectionId(usedConnectionIds, db);
    		
    	}
    	
    }
    
    /**
     * Actually allocate an available Connection Identifier to offer to the other peer
     * If EDHOC is used for keying OSCORE, Recipient IDs are used as Connect Identifiers
     *  
     * @param usedConnectionIds   The collection of already allocated Connection Identifiers
     * @param db   The database of OSCORE security contexts when using EDHOC to key OSCORE, it can be null
     * @return   the newly allocated connection identifier, or null in case of errors
     */
    private static byte[] allocateConnectionId(List<Set<Integer>> usedConnectionIds, OSCoreCtxDB db) {
    	
    	byte[] connectionId = null;
        boolean found = false;
    	
    	int maxIdValue;
    	
        // Start with 1 byte as size of the Connection ID; try with up to 4 bytes in size        
        for (int idSize = 1; idSize <= 4; idSize++) {
        	
        	if (idSize == 4)
        		maxIdValue = (1 << 31) - 1;
        	else
        		maxIdValue = (1 << (idSize * 8)) - 1;
        	
	        for (int j = 0; j <= maxIdValue; j++) {
	        	
	        	connectionId = Util.intToBytes(j);
    			
    			// This Connection ID is marked as not available to use
    			if (usedConnectionIds.get(idSize - 1).contains(j))
    				continue;
    			
    			try {
		        	// This Connection ID seems to be available to use 
	        		if (!usedConnectionIds.get(idSize - 1).contains(j)) {
	        			
	        			// Double check in the database of OSCORE Security Contexts
	        			if (db != null && db.getContext(connectionId) != null) {
	        				
	        				// A Security Context with this Connection ID used as Recipient ID exists and was not tracked!
	        				// Update the local list of used Connection IDs, then move on to the next candidate
	        				usedConnectionIds.get(idSize - 1).add(j);
	        				continue;
	        				
	        			}
	        			else {
	        				
	        				// This Recipient ID is actually available at the moment as Connection ID. Add it to the local list
	        				usedConnectionIds.get(idSize - 1).add(j);
	        				found = true;
	        				break;
	        			}
	        			
	        		}
    			}
        		catch(RuntimeException e) {
    				// Multiple Security Contexts with this Connection ID as Recipient ID exist and it was not tracked!
    				// Update the local list of used Connection IDs, then move on to the next candidate
    				usedConnectionIds.get(idSize - 1).add(j);
    				continue;
        		}
        			
	        }
	        
	        if (found)
	        	break;
	        	
        }
        
        if (!found)
        	return null;
        else
        	return connectionId;
    	
    }
    
    /**
     * Deallocate a Connection Identifier previously locked to offer to a peer
     * Note that, if this was an OSCORE Recipient ID, the Recipient ID itself will not be deallocated
     *  
     * @param connectionId   The Connection Identifier to release
     * @param usedConnectionIds   The collection of already allocated Connection Identifiers
     */
    public static void releaseConnectionId (byte[] connectionId, List<Set<Integer>> usedConnectionIds) {
    	
    	if (connectionId == null || connectionId.length > 4)
    		return;
    	
    	int connectionIdAsInt = bytesToInt(connectionId);
    	
    	if (connectionId.length != 0)
    		usedConnectionIds.get(connectionId.length - 1).remove(connectionIdAsInt);
    	// else set to false a to-be-introduced flag related to a zero-length connection ID
    	/*
    	 * 
    	 */
    	
    }
    
	/**
	 * Remove an EDHOC session from the list of active sessions; release the used Connection Identifier; invalidate the session
	 * @param session   The EDHOC session to invalidate
	 * @param connectionIdentifier   The Connection Identifier used for the session to invalidate
	 * @param edhocSessions   The list of active EDHOC sessions of the recipient
     * @param usedConnectionIds   The collection of already allocated Connection Identifiers
	 */
	public static void purgeSession(EdhocSession session, CBORObject connectionIdentifier,
			                        Map<CBORObject, EdhocSession> edhocSessions, List<Set<Integer>> usedConnectionIds) {
		if (session != null) {
		    edhocSessions.remove(connectionIdentifier, session);
		    Util.releaseConnectionId(connectionIdentifier.GetByteString(), usedConnectionIds);
		    session.deleteTemporaryMaterial();
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
	        	Security.insertProviderAt(EdDSA, 0);
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
    	String testKeyBytesBase64 = Base64.getEncoder().encodeToString(keyPairBytes);
    	System.out.println(testKeyBytesBase64);
    	
    	System.out.println(keyCurve);
    	System.out.println(keyPair.AsCBOR());
    	*/
		
		// Print out the base64 serialization of the public key only
		/*
    	OneKey testPublicKey = keyPair.PublicKey();
    	byte[] testPublicKeyBytes = testPublicKey.EncodeToBytes();
    	String testPublicKeyBytesBase64 = Base64.getEncoder().encodeToString(testPublicKeyBytes);
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
    	
    	String contentStr = Utils.bytesToHex(content);
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
		        key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
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
     * @param supportedCiphersuites   The list of supported ciphersuites for this peer
     * @return SUITES_R, as a CBOR object
     */
	public static CBORObject buildSuitesR(List<Integer> supportedCiphersuites) {
		
		CBORObject suitesR;
		
		if (supportedCiphersuites.size() == 1) {
			int cs = supportedCiphersuites.get(0).intValue();
			suitesR = CBORObject.FromObject(cs);
		}
		// This peer supports multiple ciphersuites
		else {
			suitesR = CBORObject.NewArray();
			for (Integer i : supportedCiphersuites) {
				suitesR.Add(i.intValue());
			}
		}
		
		return suitesR;
		
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
     * Build an ID_CRED using 'kid'
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
     * Check that a signature key is compliant with the selected cipher suite
     *  
     * @param identityKey   The signature key to check against the selected cipher suite
     * @param selectedCipherSuite   The selected cipher suite used in an EDHOC session
     * @return True in case the key complies with the selected cipher suite, or false otherwise
     */
	public static boolean checkSignatureKeyAgainstCiphersuite(OneKey key, int selectedCipherSuite) {
			
		
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
	public static boolean checkDiffieHellmanKeyAgainstCiphersuite(OneKey key, int selectedCipherSuite) {
			
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
	
}
