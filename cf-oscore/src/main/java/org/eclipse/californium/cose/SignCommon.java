/*******************************************************************************

 * Original from https://github.com/cose-wg/COSE-JAVA Commit f972b11
 *
 * Copyright (c) 2016, Jim Schaad
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.

 * Neither the name of COSE-JAVA nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
     
 ******************************************************************************/
package org.eclipse.californium.cose;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

import org.eclipse.californium.core.Utils;


/**
 *
 * @author jimsch
 */

public abstract class SignCommon extends Message {
    protected String contextString;

    byte[] computeSignature(byte[] rgbToBeSigned, OneKey cnKey) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return computeSignature(alg, rgbToBeSigned, cnKey);
    }

    static byte[] computeSignature(AlgorithmID alg, byte[] rgbToBeSigned, OneKey cnKey) throws CoseException {
        String      algName = null;
        int         sigLen = 0;
        
        switch (alg) {
            case ECDSA_256:
                algName = "SHA256withECDSA";
                sigLen = 32;
                break;
            case ECDSA_384:
                algName = "SHA384withECDSA";
                sigLen = 48;
                break;
            case ECDSA_512:
                algName = "SHA512withECDSA";
                sigLen = 66;
                break;
            case EDDSA:
                algName = "NonewithEdDSA";
                break;
                
            default:
                throw new CoseException("Unsupported Algorithm Specified");
        }
        
        if (cnKey == null) {
            throw new NullPointerException();
        }
        
        PrivateKey  privKey = cnKey.AsPrivateKey();
        if (privKey == null) {
            throw new CoseException("Private key required to sign");
        }
        
        byte[]      result = null;
        try {
            Signature sig = Signature.getInstance(algName);
            sig.initSign(privKey);
            sig.update(rgbToBeSigned);
            
			System.out.println("COSE: To be signed: " + Utils.toHexString(rgbToBeSigned));
            
            result = sig.sign();
            if (sigLen > 0) {
                result = convertDerToConcat(result, sigLen);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature failure", ex);
        }
                
        return result;
    }
    
    private static byte[] convertDerToConcat(byte[] der, int len) throws CoseException {
        // this is far too naive
        byte[] concat = new byte[len * 2];

        // assumes SEQUENCE is organized as "R + S"
        int kLen = 4;
        if (der[0] != 0x30) {
            throw new CoseException("Unexpected signature input");
        }
        if ((der[1] & 0x80) != 0) {
            // offset actually 4 + (7-bits of byte 1)
            kLen = 4 + (der[1] & 0x7f);
        }
        
        // calculate start/end of R
        int rOff = kLen;
        int rLen = der[rOff - 1];
        int rPad = 0;
        if (rLen > len) {
            rOff += (rLen - len);
            rLen = len;
        } else {
            rPad = (len - rLen);
        }
        // copy R
        System.arraycopy(der, rOff, concat, rPad, rLen);
        
        // calculate start/end of S
        int sOff = rOff + rLen + 2;
        int sLen = der[sOff - 1];
        int sPad = 0;
        if (sLen > len) {
            sOff += (sLen - len);
            sLen = len;
        } else {
            sPad = (len - sLen);
        }
        // copy S
        System.arraycopy(der, sOff, concat, len + sPad, sLen);
        
        return concat;
    }
    
    boolean validateSignature(byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey) throws CoseException {
        AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
        return validateSignature(alg, rgbToBeSigned, rgbSignature, cnKey);
    }

    static boolean validateSignature(AlgorithmID alg, byte[] rgbToBeSigned, byte[] rgbSignature, OneKey cnKey) throws CoseException {
        String algName = null;
        boolean convert = false;

        switch (alg) {
        case ECDSA_256:
            algName = "SHA256withECDSA";
            convert = true;
            break;
        case ECDSA_384:
            algName = "SHA384withECDSA";
            convert = true;
            break;
        case ECDSA_512:
            algName = "SHA512withECDSA";
            convert = true;
            break;
            
        case EDDSA:
            algName = "NonewithEdDSA";
            break;

        default:
            throw new CoseException("Unsupported Algorithm Specified");
        }

        if (cnKey == null) {
            throw new NullPointerException();
        }

        PublicKey pubKey = cnKey.AsPublicKey();
        if (pubKey == null) {
            throw new CoseException("Public key required to verify");
        }

        boolean result = false;
        try {
            Signature sig = Signature.getInstance(algName);
            sig.initVerify(pubKey);
            sig.update(rgbToBeSigned);
            
			System.out.println("COSE: To be signed (checked): " + Utils.toHexString(rgbToBeSigned));

            if (convert) {
                rgbSignature = convertConcatToDer(rgbSignature);
            }
            result = sig.verify(rgbSignature);
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature verification failure", ex);
        }

        return result;
    }

    private static byte[] convertConcatToDer(byte[] concat) throws CoseException {
        int len = concat.length / 2;
        byte[] r = Arrays.copyOfRange(concat, 0, len);
        byte[] s = Arrays.copyOfRange(concat, len, concat.length);

        return ASN1.EncodeSignature(r, s);
    }
}
