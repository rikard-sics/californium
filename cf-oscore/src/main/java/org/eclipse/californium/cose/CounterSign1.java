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

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 *
 * @author Jim
 */
public class CounterSign1 extends Signer {
    public CounterSign1()
    {
        contextString = "CounterSignature0";
    }
    
    public CounterSign1(byte[] rgb) {
        contextString = "CounterSignature0";
        rgbSignature = rgb;
        rgbProtected = new byte[0];
    }
    
    public CounterSign1(OneKey key) {
        super(key);
        contextString = "CounterSignature0";
    }
    
	@SuppressWarnings("unused")
	private Message m_msgToSign;
	@SuppressWarnings("unused")
	private Signer m_signerToSign;
    
    public void setObject(Message msg)
    {
        m_msgToSign = msg;
    }
    
    public void setObject(Signer signer)
    {
        m_signerToSign = signer;
    }
    
    @Override
    public void DecodeFromCBORObject(CBORObject cbor) throws CoseException {
        if (cbor.getType() != CBORType.ByteString) {
            throw new CoseException("Invalid format for Countersignature0");
        }
        
        rgbSignature = cbor.GetByteString();
        rgbProtected = new byte[0];
    }
    
    public CBORObject EncodeToCBORObject() throws CoseException {
        if (!objProtected.getValues().isEmpty() || !objUnprotected.getValues().isEmpty()) {
            throw new CoseException("CoutnerSign1 object cannot have protected or unprotected attributes");
        }
        
        return CBORObject.FromObject(rgbSignature);
    }
            
}
