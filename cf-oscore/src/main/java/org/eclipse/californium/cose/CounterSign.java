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

/**
 *
 * @author jimsch
 */
public class CounterSign extends Signer {
    
    public CounterSign() {
        contextString = "CounterSignature";
    }
    
    public CounterSign(byte[] rgb) throws CoseException {
        contextString = "CounterSignature";
        DecodeFromBytes(rgb);
    }
    
    public CounterSign(CBORObject cbor) throws CoseException {
        DecodeFromCBORObject(cbor);
        contextString = "CounterSignature";
    }
    
    public void DecodeFromBytes(byte[] rgb) throws CoseException
    {
        CBORObject obj = CBORObject.DecodeFromBytes(rgb);
        
        DecodeFromCBORObject(obj);
    }
    
    public byte[] EncodeToBytes() throws CoseException {
        return EncodeToCBORObject().EncodeToBytes();
    }
    
    public void Sign(Message message) throws CoseException {
        byte[] rgbBodyProtect;
        if (message.objProtected.size() > 0) rgbBodyProtect = message.objProtected.EncodeToBytes();
        else rgbBodyProtect = new byte[0];
        
        sign(rgbBodyProtect, message.rgbContent);        
    }
    
    public boolean Validate(Message message) throws CoseException {
        byte[] rgbBodyProtect;
        if (message.objProtected.size() > 0) rgbBodyProtect = message.objProtected.EncodeToBytes();
        else rgbBodyProtect = new byte[0];
        
        return validate(rgbBodyProtect, message.rgbContent);
    }

	@SuppressWarnings("unused")
	private Message m_msgToSign;
	@SuppressWarnings("unused")
	private Signer m_signerToSign;

	public void setObject(Message msg) {
		m_msgToSign = msg;
	}

	public void setObject(Signer signer) {
		m_signerToSign = signer;
	}

}
