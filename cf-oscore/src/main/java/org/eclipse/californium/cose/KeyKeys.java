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
public enum KeyKeys {
    KeyType(1),
    Algorithm(3),
    KeyId(2),
    Key_Ops(4),
    Base_IV(5),
    Octet_K(-1),
    EC2_Curve(-1),
    EC2_X(-2),
    EC2_Y(-3),
    EC2_D(-4),
    OKP_Curve(-1),
    OKP_X(-2),
    OKP_D(-4),
            ;
    
    private final CBORObject value;
    
    public final static CBORObject KeyType_OKP = CBORObject.FromObject(1);
    public final static CBORObject KeyType_EC2 = CBORObject.FromObject(2);
    public final static CBORObject KeyType_Octet =  CBORObject.FromObject(4);
    
    public final static CBORObject EC2_P256 = CBORObject.FromObject(1);
    public final static CBORObject EC2_P384 = CBORObject.FromObject(2);
    public final static CBORObject EC2_P521 = CBORObject.FromObject(3);
    
    public final static CBORObject OKP_X25519 = CBORObject.FromObject(4);
    public final static CBORObject OKP_X448 = CBORObject.FromObject(5);
    public final static CBORObject OKP_Ed25519 = CBORObject.FromObject(6);
    public final static CBORObject OKP_Ed448 = CBORObject.FromObject(7);
    
    KeyKeys(int val) {
        this.value = CBORObject.FromObject(val);
    }
    
    public CBORObject AsCBOR() {
        return value;
    }
    
}
