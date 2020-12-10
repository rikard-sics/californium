/*******************************************************************************
 * Copyright (c) 2020 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial creation
 *    Rikard Höglund (RISE SICS) - Group OSCORE receiver functionality
 ******************************************************************************/
package org.eclipse.californium.cose;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import org.eclipse.californium.core.coap.CoAP;
import java.security.PublicKey;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalKeyPairGenerator;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;


public class Tester {

    public static void runme() throws Exception {
		
        // === Initial testing ===
//
        OneKey okCOSE1 = OneKey.generateKey(KeyKeys.OKP_Ed25519);
        OneKey okCOSE2 = new OneKey(okCOSE1.AsPublicKey(), okCOSE1.AsPrivateKey());
        OneKey okCOSE3 = new OneKey(okCOSE1.AsCBOR());
        OneKey okCOSE4 = new OneKey(okCOSE2.AsCBOR());

        System.out.println(okCOSE1.AsCBOR());
        System.out.println(okCOSE2.AsCBOR());
        System.out.println(okCOSE3.AsCBOR());
        System.out.println(okCOSE4.AsCBOR());
//
//        // Testing lines:
        OneKey first = OneKey.generateKey(AlgorithmID.EDDSA);
        OneKey second = new OneKey(first.AsPublicKey(), first.AsPrivateKey());
        //

        // === Java 15 testing ===
        /*
         * KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519"); KeyPair kp = kpg.generateKeyPair(); PublicKey
         * publicJava15 = kp.getPublic(); PrivateKey privateJava15 = kp.getPrivate(); OneKey java15Test = new
         * OneKey(publicJava15, privateJava15); System.out.println(java15Test.AsCBOR());
         */
        
        // === ECDSA testing ===
        KeyPairGenerator kpg_ECDSA = KeyPairGenerator.getInstance("EC");
        KeyPair kp_ECDSA = kpg_ECDSA.generateKeyPair();
        PublicKey publicJava15_ECDSA = kp_ECDSA.getPublic();
        PrivateKey privateJava15_ECDSA = kp_ECDSA.getPrivate();
        OneKey java15Test_ECDSA = new OneKey(publicJava15_ECDSA, privateJava15_ECDSA);
        System.out.println(java15Test_ECDSA.AsCBOR());


        // === DTLS testing below ===

        KeyPair keyPair = new ThreadLocalKeyPairGenerator("Ed25519").current().generateKeyPair();
        OneKey coseVersion = new OneKey(keyPair.getPublic(), keyPair.getPrivate());
        PublicKey publicJava = coseVersion.AsPublicKey();
        PrivateKey privateJava = coseVersion.AsPrivateKey();

        //

        // pAMnAQEgBiFYIDajeDBT7zonm7zQ9psEjSou6/90+fTTQorNWMVUKhI2
        // Now the client keys follow...
        //
        // pQMnAQEgBiFYIOUm2zJfz1XiEVFZrqrByQs8bUjYwoPbW4vDpUysEs4bI1gggmNaMokjWMs080uKeRHfeefHQKs0zGsVtORt9V9TbX4=
        // pAMnAQEgBiFYIOUm2zJfz1XiEVFZrqrByQs8bUjYwoPbW4vDpUysEs4b

        //


        // Start from Java key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair kp = kpg.generateKeyPair();
        PublicKey javaPublic = kp.getPublic();
        PrivateKey javaPrivate = kp.getPrivate();

        // Start from COSE OneKey
        OneKey coseBasedKey = OneKey.generateKey(KeyKeys.OKP_Ed25519);
        // Works (Provider must be at 1)

        // Generate key using Java, then build OneKey
        OneKey originallyJava = new OneKey(javaPublic, javaPrivate);
        // Works

        // Make Base64 key from above
        String base64New = java.util.Base64.getEncoder().encodeToString(originallyJava.EncodeToBytes());
        System.out.println("New base64 " + base64New);

        // OneKey from the new Base64 String
        String base64String = "pQEBAycgBiFYILan2jOypo2aquXu9dGULNpcpFG/p1DCmz5dtSDWE+AdI1gg57sTlm2NyGDkBiz0Iswa85MvPptw6RAyUiTcCMorJOs=";
        OneKey asymmetricB = new OneKey(CBORObject.DecodeFromBytes(java.util.Base64.getDecoder().decode(base64String)));

        System.out.println(" B " + asymmetricB.AsCBOR());

        String javaVersion = System.getProperty("java.version");
        System.out.println("Ver " + javaVersion);
        if (!javaVersion.equals("15")) {
            System.err.println("Needs Java 15!");
        }

        //
        String keyString = "pQMnAQEgBiFYIDajeDBT7zonm7zQ9psEjSou6/90+fTTQorNWMVUKhI2I1ggkOTw7TxVACoEj/Ss6wwASfplNFQ5lUYVfQCqmKEvpeM=";
        OneKey asymmetric = new OneKey(CBORObject.DecodeFromBytes(java.util.Base64.getDecoder().decode(keyString)));

        String keyStringPublic = "pAMnAQEgBiFYIDajeDBT7zonm7zQ9psEjSou6/90+fTTQorNWMVUKhI2";
        OneKey asymmetricPublic = new OneKey(
                CBORObject.DecodeFromBytes(java.util.Base64.getDecoder().decode(keyStringPublic)));
        //
        DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder()
                .setAddress(new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));
        config.setSupportedCipherSuites(new CipherSuite[] { CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 });
        config.setIdentity(asymmetric.AsPrivateKey(), asymmetric.AsPublicKey());

        config.setClientAuthenticationRequired(false);
        DTLSConnector connector = new DTLSConnector(config.build());
        CoapEndpoint cep = new org.eclipse.californium.core.network.CoapEndpoint.Builder().setConnector(connector)
                .setNetworkConfig(NetworkConfig.getStandard()).build();
        CoapServer rs = new CoapServer();
        rs.addEndpoint(cep);
        // Add a CoAP (no 's') endpoint for authz-info
        CoapEndpoint aiep = new org.eclipse.californium.core.network.CoapEndpoint.Builder()
                .setInetSocketAddress(new InetSocketAddress(CoAP.DEFAULT_COAP_PORT)).build();
        rs.addEndpoint(aiep);
        rs.start();
        System.out.println("Server starting");
        System.out.println("Server starting");
        System.out.println("Server starting");
        System.out.println("Server starting");

        System.out.println("Helo");
        System.out.println("Helo");
        System.out.println("Helo");

        OneKey mykey = OneKey.generateKey(AlgorithmID.EDDSA);
        System.out.println("OUR D : " + Utils.toHexString(mykey.get(KeyKeys.OKP_D).GetByteString()));
        System.out.println("First generated key: " + mykey.AsCBOR().toString());

        OneKey mykeyFull = new OneKey(mykey.AsPublicKey(), mykey.AsPrivateKey());
        System.out.println("OUR mykeyFull D : " + Utils.toHexString(mykeyFull.get(KeyKeys.OKP_D).GetByteString()));
        System.out.println("New rebuilt key: " + mykeyFull.AsCBOR().toString());

        System.out.println("Private encoded: " + Utils.toHexString(mykey.AsPrivateKey().getEncoded()));
        System.out.println("Public encoded: " + Utils.toHexString(mykey.AsPublicKey().getEncoded()));

        OneKey fromCBOR = new OneKey(mykey.AsCBOR());
        System.out.println("CBOR Private encoded: " + Utils.toHexString(fromCBOR.AsPrivateKey().getEncoded()));
        System.out.println("CBOR Public encoded: " + Utils.toHexString(fromCBOR.AsPublicKey().getEncoded()));

	}
}
