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
package org.eclipse.californium.oscore.group.interop;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalKeyPairGenerator;

import com.upokecenter.cbor.CBORObject;

public class Tester {

	public static void main(String[] args) throws Exception {
		
		// Provider EdDSAX = new EdDSASecurityProvider();
		// Security.insertProviderAt(EdDSAX, 0);

		KeyPair keyPair = new ThreadLocalKeyPairGenerator("Ed25519").current().generateKeyPair();
		OneKey coseVersion = new OneKey(keyPair.getPublic(), keyPair.getPrivate());
		PublicKey publicJava = coseVersion.AsPublicKey();
		PrivateKey privateJava = coseVersion.AsPrivateKey();

		//

		// pAMnAQEgBiFYIDajeDBT7zonm7zQ9psEjSou6/90+fTTQorNWMVUKhI2
		// Now the client keys follow...
		// pQMnAQEgBiFYIOUm2zJfz1XiEVFZrqrByQs8bUjYwoPbW4vDpUysEs4bI1gggmNaMokjWMs080uKeRHfeefHQKs0zGsVtORt9V9TbX4=
		// pAMnAQEgBiFYIOUm2zJfz1XiEVFZrqrByQs8bUjYwoPbW4vDpUysEs4b

		//

		//
		String keyString = "pQMnAQEgBiFYIDajeDBT7zonm7zQ9psEjSou6/90+fTTQorNWMVUKhI2I1ggkOTw7TxVACoEj/Ss6wwASfplNFQ5lUYVfQCqmKEvpeM=";
		OneKey asymmetric = new OneKey(CBORObject.DecodeFromBytes(java.util.Base64.getDecoder().decode(keyString)));

		String keyStringPublic = "pAMnAQEgBiFYIDajeDBT7zonm7zQ9psEjSou6/90+fTTQorNWMVUKhI2";
		OneKey asymmetricPublic = new OneKey(
				CBORObject.DecodeFromBytes(java.util.Base64.getDecoder().decode(keyStringPublic)));
		//
		DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder()
	              .setAddress(
	                      new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));
		config.setSupportedCipherSuites(new CipherSuite[] {
				CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 });
	          config.setRpkTrustAll();
		config.setIdentity(asymmetric.AsPrivateKey(), asymmetric.AsPublicKey());

		config.setClientAuthenticationRequired(true);
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
		System.out.println("New rebuilt key:     " + mykeyFull.AsCBOR().toString());

		System.out.println("Private encoded: " + Utils.toHexString(mykey.AsPrivateKey().getEncoded()));
		System.out.println("Public encoded: " + Utils.toHexString(mykey.AsPublicKey().getEncoded()));

		OneKey fromCBOR = new OneKey(mykey.AsCBOR());
		System.out.println("CBOR Private encoded: " + Utils.toHexString(fromCBOR.AsPrivateKey().getEncoded()));
		System.out.println("CBOR Public encoded: " + Utils.toHexString(fromCBOR.AsPublicKey().getEncoded()));

	}
}
