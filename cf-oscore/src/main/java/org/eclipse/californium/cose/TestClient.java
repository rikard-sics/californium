/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Achim Kraus (Bosch Software Innovations GmbH) - add saving payload
 ******************************************************************************/
package org.eclipse.californium.cose;

import java.io.File;
import java.io.FileOutputStream;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;

public class TestClient {

	private static final File CONFIG_FILE = new File("Californium.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Fileclient";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 2 * 1024 * 1024; // 2 MB
	private static final int DEFAULT_BLOCK_SIZE = 512;

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
		}
	};

	/*
	 * Application entry point.
	 * 
	 */	
    public static void runme(String args[]) throws URISyntaxException, CoseException {
		NetworkConfig config = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		NetworkConfig.setStandard(config);

        String uri = "coaps://127.0.0.1/.well-known/core"; // URI parameter of the request

        String keyStringPublic = "pAMnAQEgBiFYIDajeDBT7zonm7zQ9psEjSou6/90+fTTQorNWMVUKhI2";
        OneKey asymmetricPublic = new OneKey(
                CBORObject.DecodeFromBytes(java.util.Base64.getDecoder().decode(keyStringPublic)));
		
        String clientKeyString = "pQEBAycgBiFYILan2jOypo2aquXu9dGULNpcpFG/p1DCmz5dtSDWE+AdI1gg57sTlm2NyGDkBiz0Iswa85MvPptw6RAyUiTcCMorJOs=";
        OneKey clientKey = new OneKey(
                CBORObject.DecodeFromBytes(java.util.Base64.getDecoder().decode(clientKeyString)));

        if (true) {

            // DLTS settings
            DtlsConnectorConfig.Builder builderClient = new DtlsConnectorConfig.Builder()
                    .setIdentity(clientKey.AsPrivateKey(), clientKey.AsPublicKey())
                    .setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
            builderClient.setClientOnly();

//            CertificateType[] certificateTypes = new CertificateType[1];
//            certificateTypes[0] = CertificateType.RAW_PUBLIC_KEY;
//            NewAdvancedCertificateVerifier verifier = new MyVerifier();
//            builderClient.setAdvancedCertificateVerifier(verifier);
//            builderClient.setTrustCertificateTypes(certificateTypes);

            // Use this to trust all RPKs
            org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier.Builder verifierBuilder = StaticNewAdvancedCertificateVerifier
                    .builder();
            verifierBuilder.setTrustAllRPKs();
            builderClient.setAdvancedCertificateVerifier(verifierBuilder.build());

            DTLSConnector connector = new DTLSConnector(builderClient.build());
            CoapEndpoint cep = new org.eclipse.californium.core.network.CoapEndpoint.Builder().setConnector(connector)
                    .setNetworkConfig(NetworkConfig.getStandard()).build();

            CoapClient client = new CoapClient();
            client.setEndpoint(cep);
            client.setURI(uri);


			CoapResponse response = null;
			try {
				response = client.get();
			} catch (ConnectorException | IOException e) {
				System.err.println("Got an error: " + e);
			}

			if (response!=null) {
				
				System.out.println(response.getCode());
				System.out.println(response.getOptions());
                if (args.length > 1) {
                    try (FileOutputStream out = new FileOutputStream(args[1])) {
						out.write(response.getPayload());
					} catch (IOException e) {
						e.printStackTrace();
					}
				} else {
					System.out.println(response.getResponseText());
					
					System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
					// access advanced API with access to more details through
					// .advanced()
					System.out.println(Utils.prettyPrint(response));
				}
			} else {
				System.out.println("No response received.");
			}
			client.shutdown();
		} else {
			// display help
			System.out.println("Californium (Cf) GET Client");
			System.out.println("(c) 2014, Institute for Pervasive Computing, ETH Zurich");
			System.out.println();
			System.out.println("Usage : " + TestClient.class.getSimpleName() + " URI [file]");
			System.out.println("  URI : The CoAP URI of the remote resource to GET");
			System.out.println("  file: optional filename to save the received payload");
		}
	}

}
