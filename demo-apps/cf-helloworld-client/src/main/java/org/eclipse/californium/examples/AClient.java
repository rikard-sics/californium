/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.IOException;
import java.net.InetAddress;

import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;

/**
 * Main starter class for jar execution.
 */
public class AClient {

	/**
	 * The IPv4 address of this host's multicast interface, as selected by the
	 * demo servers, or the loopback address if there is none.
	 */
	private static String defaultHost() {
		InetAddress address = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
		if (address == null) {
			address = InetAddress.getLoopbackAddress();
		}
		return address.getHostAddress();
	}

	public static void main(String[] args) throws IOException, ConnectorException, InterruptedException {

		if (args.length < 1) {
			System.out.println("Usage: AClient <command> [host] [port]");
			System.out.println("  host defaults to this host's multicast interface IPv4 address");
			System.out.println("  port defaults to 5683");
			System.exit(1);
		}

		String host = args.length >= 2 ? args[1] : defaultHost();
		int port = args.length >= 3 ? Integer.parseInt(args[2]) : 5683;
		String uri = "coap://" + host + ":" + port + "/";
		String uri_get = "get";
		String[] resource = new String[] { uri + uri_get };

		String content;
		int rounds = 1;

		switch (args[0]) {
			case "obs":
				System.out.println("OBSERVE");
				ObserveClient.main(uri + "obs");
				break;
			case "get":
				System.out.println("GET");
				GETClient.main(resource);
				break;
			case "post":
				System.out.println("POST");
				content = Integer.toString((int) (Math.random() * 50 + 1));
				POSTClient.main(uri + "obs", content);
				break;
			case "put":
				System.out.println("executing random put: " + rounds + " times");
				for (int i = 0; i < rounds; i++) {
					content = Integer.toString((int) (Math.random() * 50 + 1));
					PUTClient.main(uri + "obs", content);
				}
				break;
			case "put-mult":
				content = Integer.toString((int) (Math.random() * 50 + 1));
				PUTClient.main(uri + "mult", content);
				break;
			case "mult":
				System.out.println("MULT");
				MulticastObserveClient.main(uri + "mult");
				break;
			case "OSCORE-mult-1":
				System.out.println(uri + "OSCORE-mult");
				OSCOREMulticastObserveClient.main(uri + "OSCORE-mult", 1, true);
				break;
			case "OSCORE-mult-2":
				System.out.println(uri + "OSCORE-mult");
				OSCOREMulticastObserveClient.main(uri + "OSCORE-mult", 2,true);
				break;
			case "OSCORE-mult-3":
				System.out.println(uri + "OSCORE-mult");
				OSCOREMulticastObserveClient.main(uri + "OSCORE-mult", 3, true);
				break;
			case "OSCORE-obs-1":
				System.out.println(uri + "OSCORE-obs");
				OSCOREObserveClient.main(uri + "obs", 1000, 1);
				break;
			case "OSCORE-obs-2":
				System.out.println(uri + "OSCORE-obs");
				OSCOREObserveClient.main(uri + "obs", 1000, 2);
				break;
			case "OSCORE-obs-3":
				System.out.println(uri + "OSCORE-obs");
				OSCOREObserveClient.main(uri + "obs", 1000, 3);
				break;
			case "OSCORE-obs-put":
				System.out.println(uri + "OSCORE-obs-put");
				content = Integer.toString((int) (Math.random() * 50 + 1));
				OSCOREPutClient.main(uri + "obs", content);
				break;
			case "OSCORE-put-mult":
				content = Integer.toString((int) (Math.random() * 50 + 1));
				OSCOREPutClient.main(uri + "OSCORE-mult", content);
				break;
			case "mix":
				System.out.println("-----------[GET]-------------");
				GETClient.main(resource);

				System.out.println("-----------[POST]-------------");
				content = Integer.toString((int) (Math.random() * 50 + 1));
				POSTClient.main(uri, content);

				System.out.println("-----------[GET]-------------");
				GETClient.main(resource);
				break;
		}
		System.exit(-1);
	}
}
