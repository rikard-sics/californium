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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add endpoints for all IP addresses
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP parameter
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.observe.GroupObservationsInfo;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.ProtocolScheduledExecutorService;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.MulticastObservableResource;
import org.eclipse.californium.oscore.NtpUtil;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreResource;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.MultiKey;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;


public class OSCOREAHelloWorldServer extends CoapServer {

	static {
		CoapConfig.register();
		UdpConfig.register();
	}

	/**
	 * Add individual endpoint listening on default CoAP address,
	 * with multicast send/receive support via UdpMulticastConnector.
	 */
	private void addEndpoint() {
		int port = Configuration.getStandard().get(CoapConfig.COAP_PORT);
		Configuration config = Configuration.getStandard();

		Inet4Address ipv4 = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
		NetworkInterface networkInterface = NetworkInterfacesUtil.getMulticastInterface();
		if (ipv4 != null && networkInterface != null) {
			InetSocketAddress physicalSocket = new InetSocketAddress(ipv4, port);
			UDPConnector udpConnector = new UDPConnector(physicalSocket, config);
			udpConnector.setReuseAddress(true);

			// Attach a multicast receiver so the UDPConnector's send socket
			// is bound to the correct network interface for outgoing multicast.
			UdpMulticastConnector.Builder mcBuilder = new UdpMulticastConnector.Builder()
					.setLocalAddress(multicastIP, GRP_PORT)
					.setMulticastReceiver(true);
			UdpMulticastConnector multicastConnector = mcBuilder.build();
			udpConnector.addMulticastReceiver(multicastConnector);

			CoapEndpoint coapEndpoint = new CoapEndpoint.Builder()
					.setConfiguration(config)
					.setConnector(udpConnector)
					.build();
			addEndpoint(coapEndpoint);
			System.out.println("Added endpoint with multicast support: " + physicalSocket);
			System.out.println("Multicast group: " + multicastIP + ":" + GRP_PORT + " on " + networkInterface.getDisplayName());
		}
		final ProtocolScheduledExecutorService executorService = ExecutorsUtil
				.newSingleThreadedProtocolExecutor(new DaemonThreadFactory(":CoapEndpoint")); //$NON-NLS-1$
		this.setExecutor(executorService, isRunning());
	}

	/*
	 * Constructor for a new Hello-World server. Here, the resources of the
	 * server are initialized.
	 */
	public OSCOREAHelloWorldServer() throws SocketException {	    
	    GroupObservationsInfo.init();
	}

	/**
	 * Controls whether or not the receiver will reply to incoming multicast
	 * non-confirmable requests.
	 * 
	 * The receiver will always reply to confirmable requests (can be used with
	 * unicast).
	 * 
	 */
	static final boolean replyToNonConfirmable = true;

	/**
	 * Whether to use OSCORE or not.
	 */
	static final boolean useOSCORE = true;

	/**
	 * Multicast address to listen to.
	 */
	static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	/**
	 * Port for multicast notifications.
	 */
	static final int GRP_PORT = 61616;

	/**
	 * Port to listen to.
	 */
	static final int listenPort = CoAP.DEFAULT_COAP_PORT;

	/* --- OSCORE Security Context information (sender) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature (EdDSA)
	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;

	// Encryption algorithm for when using Group mode
	private final static AlgorithmID algGroupEnc = AlgorithmID.AES_CCM_16_64_128;

	// Algorithm for key agreement
	private final static AlgorithmID algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };

	private static final int REPLAY_WINDOW = 32;

	/* --- Unicast leg: RFC 8613 OSCORE, one pairwise Security Context per client ---
	 * draft-ietf-core-observe-multicast-notifications-15 §9: the original registration
	 * request and the informative response MUST be protected; §10 uses pairwise OSCORE.
	 * Sender IDs are distinct from the Group OSCORE ones (as 0x01/0x02 vs 0x05 in §10):
	 * client N (OSCORE-mult-N) = 0x0N, server = 0x00. Master Secret: the group one with
	 * its last byte set to 0x10 + N, so each pairwise context has its own keys.
	 * Master Salt: as the group. No ID Context. AES-CCM-16-64-128, HKDF SHA-256. */
	private final static byte[] PAIRWISE_SERVER_ID = new byte[] { 0x00 };

	private static byte[] pairwiseMasterSecret(int client) {
		byte[] ms = master_secret.clone();
		ms[ms.length - 1] = (byte) (0x10 + client);
		return ms;
	}

	private final static byte[] gm_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F6D79736974652E6578616D706C652E636F6D026C67726F75706D616E6167657203781A636F6170733A2F2F646F6D61696E2E6578616D706C652E6F7267041AAB9B154F08A101A4010103272006215820CDE3EFD3BC3F99C9C9EE210415C6CBA55061B5046E963B8A58C9143A61166472");

	private static byte[] server_id = new byte[] { 0x52 };
	private static byte[] server_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B");
	private static byte[] server_private_key_bytes = new byte[] { (byte) 0x85, 0x7E, (byte) 0xB6, 0x1D, 0x3F, 0x6D, 0x70,
			(byte) 0xA2, 0x78, (byte) 0xA3, 0x67, 0x40, (byte) 0xD1, 0x32, (byte) 0xC0, (byte) 0x99, (byte) 0xF6, 0x28,
			(byte) 0x80, (byte) 0xED, 0x49, 0x7E, 0x27, (byte) 0xBD, (byte) 0xFD, 0x46, (byte) 0x85, (byte) 0xFA, 0x1A,
			0x30, 0x4F, 0x26 };
	private static MultiKey server_private_key;
	private static MultiKey server_public_key;

	private final static byte[] sender_1_ID = new byte[] { 0x25 };
	private static byte[] sender_1_public_key_bytes = StringUtil.hex2ByteArray(
		    "A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
	private static MultiKey sender_1_public_key;

	private final static byte[] sender_2_ID = new byte[] { 0x77 };
	private static byte[] sender_2_public_key_bytes = StringUtil.hex2ByteArray(
		    "A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820105B8C6A8C88019BF0C354592934130BAA8007399CC2AC3BE845884613D5BA2E");
	private static MultiKey sender_2_public_key;

	
	private static MultiKey sender_3_public_key;
	private final static byte[] sender_3_ID = new byte[] { 0x33 };

	private final static byte[] sender_3_public_key_bytes = StringUtil.hex2ByteArray(
	    "A501781B636F6170733A2F2F73656E646572332E6578616D706C652E636F6D026773656E6465723303781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582027259DED530940E179F7A47BDD6862880A8100B604C3D18449F84B94A0EEB9F3");
	
	private final static byte[] group_identifier = new byte[] { 0x44, 0x61, 0x6c }; // GID
	/* --- OSCORE Security Context information --- */

	/**
	 * Main method
	 * 
	 * @param args command line arguments
	 * @throws Exception on setup or message processing failure
	 */
	public static void main(String[] args) throws Exception {
		OSCOREAHelloWorldServer server = new OSCOREAHelloWorldServer();

		Resource resource = server.getRoot();
		InetSocketAddress address = new InetSocketAddress(NetworkInterfacesUtil.getMulticastInterfaceIpv4(), listenPort);
		server.OSCORESetup(address);
		server.addEndpoint();

		int GRP_PORT = 61616;
		InetSocketAddress multicastAddress = new InetSocketAddress(CoAP.MULTICAST_IPV4, GRP_PORT);

		Endpoint endpoint = server.getEndpoint(listenPort);
		
		//resource.add(new MulticastObservableResource("mult", true, server.getMessageDeliverer()));
		resource.add(new ObservableResource());
		resource.add(new MulticastObservableResource("OSCORE-mult", true, db, multicastAddress));
		//resource.add(new MulticastObservableResource("OSCORE-mult", true, multicastAddress));

		server.start();

		System.out.println("==================");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Respond to non-confirmable messages: " + replyToNonConfirmable);
		System.out.println("Unicast IP: " + endpoint.getAddress().getHostString());
		System.out.println("Incoming port: " + endpoint.getAddress().getPort());
		System.out.print("CoAP resources: ");
		for (Resource res : server.getRoot().getChildren()) {
			System.out.print(res.getURI() + " ");
		}
		System.out.println("");
		System.out.println("==================");

		Thread.currentThread().join();
	}

	private void OSCORESetup(InetSocketAddress address) throws OSException {
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		// Set sender & receiver keys for countersignatures
		server_private_key = new MultiKey(server_public_key_bytes, server_private_key_bytes);
		server_public_key = new MultiKey(server_public_key_bytes); 
		sender_1_public_key = new MultiKey(sender_1_public_key_bytes);
		sender_2_public_key = new MultiKey(sender_2_public_key_bytes);
		sender_3_public_key = new MultiKey(sender_3_public_key_bytes);


		if (useOSCORE) {
			byte[] gmPublicKey = gm_public_key_bytes;
			GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
					algGroupEnc, algKeyAgreement, gmPublicKey);

			commonCtx.addSenderCtxCcs(server_id, server_private_key);
			commonCtx.addRecipientCtxCcs(sender_1_ID, REPLAY_WINDOW, sender_1_public_key);
			commonCtx.addRecipientCtxCcs(sender_2_ID, REPLAY_WINDOW, sender_2_public_key);
			commonCtx.addRecipientCtxCcs(sender_3_ID, REPLAY_WINDOW, sender_3_public_key);
			
			// Add server's own ID as recipient for phantom request self-decryption
			commonCtx.addRecipientCtxCcs(server_id, REPLAY_WINDOW, server_public_key);

			commonCtx.setResponsesIncludePartialIV(false);
			commonCtx.setPairwiseModeResponses(false);

			// Unicast leg: one pairwise RFC 8613 context per client (see PAIRWISE_SERVER_ID)
			for (int client = 1; client <= 3; client++) {
				db.addContext(new OSCoreCtx(pairwiseMasterSecret(client), false, alg, PAIRWISE_SERVER_ID,
						new byte[] { (byte) client }, kdf, REPLAY_WINDOW, master_salt, null, 4096));
			}

			db.addContext("OSCORE-mult", commonCtx);
			db.addContext("coap://" + address.getHostString() + ":" + address.getPort() + "/OSCORE-mult", commonCtx);

			GroupObservationsInfo.getInstance().setSenderId(server_id);
			OSCoreCoapStackFactory.useAsDefault(db);
		}
	}

	private static class ObservableResource extends OSCoreResource {

		public Integer content = 1;
		private Timer timer = new Timer();

		private static final int CSV_WRITE_THRESHOLD = 36;
		private static final String CSV_FILE = "timing_results.csv";
		private final List<long[]> timingRecords = new ArrayList<>();
		
		public ObservableResource() {
			super("obs", true);

			this.setObservable(true);
			this.getAttributes().setObservable();
			getAttributes().setTitle("pub-sub Resource");
			setObserveType(Type.NON);

			timer.schedule(new UpdateTask(), 20000, 3000);
		}
		@Override
		public void changed() {
			long serverTime = NtpUtil.now();
			timingRecords.add(new long[]{ content, serverTime });

			if (content >= CSV_WRITE_THRESHOLD) {
				writeTimingCsv();
			}

			super.changed();
		}
		
		private void writeTimingCsv() {
			try (FileWriter writer = new FileWriter(CSV_FILE)) {
				writer.write("state,server_time,client_1,client_2,client_3\n");
				for (long[] record : timingRecords) {
					writer.write(record[0] + "," + record[1] + ",,,\n");
				}
			} catch (IOException e) {
			}
		}


		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, this.content.toString());
		}

		@Override
		public void removeObserveRelation(ObserveRelation relation) {
			super.removeObserveRelation(relation);
		
		}

		class UpdateTask extends TimerTask {
			@Override
			public void run() {
				content++;
				changed();
			}
		}
	}
	
}
