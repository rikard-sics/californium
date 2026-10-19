package org.eclipse.californium.examples;

import java.io.FileWriter;
import java.io.IOException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.NtpUtil;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.MultiKey;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OSCOREObserveClient {

	/* --- OSCORE Security Context information (sender) --- */
	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HMAC_SHA_256;

	// Group OSCORE countersignature algorithm (EdDSA)
	private final static AlgorithmID algCountersign = AlgorithmID.EDDSA;

	// Encryption algorithm for Group mode
	private final static AlgorithmID algGroupEnc = AlgorithmID.AES_CCM_16_64_128;

	// Algorithm for key agreement
	private final static AlgorithmID algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

	// Master secret and salt from OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };

	private static final int REPLAY_WINDOW = 32;

	private final static byte[] gm_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F6D79736974652E6578616D706C652E636F6D026C67726F75706D616E6167657203781A636F6170733A2F2F646F6D61696E2E6578616D706C652E6F7267041AAB9B154F08A101A4010103272006215820CDE3EFD3BC3F99C9C9EE210415C6CBA55061B5046E963B8A58C9143A61166472");

	// Server
	private static byte[] server_id = new byte[] { 0x52 };
	private static byte[] server_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B");

	// Sender 1
	private final static byte[] sender_1_ID = new byte[] { 0x25 };
	private static byte[] sender_1_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
	private static byte[] sender_1_private_key_bytes = new byte[] { (byte) 0x64, (byte) 0x71, (byte) 0x4D, (byte) 0x41,
			(byte) 0xA2, (byte) 0x40, (byte) 0xB6, (byte) 0x1D, (byte) 0x8D, (byte) 0x82, (byte) 0x35, (byte) 0x02,
			(byte) 0x71, (byte) 0x7A, (byte) 0xB0, (byte) 0x88, (byte) 0xC9, (byte) 0xF4, (byte) 0xAF, (byte) 0x6F,
			(byte) 0xC9, (byte) 0x84, (byte) 0x45, (byte) 0x53, (byte) 0xE4, (byte) 0xAD, (byte) 0x4C, (byte) 0x42,
			(byte) 0xCC, (byte) 0x73, (byte) 0x52, (byte) 0x39 };

	// Sender 2
	private final static byte[] sender_2_ID = new byte[] { 0x77 };
	private static byte[] sender_2_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820105B8C6A8C88019BF0C354592934130BAA8007399CC2AC3BE845884613D5BA2E");
	private static byte[] sender_2_private_key_bytes = new byte[] { 0x7B, (byte) 0xF6, 0x2F, 0x76, 0x7E, (byte) 0xD1, (byte) 0xCF, 0x4C,
			0x60, (byte) 0x91, 0x1F, (byte) 0xC4, (byte) 0x9F, (byte) 0xDF, (byte) 0xCC, (byte) 0xB9,
			(byte) 0xBD, 0x47, (byte) 0xCC, 0x7E, (byte) 0x9F, (byte) 0xAF, 0x41, (byte) 0xCB, 0x66, 0x36,
			(byte) 0x9D, 0x5C, (byte) 0x85, 0x08, (byte) 0xB2, 0x39 };

	
	 private final static byte[] sender_3_ID = new byte[] { 0x33 };

	  private final static byte[] sender_3_public_key_bytes = StringUtil.hex2ByteArray(
	      "A501781B636F6170733A2F2F73656E646572332E6578616D706C652E636F6D026773656E6465723303781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582027259DED530940E179F7A47BDD6862880A8100B604C3D18449F84B94A0EEB9F3");

	  private static byte[] sender_3_private_key_bytes = new byte[] { (byte) 0xD0, (byte) 0x6C, (byte) 0x49, (byte) 0x70, (byte) 0x2E, (byte) 0x7F, (byte) 0x58, (byte) 0xD2, (byte) 0x21, (byte) 0x1B, (byte) 0xD2, (byte) 0x3F, (byte) 0x70, (byte) 0x9A, (byte) 0xA4, (byte) 0x16, (byte) 0x55, (byte) 0x19, (byte) 0x5B, (byte) 0x8D, (byte) 0x48, (byte) 0xEC, (byte) 0xB0, (byte) 0xA5, (byte) 0x10, (byte) 0xAC, (byte) 0x44, (byte) 0x81, (byte) 0xC7, (byte) 0x83, (byte) 0x19, (byte) 0x5B };

	private final static byte[] group_identifier = new byte[] { 0x44, 0x61, 0x6c }; // GID

	/* --- OSCORE Security Context information --- */

	static {
		CoapConfig.register();
		UdpConfig.register();
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(OSCOREObserveClient.class);

	private static int clientId = 1;

	private static class ObserveHandler implements CoapHandler {

		private static final int CSV_WRITE_THRESHOLD = 20;
		private int notificationCount = 0;
		private final int targetCount;
		private final java.util.List<long[]> timingRecords = new ArrayList<>();

		public ObserveHandler(int targetCount) {
			this.targetCount = targetCount;
		}

		public synchronized void waitForNotifications() {
			while (notificationCount < targetCount) {
				try {
					this.wait();
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					return;
				}
			}
		}

		@Override
		public void onLoad(CoapResponse response) {
			LOGGER.info("onLoad(): \n {}", Utils.prettyPrint(response));

			long clientTime = NtpUtil.now();
			try {
				int state = Integer.parseInt(response.getResponseText().trim());
				timingRecords.add(new long[]{ state, clientTime });
				LOGGER.info("[TIMING] client_{}  state={} clientTime={}", clientId, state, clientTime);

				if (state >= CSV_WRITE_THRESHOLD) {
					writeTimingCsv();
				}
			} catch (NumberFormatException e) {
				LOGGER.warn("[TIMING] Could not parse state from payload: {}", response.getResponseText());
			}

			synchronized (this) {
				notificationCount++;
				notifyAll();
			}
		}

		private void writeTimingCsv() {
			String fileName = "timing_client_" + clientId + ".csv";
			try (FileWriter writer = new FileWriter(fileName)) {
				writer.write("state,client_" + clientId + "\n");
				for (long[] record : timingRecords) {
					writer.write(record[0] + "," + record[1] + "\n");
				}
				LOGGER.info("[TIMING] Wrote {} records to {}", timingRecords.size(), fileName);
			} catch (IOException e) {
				LOGGER.error("[TIMING] Failed to write CSV: {}", e.getMessage());
			}
		}

		@Override
		public void onError() {
			LOGGER.error("Error receiving notification");
		}
	}

	private static void setupOscore(String requestURI, int sender) throws OSException {
		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		// Select client identity based on sender parameter
		byte[] sender_id;
		MultiKey sender_private_key;

		switch (sender) {
			case 1:
				sender_id = sender_1_ID;
				sender_private_key = new MultiKey(sender_1_public_key_bytes, sender_1_private_key_bytes);
				break;
			case 2:
				sender_id = sender_2_ID;
				sender_private_key = new MultiKey(sender_2_public_key_bytes, sender_2_private_key_bytes);
				break;
			case 3:
				sender_id = sender_3_ID;
				sender_private_key = new MultiKey(sender_3_public_key_bytes, sender_3_private_key_bytes);
				break;
			default:
				throw new IllegalArgumentException("Unknown sender ID: " + sender);
		}

		// Set up the OSCORE security context
		byte[] gmPublicKey = gm_public_key_bytes;
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
				algGroupEnc, algKeyAgreement, gmPublicKey);

		commonCtx.addSenderCtxCcs(sender_id, sender_private_key);
		commonCtx.addRecipientCtxCcs(server_id, REPLAY_WINDOW, new MultiKey(server_public_key_bytes));
		db.addContext(requestURI, commonCtx);
		LOGGER.info("Registering common context for URI: {}", requestURI);
		OSCoreCoapStackFactory.useAsDefault(db);
	}

	/**
	 * Creates an OSCORE-protected request.
	 */
	private static Request createRequest(Code code, String resourceUri) {
		LOGGER.info("Connecting to: {}", resourceUri);

		Request r = new Request(code);
		r.setConfirmable(true);
		r.setURI(resourceUri);
		r.getOptions().setOscore(Bytes.EMPTY);
		r.setObserve();

		return r;
	}

	public static void main(String requestURI, int timeout, int sender) {
		clientId = sender;
		NtpUtil.initialize();
		try {
			Configuration config = Configuration.getStandard();
			Configuration.setStandard(config);

			LOGGER.debug("Requesting {}", requestURI);
			try {
				setupOscore(requestURI, sender);
			} catch (OSException e) {
				LOGGER.error("Failed to set up OSCORE context", e);
				return;
			}

			CoapEndpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
			CoapClient client = new CoapClient();
			client.setEndpoint(endpoint);
			client.setURI(requestURI);

			Request observeRequest = createRequest(Code.GET, requestURI);

			ObserveHandler handler = new ObserveHandler(40);
			CoapObserveRelation relation = client.observe(observeRequest, handler);

			handler.waitForNotifications();

			// Deregister observe
			Request deregisterRequest = createRequest(Code.GET, requestURI);
			deregisterRequest.getOptions().setObserve(1); // Observe=1 means cancel
			deregisterRequest.send();
		} catch (Exception e) {
			LOGGER.error("Error in observe client", e);
		}
	}
}
