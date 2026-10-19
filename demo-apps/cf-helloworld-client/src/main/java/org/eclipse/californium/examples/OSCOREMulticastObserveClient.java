package org.eclipse.californium.examples;

import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.option.OptionRegistry;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.observe.ObservationInfo;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.CoapOSException;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.NtpUtil;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.OscoreOptionDecoder;
import org.eclipse.californium.oscore.PhantomRequestValues;
import org.eclipse.californium.oscore.RequestDecryptor;
import org.eclipse.californium.oscore.ResponseDecryptor;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.GroupRecipientCtx;
import org.eclipse.californium.oscore.group.MultiKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class OSCOREMulticastObserveClient {
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

	// test vector OSCORE draft Appendix C.1.1
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

	// The DB maps a URI to one context per host. The pairwise context is mapped while the
	// unicast registration runs; the group context is mapped back before the client-injected
	// phantom request, so the multicast token is bound to the Group OSCORE context.
	private static GroupCtx groupCtx;
	private static String groupCtxUri;

	private static byte[] pairwiseMasterSecret(int client) {
		byte[] ms = master_secret.clone();
		ms[ms.length - 1] = (byte) (0x10 + client);
		return ms;
	}

	private final static byte[] gm_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F6D79736974652E6578616D706C652E636F6D026C67726F75706D616E6167657203781A636F6170733A2F2F646F6D61696E2E6578616D706C652E6F7267041AAB9B154F08A101A4010103272006215820CDE3EFD3BC3F99C9C9EE210415C6CBA55061B5046E963B8A58C9143A61166472");
	
	// server 1
	private static byte[] server_id = new byte[] { 0x52 };
	private static byte[] server_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B");
	// Sender 1
	private final static byte[] sender_1_ID = new byte[] { 0x25 };

	private final static byte[] sender_1_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
	private static byte[] sender_1_private_key_bytes = new byte[] { (byte) 0x64, (byte) 0x71, (byte) 0x4D, (byte) 0x41,
			(byte) 0xA2, (byte) 0x40, (byte) 0xB6, (byte) 0x1D, (byte) 0x8D, (byte) 0x82, (byte) 0x35, (byte) 0x02,
			(byte) 0x71, (byte) 0x7A, (byte) 0xB0, (byte) 0x88, (byte) 0xC9, (byte) 0xF4, (byte) 0xAF, (byte) 0x6F,
			(byte) 0xC9, (byte) 0x84, (byte) 0x45, (byte) 0x53, (byte) 0xE4, (byte) 0xAD, (byte) 0x4C, (byte) 0x42,
			(byte) 0xCC, (byte) 0x73, (byte) 0x52, (byte) 0x39 
    };
	
	// Sender 2
  private final static byte[] sender_2_ID = new byte[] { 0x77 };
  private final static byte[] sender_2_public_key_bytes= StringUtil.hex2ByteArray(
      "A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820105B8C6A8C88019BF0C354592934130BAA8007399CC2AC3BE845884613D5BA2E");
  private static byte[] sender_2_private_key_bytes = new byte[] { 0x7B, (byte) 0xF6, 0x2F, 0x76, 0x7E, (byte) 0xD1, (byte) 0xCF, 0x4C,
      0x60, (byte) 0x91, 0x1F, (byte) 0xC4, (byte) 0x9F, (byte) 0xDF, (byte) 0xCC, (byte) 0xB9,
      (byte) 0xBD, 0x47, (byte) 0xCC, 0x7E, (byte) 0x9F, (byte) 0xAF, 0x41, (byte) 0xCB, 0x66, 0x36,
      (byte) 0x9D, 0x5C, (byte) 0x85, 0x08, (byte) 0xB2, 0x39 
    };
  
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
  private static final Logger LOGGER = LoggerFactory.getLogger(OSCOREMulticastObserveClient.class);

  private static UDPConnector udpConnector;
  private static UdpMulticastConnector multicastReceiver;
  private static CoapEndpoint endpoint;
  private static CoapClient multicastClient;
  private static boolean receiverReady = false;
  private static boolean useOscore = false;
  private static int clientId = 1;

  private static class MulticastObserveHandler implements CoapHandler {

    private static final int CSV_WRITE_THRESHOLD = 20;
    private int notificationCount = 0;
    private final int targetCount;
    /* The original Observe registration request of this client. Kept because the
     * informative response may carry no 'ph_req': the phantom request is then rebuilt
     * from the transport-independent information of this request (Section 5.2, step 2). */
    private final Request registrationRequest;
    private final java.util.List<long[]> timingRecords = new ArrayList<>();

    public MulticastObserveHandler(int targetCount, Request registrationRequest) {
      this.targetCount = targetCount;
      this.registrationRequest = registrationRequest;
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
    /**
     * Decrypts and verifies the phantom registration request using RequestDecryptor,
     * similar to how ObjectSecurityLayer.receiveRequest handles incoming OSCORE requests.
     * A successful return means the request is verified; null means verification failed.
     */
    private Request decrypt(Request request) {
		OSCoreCtx ctx = null;
		try {
			OscoreOptionDecoder optionDecoder = new OscoreOptionDecoder(request.getOptions().getOscore());
			byte[] rid = optionDecoder.getKid();
			byte[] idContext = optionDecoder.getIdContext();
			ctx = db.getContext(rid, idContext);
		} catch (CoapOSException e) {
			LOGGER.error("Failed to retrieve OSCORE context for phantom request: {}", e.getMessage());
			return null;
		}

		if (ctx == null) {
			LOGGER.error("No OSCORE context found for phantom request");
			return null;
		}

		try {
			// Mark as phantom request so that the replay check is skipped (Section 9.3.1).
			// This exception applies only here, to the client's own verification
			// of the ph_req it received; it must not apply to the server's
			// processing of an incoming phantom request.
			request.setIsPhantomRequest(true);
			request = RequestDecryptor.decrypt(db, request, ctx, true);
			request.getOptions().setOscore(Bytes.EMPTY);
			return request;
		} catch (CoapOSException e) {
			LOGGER.error("Phantom request decryption/verification failed: {}", e.getMessage());
			return null;
		}
    }
    @Override
    public void onLoad(CoapResponse response) {
      LOGGER.info("onLoad(): \n {}", Utils.prettyPrint(response));

      if (response.getOptions().isContentFormat(MediaTypeRegistry.APPLICATION_INFORMATIVE_RESPONSE_CBOR)) {
        response.advanced().cancel();
    	LOGGER.info("Got APPLICATION_INFORMATIVE_RESPONSE_CBOR (ObservationInfo)");
        ObservationInfo info = ObservationInfo.fromCbor(response.getPayload());

        InetSocketAddress groupSock = info.getTpInfo().getTpiClient().toSocketAddress();
        InetAddress groupAddr = groupSock.getAddress();
        int groupPort = groupSock.getPort();
        Token multicastToken = info.getToken();

        byte[] phantomRequestBytes = info.getPhReq();
        int phantomSeqNr = 0;
        byte[] phantomOscoreOption = null;
        Request finalPhantomRequest = null;

        if (useOscore) {
          // OSCORE mode: ph_req MUST be present (RFC Section 9.3.1)
          if (phantomRequestBytes == null || phantomRequestBytes.length == 0) {
            LOGGER.error("Malformed informative response: missing required 'ph_req' parameter");
            return;
          }

          // ph_req is transport-independent information (Section 4.2.2): code byte
          // followed by options and optional payload. Parse it the same way as
          // last_notif below, using tpi_token (Section 5.2 step 2) as the Token.
          int phantomCode = phantomRequestBytes[0] & 0xFF;
          byte[] phantomOptionsAndPayload = new byte[phantomRequestBytes.length - 1];
          System.arraycopy(phantomRequestBytes, 1, phantomOptionsAndPayload, 0, phantomOptionsAndPayload.length);
          Request phantomRequest = new Request(Code.valueOf(phantomCode));
          phantomRequest.setToken(multicastToken);
          // ph_req was sent by the server: as for any received message, the external_aad
          // uses the OSCORE option carried in it (Group OSCORE, Section 3.4)
          phantomRequest.setSourceContext(response.advanced().getSourceContext());
          DataParser phantomParser = new UdpDataParser(true, (OptionRegistry) null);
          phantomParser.parseOptionsAndPayload(new DatagramReader(phantomOptionsAndPayload), phantomRequest);

          phantomOscoreOption = phantomRequest.getOptions().getOscore();

          Request decryptedPhantomRequest = decrypt(phantomRequest);
          if (decryptedPhantomRequest == null) {
            LOGGER.error("Phantom request verification failed: decryption or signature check failed");
            return;
          }
          LOGGER.info("Phantom request verified successfully");
          finalPhantomRequest = decryptedPhantomRequest;

          try {
            OscoreOptionDecoder phantomOptionDecoder = new OscoreOptionDecoder(phantomOscoreOption);
            byte[] phantomKid = phantomOptionDecoder.getKid();
            byte[] phantomPiv = phantomOptionDecoder.getPartialIV();
            byte[] phantomKidContext = phantomOptionDecoder.getIdContext();
            phantomSeqNr = phantomOptionDecoder.getSequenceNumber();

            OSCoreCtx oscoreCtx = db.getContext(phantomKid, phantomKidContext);
            if (oscoreCtx instanceof GroupRecipientCtx) {
              db.addPhantomRequestValues(multicastToken,
                  new PhantomRequestValues(phantomKid, phantomPiv, phantomKidContext));
              LOGGER.info("Stored phantom request values for token {} - kid: {}, piv: {}, kidContext: {}",
                  multicastToken.getAsString(),
                  StringUtil.byteArray2Hex(phantomKid),
                  StringUtil.byteArray2Hex(phantomPiv),
                  StringUtil.byteArray2Hex(phantomKidContext));
            } else {
              LOGGER.error("Could not find GroupRecipientCtx for phantom request kid");
              return;
            }
          } catch (CoapOSException e) {
            LOGGER.error("Failed to parse phantom request OSCORE option: {}", e.getMessage());
            return;
          }
        } else {
          // Non-OSCORE mode: ph_req is optional, just log if present
          if (phantomRequestBytes != null && phantomRequestBytes.length > 0) {
            UdpDataParser parser = new UdpDataParser();
            Message mess = parser.parseMessage(phantomRequestBytes);
            if (mess instanceof Request) {
              LOGGER.info("Phantom request parsed successfully: {}", mess);
              finalPhantomRequest = (Request) mess;
              finalPhantomRequest.setToken(multicastToken);
            } else {
              LOGGER.warn("Failed to parse phantom request from informative response");
            }
          }
        }

        LOGGER.info("Requested URI: {}", info.getTpInfo().getTpiServer().toString());
        LOGGER.info("Multicast group: {} : {}", groupAddr, groupPort);
        LOGGER.info("Token: {}", multicastToken.getAsString());

        byte[] lastNotifBytes = info.getLastNotifBytes();
        if (lastNotifBytes != null && lastNotifBytes.length > 0) {
          int notifCode = lastNotifBytes[0] & 0xFF;
          byte[] notifOptionsAndPayload = new byte[lastNotifBytes.length - 1];
          System.arraycopy(lastNotifBytes, 1, notifOptionsAndPayload, 0, notifOptionsAndPayload.length);
          Response lastNotif = new Response(ResponseCode.valueOf(notifCode));
          lastNotif.setToken(multicastToken);
          DataParser notifParser = new UdpDataParser(true, (OptionRegistry) null);
          notifParser.parseOptionsAndPayload(
              new DatagramReader(notifOptionsAndPayload),
              lastNotif);

          if (useOscore) {
            lastNotif.setSourceContext(new AddressEndpointContext(groupSock));
            try {
              OscoreOptionDecoder phantomDec = new OscoreOptionDecoder(phantomOscoreOption);
              byte[] senderKid = phantomDec.getKid();
              byte[] kidContext = phantomDec.getIdContext();
              OSCoreCtx recipientCtx = db.getContext(senderKid, kidContext);
              if (recipientCtx != null) {
                db.addContext(multicastToken, recipientCtx);
              }
              Response decryptedNotif = ResponseDecryptor.decrypt(db, lastNotif, phantomSeqNr);
              LOGGER.info("last_notif decrypted - code: {}, payload: {}",
                  decryptedNotif.getCode(), decryptedNotif.getPayloadString());
              LOGGER.info("last_notif: \n {}", Utils.prettyPrint(decryptedNotif));
            } catch (OSException e) {
              LOGGER.error("Failed to decrypt last_notif: {}", e.getMessage());
            }
          } else {
            LOGGER.info("last_notif - code: {}, payload: {}", lastNotif.getCode(), lastNotif.getPayloadString());
            LOGGER.info("last_notif: \n {}", Utils.prettyPrint(lastNotif));
          }
        } else {
          LOGGER.info("No last_notif in informative response");
        }

        if (!receiverReady) {
          try {
            LOGGER.info("Setting up multicast receiver...");
            setupMulticastReceiverOnce(groupAddr, groupPort, Configuration.createStandardWithoutFile(), multicastToken,
                info.getTpInfo().getTpiServer().toSocketAddress());
            LOGGER.info("Multicast receiver activated.");

            if (finalPhantomRequest == null) {
              // No 'ph_req' in the informative response: rebuild the phantom request from the
              // transport-independent information of the original Observe registration request
              // (Section 5.2, step 2, second bullet).
              if (registrationRequest == null) {
                LOGGER.error("No original registration request available to rebuild the phantom request");
                return;
              }
              finalPhantomRequest = createPhantomRequest(registrationRequest, multicastToken,
                  info.getTpInfo().getTpiServer().toString(),
                  info.getTpInfo().getTpiServer().toSocketAddress());
              LOGGER.info("Created PhantomRequest with token: {}", multicastToken);
            } else {
              finalPhantomRequest.setDestinationContext(new AddressEndpointContext(new InetSocketAddress(groupAddr, groupPort)));
              finalPhantomRequest.setClientInjection(true);

              String fullUri = info.getTpInfo().getTpiServer().toString();
              String path = finalPhantomRequest.getOptions().getUriPathString();
              if (path != null && !path.isEmpty()) {
                  if (!fullUri.endsWith("/")) fullUri += "/";
                  fullUri += path;
              }
              String query = finalPhantomRequest.getOptions().getUriQueryString();
              if (query != null && !query.isEmpty()) {
                  fullUri += "?" + query;
              }
              finalPhantomRequest.setURI(fullUri);
              finalPhantomRequest.setType(Type.NON);
              finalPhantomRequest.setObserve();

              if (useOscore && phantomOscoreOption != null) {
                  finalPhantomRequest.getOptions().setOscore(phantomOscoreOption);
              }

              LOGGER.info("Using rebuilt PhantomRequest with token: {} URI: {}", multicastToken, fullUri);
            }

            if (useOscore) {
              // Unicast registration is complete: bind the server URI to the group context
              // again, so the phantom request / multicast token uses Group OSCORE (§9.3.2).
              try {
                db.addContext(groupCtxUri, groupCtx);
              } catch (OSException e) {
                LOGGER.error("Failed to rebind the group context: {}", e.getMessage());
              }
            }
            multicastClient.observe(finalPhantomRequest, this);
            LOGGER.info("Registered phantom observe relation.");

            receiverReady = true;
          } catch (IOException e) {
            LOGGER.error("Failed to activate multicast receiver", e);
          }
        } else {
          LOGGER.info("Multicast receiver already active");
        }

        return;
      }

      // Section 5.4: Detect cancellation — 5.03 with no payload and no Observe option
      if (response.getCode() == ResponseCode.SERVICE_UNAVAILABLE
          && !response.getOptions().hasObserve()
          && (response.getPayload() == null || response.getPayload().length == 0)) {
        LOGGER.info("Received group observation cancellation (5.03, no payload, no Observe)");
        if (multicastClient != null) {
          multicastClient.shutdown();
        }
        receiverReady = false;
        synchronized (this) {
          notificationCount = targetCount; // unblock waitForNotifications
          notifyAll();
        }
        return;
      }

      // Otherwise it's a normal notification payload
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
      LOGGER.error("Error receiving multicast notification");
    }
  }
  private static void setupOscore(int sender, String contextUri) throws OSException {
	// Install cryptographic providers
			Provider EdDSA = new EdDSASecurityProvider();
			Security.insertProviderAt(EdDSA, 1);
			// InstallCryptoProviders.generateCounterSignKey();

    	    // Select client identity based on sender parameter
	    byte[] sender_id;
	    MultiKey sender_private_key;

	    switch (sender) {
	        case 1: // sender_1 identity (0x52)
	            sender_id = sender_1_ID;
	            sender_private_key = new MultiKey(sender_1_public_key_bytes, sender_1_private_key_bytes);
	            break;
	        case 2: // sender_2 identity (0x77)
	            sender_id = sender_2_ID;
	            sender_private_key = new MultiKey(sender_2_public_key_bytes, sender_2_private_key_bytes);
	            break;
	        case 3: // sender_2 identity (0x33)
	            sender_id = sender_3_ID;
	            sender_private_key = new MultiKey(sender_3_public_key_bytes, sender_3_private_key_bytes);
	            break;
	        default:
	            throw new IllegalArgumentException("Unknown sender ID: " + sender);
	    }

			// If OSCORE is being used set the context information

				byte[] gmPublicKey = gm_public_key_bytes;
				GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
						algGroupEnc, algKeyAgreement, gmPublicKey);

				commonCtx.addSenderCtxCcs(sender_id, sender_private_key);
				commonCtx.addRecipientCtxCcs(server_id, REPLAY_WINDOW, new MultiKey(server_public_key_bytes));
				db.addContext(contextUri, commonCtx);

				// Unicast leg: register the pairwise RFC 8613 context under the same URI, after
				// the group context, so it protects the registration request. The group
				// recipient context (server 0x52) stays in the DB for ph_req and notifications.
				OSCoreCtx pairwiseCtx = new OSCoreCtx(pairwiseMasterSecret(sender), true, alg,
						new byte[] { (byte) sender }, PAIRWISE_SERVER_ID, kdf, REPLAY_WINDOW, master_salt, null, 4096);
				db.addContext(contextUri, pairwiseCtx);
				groupCtx = commonCtx;
				groupCtxUri = contextUri;

				OSCoreCoapStackFactory.useAsDefault(db);				

}
  private static Request createRequest(Code code, String resourceUri) {
      System.out.println("Connecting to: " + resourceUri);

      Request r = new Request(code);
      r.setConfirmable(true);
      r.setURI(resourceUri);
      if (useOscore) {
        // draft-15 §9: the original registration request MUST be protected (RFC 8613 OSCORE)
        r.getOptions().setOscore(Bytes.EMPTY);
      }
      r.setObserve();

      // Section 5.1: Observation request MUST NOT have link-local source or destination addresses
      InetAddress destAddr = r.getDestinationContext() != null
              ? r.getDestinationContext().getPeerAddress().getAddress() : null;
      if (destAddr != null && destAddr.isLinkLocalAddress()) {
          throw new IllegalArgumentException(
                  "Observation request destination " + destAddr.getHostAddress()
                  + " is link-local (RFC Section 5.1)");
      }

      return r;
  }
  /**
   * Creates a phantom request to register an observe relation for receiving multicast
   * notifications, rebuilt from the client's own original Observe registration request.
   * <p>
   * draft-ietf-core-observe-multicast-notifications-15 Section 5.2, step 2, second bullet:
   * "If the 'ph_req' parameter is not present in the informative response, the client uses
   * the transport-independent information from its original Observe registration request."
   * The rebuilt request therefore carries the same REST code and the same options as
   * {@code registrationRequest}, except that the Observe option is 0 (this is a new
   * registration). Like the original registration request it is addressed to the server, not
   * to the multicast group: the group address is where the notifications arrive, and the
   * phantom request is only registered locally. The destination is the one of the original
   * registration request, with the default CoAP port 5683 when that one carries no port. The
   * URI is assembled exactly as in the 'ph_req' case: the requested URI, plus the Uri-Path
   * and Uri-Query options carried by the original request.
   */
  private static Request createPhantomRequest(Request registrationRequest, Token multicastToken,
      String requestedURI, InetSocketAddress serverAddress) {
    Request phantomRequest = new Request(registrationRequest.getCode());
    phantomRequest.setOptions(registrationRequest.getOptions());
    phantomRequest.setToken(multicastToken);
    InetSocketAddress destination = serverAddress;
    if (destination == null || destination.getPort() <= 0) {
      // No port on the server address: apply the default CoAP port (RFC 7252 §4.1).
      destination = new InetSocketAddress(destination == null ? null : destination.getAddress(),
          CoAP.DEFAULT_COAP_PORT);
    }
    phantomRequest.setDestinationContext(new AddressEndpointContext(destination));
    phantomRequest.setClientInjection(true);
    phantomRequest.setType(Type.NON);

    String fullUri = requestedURI;
    String path = phantomRequest.getOptions().getUriPathString();
    if (path != null && !path.isEmpty()) {
        if (!fullUri.endsWith("/")) fullUri += "/";
        fullUri += path;
    }
    String query = phantomRequest.getOptions().getUriQueryString();
    if (query != null && !query.isEmpty()) {
        fullUri += "?" + query;
    }
    phantomRequest.setURI(fullUri);
    // A registration, like the original request: Observe = 0.
    phantomRequest.setObserve();

    LOGGER.debug("Created phantom request: {}", phantomRequest);
    LOGGER.info("Rebuilt PhantomRequest from the original registration request, URI: {}", fullUri);
    return phantomRequest;
  }

  public static void setupMulticastReceiverOnce(InetAddress groupAddr, int port, Configuration config, Token multicastToken,
      InetSocketAddress srvAddr) throws IOException {
    // Join the group on the interface that reaches the server rather than on a
    // globally selected one, exactly as the unprotected client does: the multicast
    // traffic of a server which is reached over loopback leaves through the loopback
    // interface, so a receiver joined on a physical interface never sees it. If
    // srvAddr is not an address of this host, the previous global selection is used
    // unchanged.
    NetworkInterface ni = NetworkInterfacesUtil.getNetworkInterface(srvAddr.getAddress());
    Inet4Address ipv4 = null;
    if (ni != null && srvAddr.getAddress() instanceof Inet4Address) {
      ipv4 = (Inet4Address) srvAddr.getAddress();
    }
    if (ni == null) {
      ni = NetworkInterfacesUtil.getMulticastInterface();
      ipv4 = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
    }
    if (ni == null) {
      throw new IOException("No multicast network interface found");
    }

    if (ipv4 == null) {
      throw new IOException("No IPv4 address found on multicast interface " + ni.getDisplayName());
    }

    InetSocketAddress bind = new InetSocketAddress(ipv4, 0);
    udpConnector = new UDPConnector(bind, config);
    udpConnector.setReuseAddress(true);
    LOGGER.info("Binding UDPConnector to {} (ephemeral port) on {}", ipv4, ni.getDisplayName());
    
    UdpMulticastConnector.Builder mcBuilder = new UdpMulticastConnector.Builder()
        .setConfiguration(config)
        .setMulticastReceiver(true)
        .setLocalAddress(groupAddr, port)
        .addMulticastGroup(groupAddr, ni);
    
    multicastReceiver = mcBuilder.build();

    try {
      multicastReceiver.start();
      multicastReceiver.setLoopbackMode(true);
      LOGGER.info("Multicast receiver started on {} port {}", groupAddr, port);
    } catch (java.net.BindException ex) {
      LOGGER.warn("Bind to multicast address failed, retrying with port only: {}", ex.getMessage());
      mcBuilder = new UdpMulticastConnector.Builder()
          .setConfiguration(config)
          .setMulticastReceiver(true)
          .setLocalPort(port)
          .addMulticastGroup(groupAddr, ni);
      multicastReceiver = mcBuilder.build();
      multicastReceiver.setLoopbackMode(true);
      multicastReceiver.start();
    }

    udpConnector.addMulticastReceiver(multicastReceiver);

    endpoint = new CoapEndpoint.Builder()
        .setConfiguration(config)
        .setConnector(udpConnector)
        .setEndpointContextMatcher(new GroupObservationContextMatcher(srvAddr))
        .build();

    endpoint.start();

    multicastClient = new CoapClient();
    multicastClient.setEndpoint(endpoint);

    LOGGER.info("Joined group {} on interface {} port {}", groupAddr, ni.getDisplayName(), port);
  }

  public static void main(String requestURI, int sender, boolean useOscoreParam) {
    clientId = sender;
    NtpUtil.initialize();
    useOscore = useOscoreParam;
    try {
    	if (useOscore) {
    		setupOscore(sender, requestURI);
    	} 
    }catch (OSException e) {
		LOGGER.error("Failed to set up OSCORE context", e);
		return;
	}
    run(requestURI);
  }

  private static void run(String requestURI) {
    try {
      Configuration config = Configuration.getStandard();
      Configuration.setStandard(config);

      LOGGER.debug("Requesting {}", requestURI);

      CoapEndpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
      CoapClient client = new CoapClient();
      client.setEndpoint(endpoint);
      client.setURI(requestURI);

      Request multicastRequest = createRequest(Code.GET, requestURI);

      MulticastObserveHandler handler = new MulticastObserveHandler(100, multicastRequest);
      client.observe(multicastRequest, handler);

      handler.waitForNotifications();

      if (multicastClient != null) multicastClient.shutdown();
    } catch (Exception e) {
      LOGGER.error("Error in multicast observe client", e);
    }
  }
}