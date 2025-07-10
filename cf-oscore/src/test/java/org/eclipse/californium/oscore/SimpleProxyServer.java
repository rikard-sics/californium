// Lucas

package org.eclipse.californium.oscore;

import java.util.Objects;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.OptionEncoder;

import com.upokecenter.cbor.CBORObject;

/**
 * 
 * SimpleProxyServer to display basic OSCORE mechanics through a proxy
 *
 */
public class SimpleProxyServer {
	private static Timer timer;

	private final static HashMapCtxDB db = new HashMapCtxDB(2);
	private final static String proxyIP = "127.0.0.1"; // "169.254.106.132"; 
	private final static String clientIP = "127.0.0.1"; // "169.254.106.130"; 
	private final static String uriLocal = "coap://localhost";
	private final static int CoapProxyPort = 5685;

	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[] { 0x01 };
	private final static byte[] rid = new byte[] { 0x01 }; //[0];
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	private final static byte[][] sids = {
			new byte[] { 0x05 }, 
			new byte[] { 0x03 }
	};

	private final static byte[][] rids = {
			new byte[] { 0x01 }, 
			new byte[] { 0x03 }
	};

	private final static byte[][] idcontexts = {
			new byte[] { 0x01 }, 
			new byte[] { 0x03 }
	};
	private static AtomicInteger counter = new AtomicInteger(0);

	public static void main(String[] args) throws OSException {
		OSCoreCtx ctxclient = new OSCoreCtx(master_secret, true, alg, sids[0], rids[0], kdf, 32, master_salt, idcontexts[0], MAX_UNFRAGMENTED_SIZE);
		db.addContext("coap://" + clientIP + ":" + Objects.toString(CoapProxyPort + 1), ctxclient);

		OSCoreCtx ctxproxy = new OSCoreCtx(master_secret, true, alg, sids[1], rids[1], kdf, 32, master_salt, idcontexts[1], MAX_UNFRAGMENTED_SIZE);
		int i = CoapProxyPort - 1;
		db.addContext("coap://" + proxyIP + ":" + Objects.toString(i), ctxproxy);

		OSCoreCoapStackFactory.useAsDefault(db);

		final CoapServer server = new CoapServer(5683);

		OSCoreResource hello = new OSCoreResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello Resource");
				r.getOptions().setMaxAge(4);
				exchange.respond(r);
			}
		};

		OSCoreResource hello1 = new OSCoreResource("1", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				//System.out.println("Accessing hello/1 resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello World!");
				exchange.respond(r);

			}
		};

		/**
		 * The resource for testing Observe support 
		 * 
		 * Responds with "one" for the first request and "two" for later updates.
		 *
		 */
		class ObserveResource extends CoapResource {

			public String value = "one";
			private boolean firstRequestReceived = false;

			public ObserveResource(String name, boolean visible) {
				super(name, visible);

				this.setObservable(true); 
				this.setObserveType(Type.NON);
				this.getAttributes().setObservable();

				timer.schedule(new UpdateTask(), 0, 750);
			}

			@Override
			public void handleGET(CoapExchange exchange) {
				Response response = new Response(ResponseCode.CONTENT);
				response.setPayload(value);
				response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);

				if (exchange.advanced().getRequest().isObserveCancel()) {
					value = "one";
					firstRequestReceived  = false;
				}
				else {
					firstRequestReceived  = true;
				}

				CBORObject[] obj = db.getInstructions(exchange.advanced().getRequest().getToken());
				if (Objects.nonNull(obj)) {
					if (obj.length > 3 && obj[3].get(7) == null) {
						CBORObject optionsPostSetHolder = CBORObject.NewMap();
						optionsPostSetHolder.Add(14, 0);
						obj[3].Add(7, optionsPostSetHolder);
					}
				}
				else if (!Objects.nonNull(obj) && exchange.getRequestOptions().hasOscore()) {

					byte[] oscoreoptScheme = CBORObject.FromObject(new byte[0]).EncodeToBytes();
					byte[] indexScheme = CBORObject.FromObject(2).EncodeToBytes();

					byte[] instructionsScheme = Bytes.concatenate(oscoreoptScheme, indexScheme);

					int[] optionSetsPostScheme = {14};
					CBORObject[] postValuesScheme = {CBORObject.FromObject(0)};

					OscoreOptionDecoder optionDecoder = null;
					try {
						optionDecoder = new OscoreOptionDecoder(exchange.advanced().getCryptographicContextID());
					} catch (CoapOSException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					int requestSequenceNumber = optionDecoder.getSequenceNumber();
					instructionsScheme = Bytes.concatenate(instructionsScheme, OptionEncoder.set(rids[0], idcontexts[0], optionSetsPostScheme, postValuesScheme, requestSequenceNumber));

					db.removeToken(exchange.advanced().getRequest().getToken());
					db.addInstructions(exchange.advanced().getRequest().getToken(),OptionEncoder.decodeCBORSequence(instructionsScheme));

				}

				//if (exchange.advanced().getRequest().getOptions().hasOscore()) {
				//	response.getOptions().setMaxAge(30);
				//}
				exchange.respond(response);
			}

			//Update the resource value when timer triggers (if 1st request is received)
			class UpdateTask extends TimerTask {
				@Override
				public void run() {
					if(firstRequestReceived) {
						value = "two";
						changed(); // notify all observers
					}
				}
			}
		}
		timer = new Timer();
		//observe2 resource for OSCORE Observe tests
		ObserveResource oscore_observe2 = new ObserveResource("2", true);

		hello.add(oscore_observe2);

		ObserveResource observe3 = new ObserveResource("observe3", true);
		server.add(observe3);

		server.add(hello.add(hello1));
		server.start();
	}
}