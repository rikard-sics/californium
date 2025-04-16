// Lucas

package org.eclipse.californium.oscore;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.oscore.group.OptionEncoder;

import com.upokecenter.cbor.CBORObject;

/**
 * 
 * SimpleProxyServer to display basic OSCORE mechanics through a proxy
 *
 */
public class SimpleProxyServer {

	private final static HashMapCtxDB db = new HashMapCtxDB();
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
			new byte[] { 0x01 }, 
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
		db.addContext(uriLocal + ":" + Objects.toString(CoapProxyPort + 1), ctxclient);

		OSCoreCtx ctxproxy = new OSCoreCtx(master_secret, true, alg, sids[1], rids[1], kdf, 32, master_salt, idcontexts[1], MAX_UNFRAGMENTED_SIZE);
		int i = CoapProxyPort - 1;
		db.addContext(uriLocal + ":" + Objects.toString(i), ctxproxy);

		OSCoreCoapStackFactory.useAsDefault(db);

		db.size();
		//OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, new byte[] { 0x01 }, MAX_UNFRAGMENTED_SIZE);
		//db.addContext(uriLocal, ctx);

		//OSCoreCoapStackFactory.useAsDefault(db);

		final CoapServer server = new CoapServer(5683);

		OSCoreResource hello = new OSCoreResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello Resource");
				//r.getOptions().setMaxAge(4);
				exchange.respond(r);
			}
		};

		OSCoreResource hello1 = new OSCoreResource("1", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello/1 resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload("Hello World!");
				System.out.println("Recieved GET with " + exchange.advanced().getRequest().getToken());
				System.out.println(exchange.advanced().getCryptographicContextID());
				CBORObject[] instructions = OptionEncoder.decodeCBORSequence(exchange.advanced().getCryptographicContextID());
				System.out.println();
				if (instructions != null) {
					for (CBORObject obj : instructions) {
						System.out.println(obj);
					}
				}
				//r.getOptions().setMaxAge(4);
				exchange.respond(r);
				counter.incrementAndGet();
				/*if (counter.get() == 2) {
					server.destroy();
				}*/

			}
		};

		server.add(hello.add(hello1));
		server.start();
	}
}