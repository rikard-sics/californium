// Lucas

package org.eclipse.californium.oscore;

import java.io.IOException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.exception.ConnectorException;

/**
 * 
 * SimpleProxyClient to display the basic OSCORE mechanics through a proxy
 *
 */
public class SimpleProxyClient {

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriLocal = "coap://localhost:5683";
	private final static String hello1 = "/hello/1";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	public static void main(String[] args) throws OSException, ConnectorException, IOException {
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null, MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriLocal, ctx);

		OSCoreCoapStackFactory.useAsDefault(db);
		CoapClient c = new CoapClient(uriLocal + hello1);

		System.out.println("Sending without proxy");
		// send without OSCORE
		Request r = new Request(Code.GET);
		CoapResponse resp = c.advanced(r);
		printResponse(resp);
		
		// Send with OSCORE
		r = new Request(Code.GET);
		r.getOptions().setOscore(new byte[0]);
		resp = c.advanced(r);
		printResponse(resp);
		
		
		System.out.println("\nSending with proxy");
		// Send to through proxy
		// set URI to proxy
		c.setURI("coap://localhost:5685/coap2coap");
				
		// send without OSCORE through proxy
		r = new Request(Code.GET);
		// set URI for proxy to forward/reverse to
		r.getOptions().setProxyUri(uriLocal + hello1);
		resp = c.advanced(r);
		printResponse(resp);
				
		// Send with OSCORE through proxy
		r = new Request(Code.GET);
		// set URI for proxy to forward/reverse to
		r.getOptions().setProxyUri(uriLocal + hello1);
		r.getOptions().setOscore(new byte[0]);
		resp = c.advanced(r);
		printResponse(resp);
		
		System.out.println("sending ending");
		
		c.shutdown();
	}

	private static void printResponse(CoapResponse resp) {
		System.out.println("Token=" + resp.advanced().getTokenString());
		if (resp != null) {
			System.out.println("RESPONSE CODE: " + resp.getCode().name() + " " + resp.getCode());
			if (resp.getPayload() != null) {
				System.out.print("RESPONSE PAYLOAD: ");
				for (byte b : resp.getPayload()) {
					System.out.print(Integer.toHexString(b & 0xff) + " ");
				}
				System.out.println();
			}
			System.out.println("RESPONSE TEXT: " + resp.getResponseText());
		} else {
			System.out.println("RESPONSE IS NULL");
		}
	}
}
