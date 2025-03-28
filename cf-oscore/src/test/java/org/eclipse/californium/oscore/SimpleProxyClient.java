// Lucas

package org.eclipse.californium.oscore;

import java.io.IOException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.group.OptionEncoder;

import com.upokecenter.cbor.CBORObject;

/**
 * 
 * SimpleProxyClient to display the basic OSCORE mechanics through a proxy
 *
 */
public class SimpleProxyClient {
	

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriServer = "coap://localhost";
	private final static String uriServerPath = "/hello/1";
	private final static String uriProxy = "coap://localhost:5685";
	private final static String uriProxyPath = "/coap-to-coap";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	//private final static byte[] sid = new byte[0];
	//private final static byte[] rid = new byte[] { 0x01 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	private final static byte[][] sids = {
			new byte[] { 0x01 }, 
			new byte[] { 0x02 }
			};
	
	private final static byte[][] rids = {
			new byte[] { 0x01 }, 
			new byte[] { 0x02 }
			};
	
	private final static byte[][] idcontexts = {
			new byte[] { 0x01 }, 
			new byte[] { 0x02 }
			};
	
	private final static int[][] optionSets = {
		{}, 
		{OptionNumberRegistry.URI_HOST, OptionNumberRegistry.URI_PORT, OptionNumberRegistry.URI_PATH, OptionNumberRegistry.PROXY_SCHEME}
	};
	
	public static void main(String[] args) throws OSException, ConnectorException, IOException {
		OSCoreCtx ctxserver = new OSCoreCtx(master_secret, true, alg, sids[0], rids[0], kdf, 32, master_salt, idcontexts[0], MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriServer, ctxserver);

		OSCoreCtx ctxproxy = new OSCoreCtx(master_secret, true, alg, sids[1], rids[1], kdf, 32, master_salt, idcontexts[1], MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriProxy, ctxproxy);

		OSCoreCoapStackFactory.useAsDefault(db);
						
		boolean hasInstructions = true;
		
		if (hasInstructions) {
			CoapEndpoint.Builder builder = CoapEndpoint.builder();
			//.setConfiguration(outgoingConfig);
			builder.setCoapStackFactory(new OSCoreCoapStackFactory());//
			builder.setCustomCoapStackArgument(db);//
			builder.setPort(5686);


			CoapEndpoint clientEndpoint = builder.build();
			clientEndpoint.setIsForwardProxy();
	
			CoapClient client = new CoapClient();
			client.setEndpoint(clientEndpoint);
			client.setURI(uriServer + uriServerPath);
	
			//CoapClient client = new CoapClient(uriServer + uriServerPath);

			AddressEndpointContext proxy = new AddressEndpointContext("localhost", 5685);
	/*		
			System.out.println(" ----- ");
			System.out.println();
			System.out.println("Sending with OSCORE...");
			System.out.println();
			System.out.println(" ----- ");
			System.out.println();
			
			Request request = Request.newGet();
			request.setDestinationContext(proxy);
			request.setProxyScheme("coap");
			request.getOptions().setOscore(new byte[0]);
			
			CoapResponse resp = client.advanced(request);
			printResponse(resp);
*/
			Request request;
			CoapResponse resp;
	
			System.out.println();
			System.out.println(" ----- ");
			System.out.println();
			System.out.println("Sending with instructions...");
			System.out.println();
			System.out.println(" ----- ");
			System.out.println();

			byte[] oscoreopt = CBORObject.FromObject(new byte[0]).EncodeToBytes();
			byte[] index = CBORObject.FromObject(2).EncodeToBytes();
			
			byte[] instructions = OptionEncoder.combine(oscoreopt, index);
			
			for (int i = 0; i < rids.length; i++) {
				instructions = OptionEncoder.combine(instructions, OptionEncoder.set(rids[i], idcontexts[i], optionSets[i]));
			}
			
			request = new Request(Code.GET);
			request.setDestinationContext(proxy);
			request.setProxyScheme("coap");
			request.getOptions().setOscore(instructions);
			
			 resp = client.advanced(request);
			printResponse(resp);

			client.shutdown();
		}
		else {
			CoapClient c = new CoapClient(uriServer + uriServerPath);
			// send without OSCORE
			SendGet(c);
			try { Thread.sleep(10); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

			// Send with OSCORE
			SendGet(c, new byte[0]);
			try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
			
			
			System.out.println("\nSending with proxy");
			
			// send without OSCORE through proxy
			SendGet(c, uriProxy + uriProxyPath);
			try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
			
			// Send with OSCORE through proxy
			SendGet(c, uriProxy + uriProxyPath, new byte[0]);
			try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
			
			System.out.println("\nSending ending");
			
			c.shutdown();
		}		
	}
		

	private static void SendGet(CoapClient c) throws IOException, ConnectorException {
		Request r = new Request(Code.GET);
		CoapResponse resp = c.advanced(r);
		printResponse(resp);
	}
	
	private static void SendGet(CoapClient c, String ProxyURI) throws IOException, ConnectorException {
		final String temp = c.getURI();
		c.setURI(ProxyURI);
		
		Request r = new Request(Code.GET);
		r.getOptions().setProxyUri(uriServer + uriServerPath);
		CoapResponse resp = c.advanced(r);
		printResponse(resp);
		
		c.setURI(temp);
	}
	
	private static void SendGet(CoapClient c, byte[] OscoreOption) throws IOException, ConnectorException {
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(OscoreOption);
		CoapResponse resp = c.advanced(r);
		printResponse(resp);
	}
	
	private static void SendGet(CoapClient c, String ProxyURI, byte[] OscoreOption) throws IOException, ConnectorException {
		final String temp = c.getURI();
		c.setURI(ProxyURI);
		
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(OscoreOption);
		r.getOptions().setProxyUri(uriServer + uriServerPath);
		CoapResponse resp = c.advanced(r);
		printResponse(resp);
		
		c.setURI(temp);
	}
	
	private static void printResponse(CoapResponse resp) {
		if (resp != null) {
			System.out.println("Printing response with:  Token=" + resp.advanced().getTokenString());
			System.out.println("RESPONSE CODE: " + resp.getCode().name() + " " + resp.getCode());
			if (resp.getPayload() != null) {
				System.out.print("RESPONSE PAYLOAD: ");
				for (byte b : resp.getPayload()) {
					System.out.print(Integer.toHexString(b & 0xff) + " ");
				}
				System.out.println();
			}
			System.out.println("RESPONSE TEXT: " + resp.getResponseText());
		} 
		else {
			System.out.println("RESPONSE IS NULL");
		}
	}
}
