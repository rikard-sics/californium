// Lucas

package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.apache.hc.client5.http.utils.Hex;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.test.CountingCoapHandler;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.group.OptionEncoder;

import com.upokecenter.cbor.CBORObject;

/**
 * 
 * SimpleProxyClient to display the basic OSCORE mechanics through a proxy
 *
 */
public class SimpleProxyClient {


	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static String uriServerPathObserve = "/hello/observe2";
	private final static String uriServerPathTestObserve = "/observe3";
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

	private final static int[][] optionSetsURI = {
			{}, 
			{OptionNumberRegistry.PROXY_URI}
	};

	private final static int[][] optionSetsScheme = {
			{}, 
			{OptionNumberRegistry.URI_PORT, OptionNumberRegistry.URI_HOST, OptionNumberRegistry.PROXY_SCHEME}
	};
	//OSCORE OPTION
	// we do not want the oscore option to be inner for first layer of encryption
	private final static boolean[] OSCOREAnswer1 = {true, false, false, false, false}; //inner oscore option

	//PROXY-URI OPTION
	//private final static boolean[] ProxyURIAnswer1 = {true, true, false, false, false};
	private final static boolean[] ProxyURIAnswer2 = {true, true, true, true, false};

	//URI-PORT OPTION
	//private final static boolean[] URIPORTAnswer1 = {true, true, false, true, false};
	private final static boolean[] URIPORTAnswer2 = {true, true, true, true, false};

	//URI-HOST OPTION
	//private final static boolean[] URIHostAnswer1 = URIPORTAnswer1;
	private final static boolean[] URIHostAnswer2 = {true, true, true, true, false};

	//PROXY-SCHEME OPTION
	//private final static boolean[] ProxySchemeAnswer1 = ProxyURIAnswer1;
	private final static boolean[] ProxySchemeAnswer2 = {true, true, true, true, false};

	private final static boolean[][][] answerSetsURI = {
			{},
			{ProxyURIAnswer2}
	};

	private final static boolean[][][] answerSetsScheme = {
			{},
			{URIPORTAnswer2, URIHostAnswer2, ProxySchemeAnswer2}
	};

	//0 did i add the option
	//1 is x a consumer of the option
	//2 is x the immediate consumer of the option
	//3 is x my next hop OR is next hop not the immediate consumer of the option
	//4 does x need option before decrypting, or in order to decrypt	

	//excluded options are not supposed to be promoted

	private final static CBORObject[][] postValuesUriObserve =  {
			{CBORObject.FromObject(uriServer + uriServerPathObserve)},
			{}
	};
	private final static CBORObject[][] postValuesUri =  {
			{CBORObject.FromObject(uriServer + uriServerPath)},
			{}
	};
	private final static CBORObject[][] postValuesScheme =  {
			{CBORObject.FromObject("coap")},
			{}
	};
	private final static int[][] optionSetsPostUriObserve = {
			{OptionNumberRegistry.PROXY_URI}, 
			{}
	};
	private final static int[][] optionSetsPostUri = {
			{OptionNumberRegistry.PROXY_URI}, 
			{}
	};

	private final static int[][] optionSetsPostScheme = {
			{OptionNumberRegistry.PROXY_SCHEME}, 
			{}
	};


	public static void main(String[] args) throws OSException, ConnectorException, IOException, InterruptedException {
		OSCoreCtx ctxserver = new OSCoreCtx(master_secret, true, alg, sids[0], rids[0], kdf, 32, master_salt, idcontexts[0], MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriServer, ctxserver);

		OSCoreCtx ctxproxy = new OSCoreCtx(master_secret, true, alg, sids[1], rids[1], kdf, 32, master_salt, idcontexts[1], MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriProxy, ctxproxy);

		OSCoreCoapStackFactory.useAsDefault(db);

		//Scenario 3 cases
		sendVanilla();

		//sendWithProxyScheme();

		//sendWithProxyURI();

		//sendWithPostURIAndScheme();

		//sendWithObserve();
	}

	
	private static void sendWithObserve() throws ConnectorException, IOException, InterruptedException {
		// Handler for Observe responses
		class ObserveHandler extends CountingCoapHandler {

			// Triggered when a Observe response is received
			@Override
			protected void assertLoad(CoapResponse response) {

				System.out.println("In Observe handler");
				String content = response.getResponseText();
				System.out.println("NOTIFICATION: " + content);

				// Check the incoming responses
				assertEquals(ResponseCode.CONTENT, response.getCode());
				assertEquals(MediaTypeRegistry.TEXT_PLAIN, response.getOptions().getContentFormat());

				if (loadCalls.get() == 1) {
					assertTrue(response.getOptions().hasObserve());
					assertEquals("one", response.getResponseText());
				} else if (loadCalls.get() == 2) {
					assertTrue(response.getOptions().hasObserve());
					assertEquals("two", response.getResponseText());
				}
			}
		}

		byte[] oscoreoptUri = CBORObject.FromObject(new byte[0]).EncodeToBytes();
		byte[] indexUri = CBORObject.FromObject(2).EncodeToBytes();

		byte[] instructionsUri = Bytes.concatenate(oscoreoptUri, indexUri);

		for (int i = 0; i < rids.length; i++) {
			instructionsUri = Bytes.concatenate(instructionsUri, OptionEncoder.set(rids[i], idcontexts[i], optionSetsURI[i], answerSetsURI[i], optionSetsPostUriObserve[i], postValuesUriObserve[i]));
		}

		CoapEndpoint.Builder builder = CoapEndpoint.builder();
		//.setConfiguration(outgoingConfig);
		// builder.setCoapStackFactory(new OSCoreCoapStackFactory());//
		// builder.setCustomCoapStackArgument(db);//
		builder.setPort(5686);


		CoapEndpoint clientEndpoint = builder.build();

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		client.setURI(uriServer);

		//CoapClient client = new CoapClient(uriServer + uriServerPath);

		AddressEndpointContext proxy = new AddressEndpointContext("localhost", 5685);

		Request request;
		CoapResponse resp;
		
		System.out.println();
		System.out.println(" ----- ");
		System.out.println();
		System.out.println("Sending with instructions... Observe");
		System.out.println();
		System.out.println(" ----- ");
		System.out.println();

		request = new Request(Code.GET);
		request.setDestinationContext(proxy);
		//request.getOptions().setOscore(instructionsUri); //  instructionsUri new byte[0]
		
		request.setObserve();
		
		request.getOptions().setOscore(new byte[0]);
		request.getOptions().setProxyUri(uriServer + uriServerPathTestObserve); //////////////


		ObserveHandler handler = new ObserveHandler();

		CoapObserveRelation relation = client.observe(request, handler);

		//Wait until 2 messages have been received
		assertTrue(handler.waitOnLoadCalls(2, 5000, TimeUnit.MILLISECONDS));
		
		Token token = request.getToken();
		
		//Now cancel the Observe and wait for the final response
		
		request = new Request(Code.GET);
		request.setDestinationContext(proxy);
		//request.getOptions().setOscore(instructionsUri); // instructionsUri new byte[0]
		request.getOptions().setObserve(1); //Deregister Observe
		request.setToken(token);

		request.getOptions().setOscore(new byte[0]);
		request.getOptions().setProxyUri(uriServer + uriServerPathTestObserve); //////////////

		System.out.println(request);
		//request.send();
		CoapResponse ackResponse = client.advanced(request);
		System.out.println("Response on cancel is type: " + ackResponse.advanced().getType());

		
		Response response = request.waitForResponse(1000);
		printResponse(response);
		System.out.println("done");
	}
	
	private static void sendWithPostURIAndScheme() throws ConnectorException, IOException {

		byte[] oscoreoptUri = CBORObject.FromObject(new byte[0]).EncodeToBytes();
		byte[] indexUri = CBORObject.FromObject(2).EncodeToBytes();

		byte[] instructionsUri = Bytes.concatenate(oscoreoptUri, indexUri);

		for (int i = 0; i < rids.length; i++) {
			instructionsUri = Bytes.concatenate(instructionsUri, OptionEncoder.set(rids[i], idcontexts[i], optionSetsURI[i], answerSetsURI[i], optionSetsPostUri[i], postValuesUri[i]));
		}


		byte[] oscoreoptScheme = CBORObject.FromObject(new byte[0]).EncodeToBytes();
		byte[] indexScheme = CBORObject.FromObject(2).EncodeToBytes();

		byte[] instructionsScheme = Bytes.concatenate(oscoreoptScheme, indexScheme);

		for (int i = 0; i < rids.length; i++) {
			instructionsScheme = Bytes.concatenate(instructionsScheme, OptionEncoder.set(rids[i], idcontexts[i], optionSetsScheme[i], answerSetsScheme[i], optionSetsPostScheme[i], postValuesScheme[i]));
		}
		CoapEndpoint.Builder builder = CoapEndpoint.builder();
		//.setConfiguration(outgoingConfig);
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());//
		builder.setCustomCoapStackArgument(db);//
		builder.setPort(5686);


		CoapEndpoint clientEndpoint = builder.build();

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		client.setURI(uriServer);

		//CoapClient client = new CoapClient(uriServer + uriServerPath);

		AddressEndpointContext proxy = new AddressEndpointContext("localhost", 5685);

		Request request;
		CoapResponse resp;

		System.out.println();
		System.out.println(" ----- ");
		System.out.println();
		System.out.println("Sending with instructions... Proxy-URI");
		System.out.println();
		System.out.println(" ----- ");
		System.out.println();


		request = new Request(Code.GET);
		request.setDestinationContext(proxy);
		request.getOptions().setOscore(instructionsUri);

		resp = client.advanced(request);
		printResponse(resp);


		client = new CoapClient();
		client.useProxy();
		client.setEndpoint(clientEndpoint);
		client.setURI(uriServer + uriServerPath);

		System.out.println();
		System.out.println(" ----- ");
		System.out.println();
		System.out.println("Sending with instructions... Proxy-Scheme");
		System.out.println();
		System.out.println(" ----- ");
		System.out.println();


		request = new Request(Code.GET);
		request.setDestinationContext(proxy);

		request.getOptions().setOscore(instructionsScheme);

		resp = client.advanced(request);
		printResponse(resp);

		client.getEndpoint().destroy();
		client.shutdown();


	}
	private static void sendWithProxyURI() throws ConnectorException, IOException {
		byte[] oscoreopt = CBORObject.FromObject(new byte[0]).EncodeToBytes();
		byte[] index = CBORObject.FromObject(2).EncodeToBytes();

		byte[] instructions = Bytes.concatenate(oscoreopt, index);

		for (int i = 0; i < rids.length; i++) {
			instructions = Bytes.concatenate(instructions, OptionEncoder.set(rids[i], idcontexts[i], optionSetsURI[i], answerSetsURI[i]));
		}

		CoapEndpoint.Builder builder = CoapEndpoint.builder();
		//.setConfiguration(outgoingConfig);
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());//
		builder.setCustomCoapStackArgument(db);//
		builder.setPort(5686);


		CoapEndpoint clientEndpoint = builder.build();

		CoapClient client = new CoapClient(uriProxy + uriProxyPath);
		client.setEndpoint(clientEndpoint);
		//client.setURI();

		//CoapClient client = new CoapClient(uriServer + uriServerPath);

		AddressEndpointContext proxy = new AddressEndpointContext("localhost", 5685);

		System.out.println(" ----- ");
		System.out.println();
		System.out.println("Sending with OSCORE...");
		System.out.println();
		System.out.println(" ----- ");
		System.out.println();


		Request request = Request.newGet();
		request.setDestinationContext(proxy);
		request.setProxyUri(uriServer + uriServerPath);
		request.getOptions().setOscore(new byte[0]);


		CoapResponse resp = client.advanced(request);
		printResponse(resp);

		//Request request;
		//CoapResponse resp;

		System.out.println();
		System.out.println(" ----- ");
		System.out.println();
		System.out.println("Sending with instructions...");
		System.out.println();
		System.out.println(" ----- ");
		System.out.println();


		request = new Request(Code.GET);
		request.setDestinationContext(proxy);
		request.setProxyUri(uriServer + uriServerPath);
		request.getOptions().setOscore(instructions);

		resp = client.advanced(request);
		printResponse(resp);

		client.getEndpoint().destroy();
		client.shutdown();
	}

	private static void sendWithProxyScheme() throws ConnectorException, IOException {
		byte[] oscoreopt = CBORObject.FromObject(new byte[0]).EncodeToBytes();
		byte[] index = CBORObject.FromObject(2).EncodeToBytes();

		byte[] instructions = Bytes.concatenate(oscoreopt, index);

		for (int i = 0; i < rids.length; i++) {
			instructions = Bytes.concatenate(instructions, OptionEncoder.set(rids[i], idcontexts[i], optionSetsScheme[i], answerSetsScheme[i]));
		}

		CoapEndpoint.Builder builder = CoapEndpoint.builder();
		//.setConfiguration(outgoingConfig);
		builder.setCoapStackFactory(new OSCoreCoapStackFactory());//
		builder.setCustomCoapStackArgument(db);//
		builder.setPort(5686);


		CoapEndpoint clientEndpoint = builder.build();

		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		client.setURI(uriServer + uriServerPath);

		//CoapClient client = new CoapClient(uriServer + uriServerPath);

		AddressEndpointContext proxy = new AddressEndpointContext("localhost", 5685);

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

		//Request request;
		//CoapResponse resp;

		System.out.println();
		System.out.println(" ----- ");
		System.out.println();
		System.out.println("Sending with instructions...");
		System.out.println();
		System.out.println(" ----- ");
		System.out.println();


		request = new Request(Code.GET);
		request.setDestinationContext(proxy);
		request.setProxyScheme("coap");
		request.getOptions().setOscore(instructions);

		resp = client.advanced(request);
		printResponse(resp);

		client.getEndpoint().destroy();
		client.shutdown();
	}

	private static void sendVanilla() throws IOException, ConnectorException {
		CoapClient c = new CoapClient(uriServer + uriServerPath);
		c.setTimeout((long) 10000);
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

	private static void printResponse(Response resp) {
		if (resp != null) {
			System.out.println("Printing response with:  Token=" + resp.getTokenString());
			System.out.println("RESPONSE CODE: " + resp.getCode().name() + " " + resp.getCode());
			if (resp.getPayload() != null) {
				System.out.print("RESPONSE PAYLOAD: ");
				for (byte b : resp.getPayload()) {
					System.out.print(Integer.toHexString(b & 0xff) + " ");
				}
				System.out.println();
			}
			System.out.println("RESPONSE TEXT: " + resp.getPayloadString());
		} 
		else {
			System.out.println("RESPONSE IS NULL");
		}
	}
}
