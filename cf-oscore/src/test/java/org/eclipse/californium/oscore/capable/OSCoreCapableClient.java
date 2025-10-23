// Lucas

package org.eclipse.californium.oscore.capable;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.test.CountingCoapHandler;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.group.OptionEncoder;

import com.upokecenter.cbor.CBORObject;

/**
 * 
 * SimpleProxyClient to display the basic OSCORE mechanics through a proxy
 *
 */
public class OSCoreCapableClient {

	private final static HashMapCtxDB db = new HashMapCtxDB(2);
	private final static String serverIP = "127.0.0.1"; //"169.254.154.184"; //
	private final static String uriServer = "coap://" + serverIP + ":5683";
	private final static String uriServerPath = "/hello/1";
	private final static String uriServerPathObserve = "/hello/2";

	private final static String proxyIP = "127.0.0.1"; // "169.254.106.132"; //
	private final static String uriProxy = "coap://" + proxyIP + ":5685";
	private final static String uriProxyPath = "";

	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	private final static byte[][] sids = {
			new byte[] { 0x01 }, 
			new byte[] { (byte) 0xAA }
	};

	private final static byte[][] rids = {
			new byte[] { 0x05 }, 
			new byte[] { (byte) 0xAA }
	};

	private final static byte[][] idcontexts = {
			new byte[] { 0x01 }, 
			new byte[] { (byte) 0xAA }
	};

	/*------------------------------PROXY-Uri OPTION------------------------------*/

	private final static int[][] optionSetsURI = {
			{}, 
			{OptionNumberRegistry.PROXY_URI}
	};

	private final static boolean[] ProxyURIAnswer = {true, true, true, true, false};

	private final static boolean[][][] answerSetsURI = {
			{},
			{ProxyURIAnswer}
	};

	private final static CBORObject[][] postValuesUri =  {
			{CBORObject.FromObject(uriServer + uriServerPath)},
			{}
	};

	private final static int[][] optionSetsPostUri = {
			{OptionNumberRegistry.PROXY_URI}, 
			{}
	};

	/*-----------------------------PROXY-Scheme OPTION----------------------------*/

	private final static int[][] optionSetsScheme = {
			{}, 
			{OptionNumberRegistry.URI_PORT, OptionNumberRegistry.URI_HOST, OptionNumberRegistry.PROXY_SCHEME}
	};

	private final static boolean[] URIPORTAnswer = {true, true, true, true, false};

	private final static boolean[] URIHostAnswer = {true, true, true, true, false};

	private final static boolean[] ProxySchemeAnswer = {true, true, true, true, false};

	private final static boolean[][][] answerSetsScheme = {
			{},
			{URIPORTAnswer, URIHostAnswer, ProxySchemeAnswer}
	};

	private final static CBORObject[][] postValuesScheme =  {
			{CBORObject.FromObject("coap"), CBORObject.FromObject(serverIP),CBORObject.FromObject(5683)},
			{}
	};

	private final static int[][] optionSetsPostScheme = {
			{OptionNumberRegistry.PROXY_SCHEME, OptionNumberRegistry.URI_HOST, OptionNumberRegistry.URI_PORT}, 
			{}
	};


	public static void main(String[] args) throws OSException, ConnectorException, IOException, InterruptedException {
		OSCoreCtx ctxserver = new OSCoreCtx(master_secret, true, alg, sids[0], rids[0], kdf, 32, master_salt, idcontexts[0], MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriServer, ctxserver);

		OSCoreCtx ctxproxy = new OSCoreCtx(master_secret, true, alg, sids[1], rids[1], kdf, 32, master_salt, idcontexts[1], MAX_UNFRAGMENTED_SIZE);
		db.addContext(uriProxy, ctxproxy);

		OSCoreCoapStackFactory.useAsDefault(db);

		CoapClient clientToServer = new CoapClient(uriProxy + uriProxyPath);

		CoapResponse response;

		response = OSCOREUri(clientToServer);
		assertTrue(response.getOptions().hasOscore());
		assertEquals(response.getResponseText(), "Hello World!");
		assertEquals(response.getCode(), ResponseCode.CONTENT);

		response = OSCOREScheme(clientToServer);
		assertTrue(response.getOptions().hasOscore());
		assertEquals(response.getResponseText(), "Hello World!");
		assertEquals(response.getCode(), ResponseCode.CONTENT);

		response = PostURISend(clientToServer);
		assertTrue(response.getOptions().hasOscore());
		assertEquals(response.getResponseText(), "Hello World!");
		assertEquals(response.getCode(), ResponseCode.CONTENT);

		response = PostSchemeSend(clientToServer);
		assertTrue(response.getOptions().hasOscore());
		assertEquals(response.getResponseText(), "Hello World!");
		assertEquals(response.getCode(), ResponseCode.CONTENT);


		response = PostObserveSend(clientToServer);

		System.out.println("Finished");
	}
	public static CoapResponse Uri(CoapClient c) throws ConnectorException, IOException {
		Request r = new Request(Code.GET);
		r.getOptions().setProxyUri(uriServer + uriServerPath);
		return c.advanced(r);
	}
	public static CoapResponse Scheme(CoapClient c) throws ConnectorException, IOException {
		AddressEndpointContext proxy = new AddressEndpointContext(proxyIP, 5685);

		Request r = new Request(Code.GET);
		r.getOptions().setProxyScheme("coap");
		r.getOptions().setUriHost(serverIP);
		r.getOptions().setUriPort(5683);
		r.getOptions().setUriPath(uriServerPath);
		r.setUriIsApplied();
		r.setDestinationContext(proxy);
		return c.advanced(r);
	}

	public static CoapResponse OSCOREUri(CoapClient c) throws ConnectorException, IOException {
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(Bytes.EMPTY);
		r.getOptions().setProxyUri(uriServer + uriServerPath);
		return c.advanced(r);
	}

	public static CoapResponse OSCOREScheme(CoapClient c) throws ConnectorException, IOException {
		AddressEndpointContext proxy = new AddressEndpointContext(proxyIP, 5685);

		Request r = new Request(Code.GET);
		r.getOptions().setOscore(Bytes.EMPTY);
		r.getOptions().setProxyScheme("coap");
		r.getOptions().setUriHost(serverIP);
		r.getOptions().setUriPort(5683);
		r.getOptions().setUriPath(uriServerPath);
		r.setUriIsApplied();
		r.setDestinationContext(proxy);
		return c.advanced(r);
	}

	public static CoapResponse PostURISend(CoapClient c) throws ConnectorException, IOException {
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(getPostURIInstruction());
		return c.advanced(r);
	}

	public static byte[] getPostURIInstruction() {
		byte[] oscoreoptUri = CBORObject.FromObject(new byte[0]).EncodeToBytes();
		byte[] indexUri = CBORObject.FromObject(2).EncodeToBytes();

		byte[] instructionsUri = Bytes.concatenate(oscoreoptUri, indexUri);

		for (int i = 0; i < rids.length; i++) {
			instructionsUri = Bytes.concatenate(instructionsUri, OptionEncoder.set(rids[i], idcontexts[i], optionSetsURI[i], answerSetsURI[i], optionSetsPostUri[i], postValuesUri[i]));
		}
		return instructionsUri;
	}

	public static CoapResponse PostSchemeSend(CoapClient c) throws ConnectorException, IOException {
		AddressEndpointContext proxy = new AddressEndpointContext(proxyIP, 5685);

		Request r = new Request(Code.GET);
		r.setUriIsApplied();
		r.setDestinationContext(proxy);

		r.getOptions().setOscore(getPostSchemeInstruction());
		r.getOptions().setUriPath(uriServerPath);
		return c.advanced(r);
	}

	public static byte[] getPostSchemeInstruction() {
		byte[] oscoreoptScheme = CBORObject.FromObject(new byte[0]).EncodeToBytes();
		byte[] indexScheme = CBORObject.FromObject(2).EncodeToBytes();

		byte[] instructionsScheme = Bytes.concatenate(oscoreoptScheme, indexScheme);

		for (int i = 0; i < rids.length; i++) {
			instructionsScheme = Bytes.concatenate(instructionsScheme, OptionEncoder.set(rids[i], idcontexts[i], optionSetsScheme[i], answerSetsScheme[i], optionSetsPostScheme[i], postValuesScheme[i]));
		}
		return instructionsScheme;
	}

	public static CoapResponse PostObserveSend(CoapClient c) throws ConnectorException, IOException, InterruptedException {
		// Handler for Observe responses
		class ObserveHandler extends CountingCoapHandler {

			// Triggered when a Observe response is received
			@Override
			protected void assertLoad(CoapResponse response) {

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
		AddressEndpointContext proxy = new AddressEndpointContext(proxyIP, 5685);

		Request r = new Request(Code.GET);
		r.setUriIsApplied();
		r.setDestinationContext(proxy);
		r.setObserve();

		//
		r.getOptions().setProxyScheme("coap");
		r.getOptions().setUriHost(serverIP);
		r.getOptions().setUriPort(5683);
		r.getOptions().setUriPath(uriServerPath);
		r.getOptions().setOscore(Bytes.EMPTY);
		r.setUriIsApplied();
		//
		//r.getOptions().setOscore(getPostSchemeInstruction());
		r.getOptions().setUriPath(uriServerPathObserve);

		ObserveHandler handler = new ObserveHandler();

		CoapObserveRelation relation = c.observe(r, handler);

		//Wait until 2 messages have been received
		assertTrue(handler.waitOnLoadCalls(2, 5000, TimeUnit.MILLISECONDS));

		Token token = r.getToken();

		//Now cancel the Observe and wait for the final response

		r = new Request(Code.GET);
		r.setUriIsApplied();
		r.setDestinationContext(proxy);
		r.getOptions().setObserve(1); //Deregister Observe
		r.setToken(token);

		//r.getOptions().setOscore(getPostSchemeInstruction());
		r.getOptions().setProxyScheme("coap");
		r.getOptions().setUriHost(serverIP);
		r.getOptions().setUriPort(5683);
		r.getOptions().setUriPath(uriServerPath);
		r.setUriIsApplied();
		r.getOptions().setOscore(Bytes.EMPTY);
		//
		r.getOptions().setUriPath(uriServerPathObserve);
		return c.advanced(r);
	}

}
