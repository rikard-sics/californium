package org.eclipse.californium.proxy2.resources;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.elements.util.DatagramWriter;

import com.upokecenter.cbor.CBORObject;

//FIXME

public class ResponseForwardingOption extends Option {

	private int tpId;
	private InetAddress srvHost;
	private CBORObject srvPort = null;

	public static int NUMBER = 96;

	protected ResponseForwardingOption(OptionDefinition definition) {
		super(definition);
		// TODO Auto-generated constructor stub
	}

	public ResponseForwardingOption(int number) {
		// FIXME
		super(null);
	}

	public int getTpId() {
		return tpId;
	}

	public void setTpId(int tpId) {
		this.tpId = tpId;
	}

	public InetAddress getSrvHost() {
		return srvHost;
	}

	public void setSrvHost(InetAddress srvHost) {
		this.srvHost = srvHost;
	}

	public int getSrvPort() {
		return srvPort.AsInt32();
	}

	public void setSrvPort(int srvPort) {
		this.srvPort = CBORObject.FromObject(srvPort);
	}

	public void setSrvPortNull() {
		this.srvPort = CBORObject.Null;
	}

	public byte[] getValue() {
		CBORObject arrayOut = CBORObject.NewArray();
		arrayOut.Add(tpId);

		byte[] hostBytes = srvHost.getAddress();
		arrayOut.Add(CBORObject.FromObject(hostBytes).WithTag(260));
		if (srvPort != null) {
			arrayOut.Add(srvPort);
		}

		return arrayOut.EncodeToBytes();
	}

	public void setValue(byte[] value) {
		CBORObject arrayIn = CBORObject.DecodeFromBytes(value);
		
		setTpId(arrayIn.get(0).AsInt32Value());
		
		InetAddress hostAddr;
		try {
			hostAddr = InetAddress.getByAddress(arrayIn.get(1).GetByteString());
			setSrvHost(hostAddr);
		} catch (UnknownHostException e) {
			System.err.println("Failed to parse srv_host in Response-Forwarding option!");
			e.printStackTrace();
		}

		if(arrayIn.size() > 2) {
			setSrvPort(arrayIn.get(2).AsInt32Value());
		} else {
			setSrvPort(CoAP.DEFAULT_COAP_PORT);
		}
	}

	@Override
	public int getLength() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void writeTo(DatagramWriter writer) {
		// TODO Auto-generated method stub

	}

	@Override
	public String toValueString() {
		// TODO Auto-generated method stub
		return null;
	}

}
