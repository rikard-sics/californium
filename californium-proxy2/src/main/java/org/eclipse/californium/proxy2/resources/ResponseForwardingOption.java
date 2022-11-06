package org.eclipse.californium.proxy2.resources;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Option;

import com.upokecenter.cbor.CBORObject;

public class ResponseForwardingOption extends Option {

	private int tpId;
	private InetAddress srvHost;
	private int srvPort = -1;

	public static int NUMBER = 96;

	public ResponseForwardingOption(int number) {
		super(number);
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
		return srvPort;
	}

	public void setSrvPort(int srvPort) {
		this.srvPort = srvPort;
	}

	@Override
	public byte[] getValue() {
		CBORObject arrayOut = CBORObject.NewArray();
		arrayOut.Add(tpId);

		byte[] hostBytes = srvHost.getAddress();
		arrayOut.Add(CBORObject.FromObject(hostBytes).WithTag(260));

		arrayOut.Add(srvPort);

		return arrayOut.EncodeToBytes();
	}

	@Override
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

}
