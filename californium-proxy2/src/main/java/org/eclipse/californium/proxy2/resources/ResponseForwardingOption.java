package org.eclipse.californium.proxy2.resources;

import org.eclipse.californium.core.coap.Option;

import com.upokecenter.cbor.CBORObject;

public class ResponseForwardingOption extends Option {

	private int tpId;
	private String srvHost;
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

	public String getSrvHost() {
		return srvHost;
	}

	public void setSrvHost(String srvHost) {
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
		arrayOut.Add(CBORObject.FromObject(srvHost).WithTag(260));
		arrayOut.Add(srvPort);

		return arrayOut.EncodeToBytes();
	}

	@Override
	public void setValue(byte[] value) {
		CBORObject arrayIn = CBORObject.DecodeFromBytes(value);
		
		setTpId(arrayIn.get(0).AsInt32Value());
		setSrvHost(arrayIn.get(1).AsString());
		
		if(arrayIn.size() > 2) {
			setSrvPort(arrayIn.get(2).AsInt32Value());
		} else {
			setSrvPort(-1);
		}
	}

}
