package org.eclipse.californium.oscore.group;


import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;

import com.upokecenter.cbor.CBORObject;

public class AppConfigReceiver {

	private static Properties props = new Properties();

	private static final String configFilename = "receiver_config.properties";

	static {
		try (FileInputStream fis = new FileInputStream(configFilename)) {
			props.load(fis);
		} catch (IOException e) {
			throw new RuntimeException("Failed to load config.properties", e);
		}
	}

	public static boolean getBoolean(String key) {
		return Boolean.parseBoolean(props.getProperty(key));
	}

	public static int getInt(String key) {
		return Integer.parseInt(props.getProperty(key));
	}

	public static String getString(String key) {
		return props.getProperty(key);
	}

	public static AlgorithmID getAlg(String key) {
		try {
			return AlgorithmID.FromCBOR(CBORObject.FromObject(AppConfigReceiver.getInt(key)));
		} catch (CoseException e) {
			System.err.println("Failed to parse algorithm in config file");
			e.printStackTrace();
		}
		return null;
	}

	public static InetAddress getInetAddress(String key) {
		try {
			return InetAddress.getByName(getString(key));
		} catch (UnknownHostException e) {
			throw new RuntimeException("Invalid IP address in config for key: " + key, e);
		}
	}

	public static byte[] getHexByteArray(String key) {
		String hex = props.getProperty(key);
		if (hex == null || hex.isEmpty())
			return new byte[0];
		int len = hex.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
		}
		return data;
	}
}

