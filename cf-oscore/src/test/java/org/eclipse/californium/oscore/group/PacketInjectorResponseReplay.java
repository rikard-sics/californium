package org.eclipse.californium.oscore.group;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Scanner;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Application for testing replays of responses. Use together with the
 * GroupOSCORESender application. Note that the appropriate Token value of the
 * request, and the source port of the request must be found (for instance using
 * Wireshark) and provided to this application.
 * 
 * It is also recommended to increase the HANDLER_TIMEOUT in GroupOSCORESender,
 * to at least 60 seconds, in order to have sufficient time.
 * 
 * This application itself injects 3 messages in the following order:
 * 
 * 1. Response with PIV2 (should work) 2. Response with PIV1 (should work) 3.
 * Response with PIV1 (should NOT work)
 * 
 */
public class PacketInjectorResponseReplay {

	public static void main(String[] args) throws UnknownHostException, SocketException, IOException {
		String message = "5844e3fd5e45afe9174cf6f293290052ffee4c3580c6f7b062d05ebfe529c5c7c7049d4d367658f006a66bb4165e2099ba07be25cc793ade69e9dc97a13a01b336942eba56b75dd4e3eeeb233a534af60b1cabde3c960b6a4b5c7865d45845962ff7e83a968c9277a2";

		String responsePIV2 = "5844d473be1e2433f1f0d0c893290252ffb3d836cf50afccaf5e61e8cf42ed388e3971f95f7f3b2dea972eff122383aeb2a8ea2bd7df88cb5b51c9f2a4342c67ba17763420b6c69668efeaa4646e8414cbf8da7613526b61ad20cbe36e04f70a6e5ab638eaedf90ec4";
		String tokenPIV2 = "be1e2433f1f0d0c8";

		String responsePIV1 = "5844ea070e1333493a81a16293290152ff6e0a50a3d8db586ab546ee34569f47fdef41f24a5a7f8dde0ab6d0850d088db6a77349dcc8f913dcc2e29c1eade92b14e6cccc3d05778e3d8f40ed4604d7f824a380943020342ff498cc4f6fc897fb802cd5cf08aed1736c";
		String tokenPIV1 = "0e1333493a81a162";

		Scanner sc = new Scanner(System.in);
		System.out.println("Enter Token: ");
		String newToken = sc.nextLine();
		responsePIV2 = responsePIV2.replace(tokenPIV2, newToken);
		responsePIV1 = responsePIV1.replace(tokenPIV1, newToken);

		System.out.println("Enter Dstport: ");
		String dstPortStr = sc.nextLine();
		int dstPort = Integer.parseInt(dstPortStr);
		sc.close();

		// Send response with PIV2
		byte[] buffer = StringUtil.hex2ByteArray(responsePIV2);
		InetAddress address = InetAddress.getByName("31.133.128.149");
		DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, dstPort);
		DatagramSocket datagramSocket = new DatagramSocket(5683, address);
		datagramSocket.send(packet);
		System.out.println(InetAddress.getLocalHost().getHostAddress());

		// Send response with PIV1
		buffer = StringUtil.hex2ByteArray(responsePIV1);
		address = InetAddress.getByName("31.133.128.149");
		packet = new DatagramPacket(buffer, buffer.length, address, dstPort);
		// datagramSocket = new DatagramSocket(5683, address);
		datagramSocket.send(packet);
		System.out.println(InetAddress.getLocalHost().getHostAddress());

		// Send response with PIV1
		buffer = StringUtil.hex2ByteArray(responsePIV1);
		address = InetAddress.getByName("31.133.128.149");
		packet = new DatagramPacket(buffer, buffer.length, address, dstPort);
		// datagramSocket = new DatagramSocket(5683, address);
		datagramSocket.send(packet);
		System.out.println(InetAddress.getLocalHost().getHostAddress());
	}
}
