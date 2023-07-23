package org.eclipse.californium.oscore.group;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Scanner;

import org.eclipse.californium.elements.util.StringUtil;

public class PacketInjectorBasic {

	public static void main(String[] args) throws UnknownHostException, SocketException, IOException {
		String message = "5844e3fd5e45afe9174cf6f293290052ffee4c3580c6f7b062d05ebfe529c5c7c7049d4d367658f006a66bb4165e2099ba07be25cc793ade69e9dc97a13a01b336942eba56b75dd4e3eeeb233a534af60b1cabde3c960b6a4b5c7865d45845962ff7e83a968c9277a2";

		Scanner sc = new Scanner(System.in);
		System.out.println("Enter Token: ");
		String newToken = sc.nextLine();
		message = message.replace("5e45afe9174cf6f2", newToken);

		System.out.println("Enter Dstport: ");
		String dstPortStr = sc.nextLine();
		int dstPort = Integer.parseInt(dstPortStr);
		sc.close();

		byte[] buffer = StringUtil.hex2ByteArray(message);


		InetAddress address = InetAddress.getByName("31.133.128.149");
		DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, dstPort);
		DatagramSocket datagramSocket = new DatagramSocket(5683, address);
		datagramSocket.send(packet);
		System.out.println(InetAddress.getLocalHost().getHostAddress());
	}
}
