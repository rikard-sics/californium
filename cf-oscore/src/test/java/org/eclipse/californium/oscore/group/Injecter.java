package org.eclipse.californium.oscore.group;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Scanner;

import org.eclipse.californium.elements.util.StringUtil;

public class Injecter {

	public static void main(String[] args) throws UnknownHostException, SocketException, IOException {
		String message = "5844e2790a5198cd2edc495e93290052ffee4c3580c6f7b062d05ebfe529c8cfa2d73e471762ea385f06009690bcb1c2b459ddc454095a0c2f77105e6630b4a3e91126eecf20067e8549b6aa51fd143165c234adf637a96b44454750a7b0d70900c40f2137287fa1";

		Scanner sc = new Scanner(System.in);
		System.out.println("Enter Token: ");
		String newToken = sc.nextLine();
		message.replace("0a5198cd2edc495e", newToken);

		System.out.println("Enter Dstport: ");
		String dstPortStr = sc.nextLine();
		int dstPort = Integer.parseInt(dstPortStr);

		byte[] buffer = StringUtil.hex2ByteArray(message);


		InetAddress address = InetAddress.getByName("31.133.128.149");
		DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, dstPort);
		DatagramSocket datagramSocket = new DatagramSocket(5683, address);
		datagramSocket.send(packet);
		System.out.println(InetAddress.getLocalHost().getHostAddress());
	}
}
