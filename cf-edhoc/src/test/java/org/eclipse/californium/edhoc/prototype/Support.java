package org.eclipse.californium.edhoc.prototype;

import java.io.IOException;

public class Support {

	/**
	 * Simple method for "press enter to continue" functionality
	 */
	static void printPause(String message) {

		System.out.println("===");
		System.out.println(message);
		System.out.println("Press ENTER to continue");
		System.out.println("===");
		try {
			@SuppressWarnings("unused")
			int read = System.in.read(new byte[2]);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	static void printIfNotNull(String str) {
		if (str != null) {
			System.out.println(str);
		}
	}
}
