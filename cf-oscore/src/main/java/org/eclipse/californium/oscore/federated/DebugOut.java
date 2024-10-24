package org.eclipse.californium.oscore.federated;

public class DebugOut {

	public static boolean ENABLE_PRINTING = true;

	static void println(Object str) {
		if (ENABLE_PRINTING) {
			System.out.println(str);
		} else {
			;
		}
	}

	static void println() {
		if (ENABLE_PRINTING) {
			System.out.println();
		} else {
			;
		}
	}

	static void print(Object str) {
		if (ENABLE_PRINTING) {
			System.out.print(str);
		} else {
			;
		}
	}

	static void errPrintln(Object str) {
		if (ENABLE_PRINTING) {
			System.err.println(str);
		} else {
			;
		}
	}
}
