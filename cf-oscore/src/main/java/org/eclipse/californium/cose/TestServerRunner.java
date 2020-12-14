package org.eclipse.californium.cose;

import java.security.Provider;
import java.security.Security;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

public class TestServerRunner {
    public static void main(String[] args) throws Exception {
        int a = 1;
		Provider EdDSAX = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSAX, 1); // Must be 1!

        org.eclipse.californium.cose.Tester.runme();
    }
}
