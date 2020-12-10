package org.eclipse.californium.cose;

import java.security.Provider;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import java.security.Security;

public class TestClientRunner {
    public static void main(String[] args) throws Exception {
        int a = 1;
        Provider EdDSAX = new EdDSASecurityProvider();
        Security.insertProviderAt(EdDSAX, 1); // Must be 1!

        org.eclipse.californium.cose.TestClient.runme(new String[] { "a" });
    }
}
