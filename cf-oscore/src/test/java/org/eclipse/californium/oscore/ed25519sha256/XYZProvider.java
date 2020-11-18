package org.eclipse.californium.oscore.ed25519sha256;

import java.security.Provider;

//https://docstore.mik.ua/orelly/java-ent/security/ch08_01.htm
public class XYZProvider extends Provider {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public XYZProvider() {
		super("XYZ", 1.0, "XYZ Security Provider v1.0");
		put("MessageDigest.XYZ", "org.eclipse.californium.oscore.ed25519sha256.XYZMessageDigest");
	}
}