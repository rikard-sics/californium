package org.eclipse.californium.oscore.ed25519sha256;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

//https://docstore.mik.ua/orelly/java-ent/security/ch09_03.htm
public class Sha512OwnMessageDigest extends MessageDigest implements Cloneable {

	private MessageDigest sha512Internal;

	public Sha512OwnMessageDigest() {
		super("Sha512Own");
		try {
			sha512Internal = MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		engineReset();
	}

	public void engineUpdate(byte b) {
		sha512Internal.update(b);
	}

	public void engineUpdate(byte b[], int offset, int length) {
		sha512Internal.update(b, offset, length);
	}

	public void engineReset() {
		sha512Internal.reset();
	}

	public byte[] engineDigest() {
		return sha512Internal.digest();
	}
}