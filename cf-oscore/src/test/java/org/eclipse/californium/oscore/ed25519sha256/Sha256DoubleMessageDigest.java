package org.eclipse.californium.oscore.ed25519sha256;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.eclipse.californium.elements.util.Bytes;

//https://docstore.mik.ua/orelly/java-ent/security/ch09_03.htm
public class Sha256DoubleMessageDigest extends MessageDigest implements Cloneable {

	private MessageDigest sha256Internal;

	public Sha256DoubleMessageDigest() {
		super("Sha256Double");
		try {
			sha256Internal = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		engineReset();
	}

	public void engineUpdate(byte b) {
		sha256Internal.update(b);
	}

	public void engineUpdate(byte b[], int offset, int length) {
		sha256Internal.update(b, offset, length);
	}

	public void engineReset() {
		sha256Internal.reset();
	}

	public byte[] engineDigest() {
		byte[] result = sha256Internal.digest();
		engineReset();

		byte[] resultDouble = Bytes.concatenate(result, result);

		return resultDouble;
	}
}