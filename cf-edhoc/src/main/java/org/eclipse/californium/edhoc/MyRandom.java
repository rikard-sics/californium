package org.eclipse.californium.edhoc;


public class MyRandom extends java.security.SecureRandom {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	public void nextBytes(byte[] bytes) {
		this.setSeed(10000L);
		;
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) 0xFF;
		}

	}

}
