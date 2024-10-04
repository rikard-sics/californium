package org.eclipse.californium.oscore.federated;

import java.nio.ByteBuffer;

/**
 * Class with methods for converting Java floats to byte arrays and vice-versa.
 * 
 * floatVectorToBytes and bytesToFloatVector can be used to do the conversion in
 * both directions. The methods can either use 32 bits or 16 bites for each
 * float value.
 */
public class FloatConverter {

	private static final int FLOAT_SIZE = Float.SIZE / 8;
	private static final int SHORT_SIZE = Short.SIZE / 8;
	private static final float SHORT_MAX = 32767.0F;

	private static final int BITS_PER_FLOAT = 32;

	/**
	 * Convert a Java array of float values to a sequence of bytes in a byte
	 * array.
	 * 
	 * @param vector the Java array with float values
	 * @return a byte array with a byte sequence representing the float values
	 */
	public static byte[] floatVectorToBytes(float[] vector) {

		switch (BITS_PER_FLOAT) {
		case 16:
			return floatVectorToBytesQuant(vector);
		case 32:
			return floatVectorToBytesNorm(vector);
		default:
			return null;
		}

	}

	/**
	 * Convert a sequence of bytes in a byte array to a Java array of float
	 * values.
	 * 
	 * @param bytes byte array with bytes representing the float values
	 * @return Java array with float values
	 */
	public static float[] bytesToFloatVector(byte[] bytes) {

		switch (BITS_PER_FLOAT) {
		case 16:
			return bytesToFloatVectorQuant(bytes);
		case 32:
			return bytesToFloatVectorNorm(bytes);
		default:
			return null;
		}

	}

	/* === Private methods below === */

	/**
	 * Convert a Java array of float values to a sequence of bytes in a byte
	 * array. Stores each float as 32 bits.
	 * 
	 * @param vector the Java array with float values
	 * @return a byte array with a byte sequence representing the float values
	 */
	private static byte[] floatVectorToBytesNorm(float[] vector) {

		int numElements = vector.length;
		byte[] resBytes = new byte[FLOAT_SIZE * numElements];

		for (int i = 0; i < numElements; i++) {
			byte[] elementBytes = ByteBuffer.allocate(FLOAT_SIZE).putFloat(vector[i]).array();
			System.arraycopy(elementBytes, 0, resBytes, i * FLOAT_SIZE, FLOAT_SIZE);
		}

		return resBytes;
	}

	/**
	 * Convert a sequence of bytes in a byte array to a Java array of float
	 * values. Reads 32 bits for each float.
	 * 
	 * @param bytes byte array with bytes representing the float values
	 * @return Java array with float values
	 */
	private static float[] bytesToFloatVectorNorm(byte[] bytes) {

		int numElements = bytes.length / FLOAT_SIZE;
		float[] resVector = new float[numElements];

		for (int i = 0; i < numElements; i++) {
			byte[] elementBytes = new byte[FLOAT_SIZE];
			System.arraycopy(bytes, i * FLOAT_SIZE, elementBytes, 0, FLOAT_SIZE);
			resVector[i] = ByteBuffer.wrap(elementBytes).getFloat();
		}

		return resVector;
	}

	/**
	 * Convert a Java array of float values to a sequence of bytes in a byte
	 * array. Stores each float as 16 bits.
	 * 
	 * @param vector the Java array with float values
	 * @return a byte array with a byte sequence representing the float values
	 */
	private static byte[] floatVectorToBytesQuant(float[] vector) {

		int numElements = vector.length;
		byte[] resBytes = new byte[SHORT_SIZE * numElements];

		for (int i = 0; i < numElements; i++) {
			short currentVal = (short) Math.round(vector[i] * SHORT_MAX);
			byte[] elementBytes = ByteBuffer.allocate(SHORT_SIZE).putShort(currentVal).array();
			System.arraycopy(elementBytes, 0, resBytes, i * SHORT_SIZE, SHORT_SIZE);
		}

		return resBytes;
	}

	/**
	 * Convert a sequence of bytes in a byte array to a Java array of float
	 * values. Reads 16 bits for each float.
	 * 
	 * @param bytes byte array with bytes representing the float values
	 * @return Java array with float values
	 */
	private static float[] bytesToFloatVectorQuant(byte[] bytes) {

		int numElements = bytes.length / SHORT_SIZE;
		float[] resVector = new float[numElements];

		for (int i = 0; i < numElements; i++) {
			byte[] elementBytes = new byte[SHORT_SIZE];
			System.arraycopy(bytes, i * SHORT_SIZE, elementBytes, 0, SHORT_SIZE);
			short currentVal = ByteBuffer.wrap(elementBytes).getShort();
			resVector[i] = currentVal / SHORT_MAX;
		}

		return resVector;
	}

	@SuppressWarnings("unused")
	private static void test(String[] args) {

		float[] testValues = new float[] { 0.3215081190455081F, -0.657086320195086320F, -1.0F, 0.714084413092130F,
				-0.908047338626733F, 1.0F, 0.0199900075962007F, -0.90405854583340585F, 0.3159249550634955F,
				-0.69696595801996595F, 0.9382401368324013F, 0.0F, 0.48420742575942F, 0.1F, 0.25F, 0.5F, 0.75F, 0.8F,
				0.9F, 0.99F, 0.999F, 0.123456789101112F };

		byte[] convertedBytes = floatVectorToBytesNorm(testValues);
		float[] reconvertedValues = bytesToFloatVectorNorm(convertedBytes);

		byte[] convertedBytes16 = floatVectorToBytesQuant(testValues);
		float[] reconvertedValues16 = bytesToFloatVectorQuant(convertedBytes16);

		System.out.println("convertedBytes.length " + convertedBytes.length);
		System.out.println("convertedBytes16.length " + convertedBytes16.length);

		float diffSum = 0;
		for (int i = 0; i < testValues.length; i++) {
			System.out.println(testValues[i]);
			System.out.println(reconvertedValues[i]);
			System.out.println(reconvertedValues16[i]);

			diffSum += Math.abs(reconvertedValues[i] - reconvertedValues16[i]);
			System.out.println();
		}
		System.out.println();
		System.out.println(diffSum);

	}
}
