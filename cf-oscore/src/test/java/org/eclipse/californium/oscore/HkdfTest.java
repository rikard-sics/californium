package org.eclipse.californium.oscore;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.eclipse.californium.elements.util.StringUtil;
import org.junit.Assert;
import org.junit.Test;

/**
 * Class to test HKDF-Expand (with SHA256) using test vectors from
 * https://www.rfc-editor.org/rfc/rfc5869#appendix-A
 * 
 *
 */
public class HkdfTest {

	/**
	 * https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	public void testHkdfVectorA1() throws InvalidKeyException, NoSuchAlgorithmException {
		byte[] okmCorrect = StringUtil
				.hex2ByteArray("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

		byte[] prk = StringUtil.hex2ByteArray("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
		byte[] info = StringUtil.hex2ByteArray("f0f1f2f3f4f5f6f7f8f9");
		int L = 42;

		byte[] okm = KudosRederivation.hkdfExpand(prk, info, L);

		Assert.assertArrayEquals("Incorrect OKM", okmCorrect, okm);
	}

	/**
	 * https://www.rfc-editor.org/rfc/rfc5869#appendix-A.2
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	public void testHkdfVectorA2() throws InvalidKeyException, NoSuchAlgorithmException {
		byte[] okmCorrect = StringUtil.hex2ByteArray(
				"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");

		byte[] prk = StringUtil.hex2ByteArray("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
		byte[] info = StringUtil.hex2ByteArray(
				"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
		int L = 82;

		byte[] okm = KudosRederivation.hkdfExpand(prk, info, L);

		Assert.assertArrayEquals("Incorrect OKM", okmCorrect, okm);
	}

	/**
	 * https://www.rfc-editor.org/rfc/rfc5869#appendix-A.3
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	public void testHkdfVectorA3() throws InvalidKeyException, NoSuchAlgorithmException {
		byte[] okmCorrect = StringUtil
				.hex2ByteArray("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

		byte[] prk = StringUtil.hex2ByteArray("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
		byte[] info = new byte[0];
		int L = 42;

		byte[] okm = KudosRederivation.hkdfExpand(prk, info, L);

		Assert.assertArrayEquals("Incorrect OKM", okmCorrect, okm);
	}

}
