/*******************************************************************************
 * Copyright (c) 2023 RISE SICS and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 * 
 * Contributors: 
 *    Rikard Höglund (RISE SICS)
 ******************************************************************************/
package org.eclipse.californium.oscore.group.interop;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * https://github.com/ace-wg/Hackathon-109/blob/master/GroupDerivation.md
 *
 */
public class InteropParametersOld {

	/* Public / private keys */

	public static final String RIKARD_ENTITY_1_KEY_ECDSA = "{1: 2, 2: h'01', -4: h'FEA2190084748436543C5EC8E329D2AFBD7068054F595CA1F987B9E43E2205E6', -3: h'64CE3DD128CC4EFA6DE209BE8ABD111C7272F612C2DB654057B6EC00FBFB0684', -2: h'1ADB2AB6AF48F17C9877CF77DB4FA39DC0923FBE215E576FE6F790B1FF2CBC96', -1: 1}";
	public static final String RIKARD_ENTITY_2_KEY_ECDSA = "{1: 2, 2: h'', -4: h'DA2593A6E0BCC81A5941069CB76303487816A2F4E6C0F21737B56A7C90381597', -3: h'1897A28666FE1CC4FACEF79CC7BDECDC271F2A619A00844FCD553A12DD679A4F', -2: h'0EB313B4D314A1001244776D321F2DD88A5A31DF06A6EEAE0A79832D39408BC1', -1: 1}";
	public static final String RIKARD_ENTITY_3_KEY_ECDSA = "{1: 2, 2: h'AA', -4: h'BF31D3F9670A7D1342259E700F48DD9983A5F9DF80D58994C667B6EBFD23270E', -3: h'5694315AD17A4DA5E3F69CA02F83E9C3D594712137ED8AFB748A70491598F9CD', -2: h'FAD4312A45F45A3212810905B223800F6CED4BC8D5BACBC8D33BB60C45FC98DD', -1: 1}";

	public static final String RIKARD_ENTITY_1_KEY_EDDSA = "{1: 1, 2: h'0A', -4: h'397CEB5A8D21D74A9258C20C33FC45AB152B02CF479B2E3081285F77454CF347', -2: h'CE616F28426EF24EDB51DBCEF7A23305F886F657959D4DF889DDFC0255042159', -1: 6}";
	public static final String RIKARD_ENTITY_2_KEY_EDDSA = "{1: 1, 2: h'51', -4: h'70559B9EECDC578D5FC2CA37F9969630029F1592AFF3306392AB15546C6A184A', -2: h'2668BA6CA302F14E952228DA1250A890C143FDBA4DAED27246188B9E42C94B6D', -1: 6}";
	public static final String RIKARD_ENTITY_3_KEY_EDDSA = "{1: 1, 2: h'52', -4: h'E550CD532B881D52AD75CE7B91171063E568F2531FBDFB32EE01D1910BCF810F', -2: h'5394E43633CDAC96F05120EA9F21307C9355A1B66B60A834B53E9BF60B1FB7DF', -1: 6}";

	public static final String JS_ENTITY_1_KEY_ECDSA = "{1: 2, 2: h'E1', -1: 1, -2: h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', -3: h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', -4: h'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3'}";
	public static final String JS_ENTITY_2_KEY_ECDSA = "{1: 2, 2: h'E2', -1: 1, -2: h'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d', -3: h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c', -4: h'aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf'}";
	public static final String JS_ENTITY_3_KEY_ECDSA = "{1: 2, -1: 1, 2: h'E3', -2: h'98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280', -3: h'f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb', -4: h'02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3'}";

	// public static final String JS_ENTITY_1_KEY_EDDSA = "";
	// public static final String JS_ENTITY_2_KEY_EDDSA = "";
	// public static final String JS_ENTITY_3_KEY_EDDSA = "";

	/* SID / RID */

	public static final byte[] RIKARD_ENTITY_1_KID_ECDSA = StringUtil.hex2ByteArray("01");
	public static final byte[] RIKARD_ENTITY_2_KID_ECDSA = Bytes.EMPTY;
	public static final byte[] RIKARD_ENTITY_3_KID_ECDSA = StringUtil.hex2ByteArray("AA");

	public static final byte[] JS_ENTITY_1_KID_ECDSA = StringUtil.hex2ByteArray("E1");
	public static final byte[] JS_ENTITY_2_KID_ECDSA = StringUtil.hex2ByteArray("E2");
	public static final byte[] JS_ENTITY_3_KID_ECDSA = StringUtil.hex2ByteArray("E3");

	public static final byte[] RIKARD_ENTITY_1_KID_EDDSA = StringUtil.hex2ByteArray("0A");
	public static final byte[] RIKARD_ENTITY_2_KID_EDDSA = StringUtil.hex2ByteArray("51");
	public static final byte[] RIKARD_ENTITY_3_KID_EDDSA = StringUtil.hex2ByteArray("52");

	// public static final byte[] JS_ENTITY_1_KID_EDDSA =
	// StringUtil.hex2ByteArray("E1");
	// public static final byte[] JS_ENTITY_2_KID_EDDSA =
	// StringUtil.hex2ByteArray("E2");
	// public static final byte[] JS_ENTITY_3_KID_EDDSA =
	// StringUtil.hex2ByteArray("E3");

	/* General context settings */

	public static final byte[] JS_MASTER_SECRET_ECDSA = StringUtil.hex2ByteArray("0102030405060708090a0b0c0d0e0f10");
	public static final byte[] JS_MASTER_SALT_ECDSA = StringUtil.hex2ByteArray("9e7ca92223786340");
	public static final byte[] JS_GROUP_ID_ECDSA = StringUtil.hex2ByteArray("0A0B0C"); // 09EDDA

	public static final byte[] RIKARD_MASTER_SECRET_ECDSA = StringUtil
			.hex2ByteArray("0102030405060708090a0b0c0d0e0f10");
	public static final byte[] RIKARD_MASTER_SALT_ECDSA = StringUtil.hex2ByteArray("9e7ca92223786340");
	public static final byte[] RIKARD_GROUP_ID_ECDSA = StringUtil.hex2ByteArray("37cbf3210017a2d3");

	public static final byte[] RIKARD_MASTER_SECRET_EDDSA = StringUtil
			.hex2ByteArray("11223344556677889900AABBCCDDEEFF");
	public static final byte[] RIKARD_MASTER_SALT_EDDSA = StringUtil.hex2ByteArray("1F2E3D4C5B6A7081");
	public static final byte[] RIKARD_GROUP_ID_EDDSA = StringUtil.hex2ByteArray("DD11");

	public static final String PVDS_PUBLIC_KEY_EDDSA = "{1: 1, 2: h'0A', -2: h'f10c06d527ecefdcf1511710186a3bccf94c2a4eb4719a3748afdcef43f319c4', -1: 6}";

}
