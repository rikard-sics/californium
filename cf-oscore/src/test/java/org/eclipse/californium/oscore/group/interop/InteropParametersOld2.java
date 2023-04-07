package org.eclipse.californium.oscore.group.interop;

import org.eclipse.californium.elements.util.Bytes;

import net.i2p.crypto.eddsa.Utils;

public class InteropParametersOld2 {

	// FIXME: Update

	/* Public / private keys */

	// Set these
	public static final String RIKARD_ENTITY_1_KEY_ECDSA = "{1: 2, -1: 1, -2: h’E2A7DC0C5D23831A4F52FBFF759EF01A6B3A7D58694774D6E8505B31A351D6C4’, -3: h’F8CA44FEDC6C322D0946FC69AE7482CD066AD11F34AA5F5C63F4EADB320FD941’, -4: h’469C76F26B8D9F286449F42566AB8B8BA1B3A8DC6E711A1E2A6B548DBE2A1578’}";
	public static final String RIKARD_ENTITY_2_KEY_ECDSA = "{1: 2, -1: 1, -2: h’E2A7DC0C5D23831A4F52FBFF759EF01A6B3A7D58694774D6E8505B31A351D6C4’, -3: h’F8CA44FEDC6C322D0946FC69AE7482CD066AD11F34AA5F5C63F4EADB320FD941’, -4: h’469C76F26B8D9F286449F42566AB8B8BA1B3A8DC6E711A1E2A6B548DBE2A1578’}";
	public static final String RIKARD_ENTITY_3_KEY_ECDSA = "{1: 2, -1: 1, -2: h’E2A7DC0C5D23831A4F52FBFF759EF01A6B3A7D58694774D6E8505B31A351D6C4’, -3: h’F8CA44FEDC6C322D0946FC69AE7482CD066AD11F34AA5F5C63F4EADB320FD941’, -4: h’469C76F26B8D9F286449F42566AB8B8BA1B3A8DC6E711A1E2A6B548DBE2A1578’}";

	public static final String RIKARD_ENTITY_1_KEY_EDDSA = "";
	public static final String RIKARD_ENTITY_2_KEY_EDDSA = "";
	public static final String RIKARD_ENTITY_3_KEY_EDDSA = "";

	public static final String JIM_ENTITY_1_KEY_ECDSA = "{1: 2, 2: h'E1', -1: 1, -2: h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff', -3: h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e', -4: h'57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3'}";
	public static final String JIM_ENTITY_2_KEY_ECDSA = "{1: 2, 2: h'E2', -1: 1, -2: h'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d', -3: h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c', -4: h'aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf'}";
	public static final String JIM_ENTITY_3_KEY_ECDSA = "{1: 2, -1: 1, 2: h'E3', -2: h'98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280', -3: h'f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb', -4: h'02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3'}";

	public static final String JIM_ENTITY_1_KEY_EDDSA = "";
	public static final String JIM_ENTITY_2_KEY_EDDSA = "";
	public static final String JIM_ENTITY_3_KEY_EDDSA = "";

	/* SID / RID */

	public static final byte[] RIKARD_ENTITY_1_KID = Utils.hexToBytes("A001");
	public static final byte[] RIKARD_ENTITY_2_KID = Utils.hexToBytes("A200");
	public static final byte[] RIKARD_ENTITY_3_KID = Utils.hexToBytes("A203");

	public static final byte[] JIM_ENTITY_1_KID = Utils.hexToBytes("E1");
	public static final byte[] JIM_ENTITY_2_KID = Utils.hexToBytes("E2");
	public static final byte[] JIM_ENTITY_3_KID = Utils.hexToBytes("E3");

	/* General context settings */

	public static final byte[] MASTER_SECRET_EDDSA = Bytes.EMPTY;
	public static final byte[] MASTER_SECRET_ECDSA = Utils.hexToBytes("0102030405060708090a0b0c0d0e0f10");

	public static final byte[] MASTER_SALT_EDDSA = Bytes.EMPTY;
	public static final byte[] MASTER_SALT_ECDSA = Utils.hexToBytes("9e7ca92223786340");

	public static final byte[] GROUP_ID_EDDSA = Bytes.EMPTY;
	public static final byte[] GROUP_ID_ECDSA = Utils.hexToBytes("0A0B0C");

}
