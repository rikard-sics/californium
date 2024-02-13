package org.eclipse.californium.oscore.federated;

import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.elements.util.StringUtil;

public class Credentials {

	/**
	 * Map with the Sender IDs of the servers
	 */
	public static Map<Integer, byte[]> serverSenderIds;
	static {
		serverSenderIds = new HashMap<>();
		serverSenderIds.put(0, new byte[] { (byte) 0x01 });
		serverSenderIds.put(1, new byte[] { (byte) 0x02 });
		serverSenderIds.put(2, new byte[] { (byte) 0x03 });
		serverSenderIds.put(3, new byte[] { (byte) 0x04 });
		serverSenderIds.put(4, new byte[] { (byte) 0x05 });
		serverSenderIds.put(5, new byte[] { (byte) 0x06 });
		serverSenderIds.put(6, new byte[] { (byte) 0x07 });
		serverSenderIds.put(7, new byte[] { (byte) 0x08 });
		serverSenderIds.put(8, new byte[] { (byte) 0x09 });
		serverSenderIds.put(9, new byte[] { (byte) 0x0A });
		serverSenderIds.put(10, new byte[] { (byte) 0x0B });
	}

	/**
	 * Map with public keys (CCS) for the servers
	 */
	public static Map<Integer, byte[]> serverPublicKeys;
	static {
		serverPublicKeys = new HashMap<>();
		serverPublicKeys.put(0, StringUtil.hex2ByteArray(
				"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B"));
		serverPublicKeys.put(1, StringUtil.hex2ByteArray(
				"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820105B8C6A8C88019BF0C354592934130BAA8007399CC2AC3BE845884613D5BA2E"));
		serverPublicKeys.put(2, StringUtil.hex2ByteArray(
				"A20267436C69656E743108A101A40101032720062158202FA0554A203C150E771E19AD14D8EB90349579325096B132E3A42DD3E6721BE4"));
		serverPublicKeys.put(3, StringUtil.hex2ByteArray(
				"A20267436C69656E743208A101A4010103272006215820C80240E84F3CB886D841DA6F71140F8578E7E27808672DF08521830AE1300F54"));
		serverPublicKeys.put(4, StringUtil.hex2ByteArray(
				"A202675365727665723108A101A4010103272006215820A42794D9EADBE3A7327FB1997A80E648ECF88C876FEE2FBAD53B1B7266C0237D"));
		serverPublicKeys.put(5, StringUtil.hex2ByteArray(
				"A202675365727665723208A101A4010103272006215820158EDB53F4373EC2FF1BA1844A1B94E2A9E9E7AE96CB15455E0AEB0475AE5481"));
		serverPublicKeys.put(6, StringUtil.hex2ByteArray(
				"A202675365727665723308A101A40101032720062158205239AE299D02615D9EF210CBD263A2E3026A868C991EB7A20AB7E40804CF4D6C"));
		serverPublicKeys.put(7, StringUtil.hex2ByteArray(
				"A202675365727665723408A101A40101032720062158208ED61CBEAD281DD16FD086280B207AD3FB706DF23E37BC43A00DF13047E4CDC4"));
		serverPublicKeys.put(8, StringUtil.hex2ByteArray(
				"A202675365727665723508A101A40101032720062158204F8D92825564057CEAAF1CC8C2ABAD0F0542BEA9A6E171BD9C7086138AF885FB"));
		serverPublicKeys.put(9, StringUtil.hex2ByteArray(
				"A202675365727665723608A101A401010327200621582003409CBD38DC73250E79B9F627739ECD78CC89651E89929983FAF8BFC94FDCA2"));
		serverPublicKeys.put(10, StringUtil.hex2ByteArray(
				"A2026941647665727361727908A101A40101032720062158208ED61CBEAD281DD16FD086280B207AD3FB706DF23E37BC43A00DF13047E4CDC4"));
	}

	/**
	 * Map with private keys for the servers
	 */
	public static Map<Integer, byte[]> serverPrivateKeys;
	static {
		serverPrivateKeys = new HashMap<>();
		serverPrivateKeys.put(0,
				StringUtil.hex2ByteArray("857EB61D3F6D70A278A36740D132C099F62880ED497E27BDFD4685FA1A304F26"));
		serverPrivateKeys.put(1,
				StringUtil.hex2ByteArray("7BF62F767ED1CF4C60911FC49FDFCCB9BD47CC7E9FAF41CB66369D5C8508B239"));
		serverPrivateKeys.put(2,
				StringUtil.hex2ByteArray("82C027A023FB522BA6B8565C73056A02BFC7C26DC89969CA15207B8FCB27A2AA"));
		serverPrivateKeys.put(3,
				StringUtil.hex2ByteArray("7D428B2549E7997E8D8833A17BDA1E09B65C9FDC0F69287F376D7DCE882E1C3F"));
		serverPrivateKeys.put(4,
				StringUtil.hex2ByteArray("77561F3438E381214F176493C01AAE1514C9D3FC05070C6026D00CBC669A86AF"));
		serverPrivateKeys.put(5,
				StringUtil.hex2ByteArray("EA67E40CA8E0770E9CF1EC2FDA7B2D926BBFB6CE704B2E261C751A5218B816C3"));
		serverPrivateKeys.put(6,
				StringUtil.hex2ByteArray("D2C6B58FAD471EDB3E17C742A332F877CEB8CE4FFB8547951BC4A9FBCF6427AA"));
		serverPrivateKeys.put(7,
				StringUtil.hex2ByteArray("A90B7D8A9E6D32DDFC794494D446F0E56505094203209BEF64A6800CF35F3988"));
		serverPrivateKeys.put(8,
				StringUtil.hex2ByteArray("B414D24D3D45D0AFA4172EE66CEC88685AFEB4FF011A9C04C0AB4CEC763616E9"));
		serverPrivateKeys.put(9,
				StringUtil.hex2ByteArray("F444DF1A8899E2C3733F391823A492B4607489820D0304530D15A2BB6B746D9A"));
		serverPrivateKeys.put(10,
				StringUtil.hex2ByteArray("A90B7D8A9E6D32DDFC794494D446F0E56505094203209BEF64A6800CF35F3988"));
	}
	
	/**
	 * Map with the Dataset ID of the servers
	 */
	public static Map<Integer, String> serverDatasets;
	static {
		serverDatasets = new HashMap<>();
		serverDatasets.put(0, "dataset_c1.csv");
		serverDatasets.put(1, "dataset_c2.csv");
		serverDatasets.put(2, "dataset_c3.csv");
		serverDatasets.put(3, "dataset_c4.csv");
		serverDatasets.put(4, "dataset_c5.csv");
		serverDatasets.put(5, "dataset_c1.csv");
		serverDatasets.put(6, "dataset_c2.csv");
		serverDatasets.put(7, "dataset_c3.csv");
		serverDatasets.put(8, "dataset_c4.csv");
		serverDatasets.put(9, "dataset_c5.csv");
		serverDatasets.put(10, "dataset_c1.csv");
	}
}
