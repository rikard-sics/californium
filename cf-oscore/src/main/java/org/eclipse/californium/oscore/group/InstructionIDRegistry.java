package org.eclipse.californium.oscore.group;

public final class InstructionIDRegistry {
	public static final int StartIndex = 2;
	
	public static final int PairwiseMode = 1;
	public static final int ContextUri = 2;
	public static final int KID = 3;
	public static final int IDContext = 5;
	public static final int PreSet = 6;
	public static final int PostSet = 7;
	public static final int RequestSequenceNumber = 8;
	public static final int Break = 9;
	
	public final class Header {
		public static final int OscoreOptionValue = 0;
		public static final int Index = 1;
	}
}