package org.eclipse.californium.oscore.group;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.ByteId;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GroupDynamicContextDerivation {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(GroupDynamicContextDerivation.class);

	/**
	 * Perform dynamic context derivation for Group OSCORE.
	 * 
	 * @param db
	 * @param request
	 * @param rid
	 * @param kidContext
	 */
	public static OSCoreCtx derive(OSCoreCtxDB db, byte[] rid, byte[] contextID) {
		// Check if we have a public key for this RID
	
		// First get the Sender Context for this request
		OSCoreCtx ctx = db.getContextByIDContext(contextID);
	
		// Abort the procedure for non Group OSCORE sender contexts
		if (ctx == null || ctx instanceof GroupSenderCtx == false) {
			return null;
		}

		LOGGER.debug("Attempting dynamic context derivation for: " + Utils.toHexString(contextID) + ":"
				+ Utils.toHexString(rid));

		// Abort if we do not have a public key for this rid
		GroupSenderCtx senderCtx = (GroupSenderCtx) ctx;
		OneKey publicKey = senderCtx.commonCtx.getPublicKeyForRID(rid);
		if (publicKey == null) {
			return null;
		}
	
		// Now add the new recipient context
		try {
			senderCtx.commonCtx.addRecipientCtx(rid, 32, publicKey);
		} catch (OSException e) {
			LOGGER.error("Dynamic context derivation failed!");
			e.printStackTrace();
		}
		GroupRecipientCtx recipientCtx = senderCtx.commonCtx.recipientCtxMap.get(new ByteId(rid));
		db.addContext(recipientCtx);
		
		//Derive pairwise keys
		senderCtx.derivePairwiseKeys();
		recipientCtx.derivePairwiseKey();
		
		LOGGER.debug("Dynamic context derivation finished successfully");

		return recipientCtx;
	}

}
