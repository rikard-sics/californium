package org.eclipse.californium.oscore.group;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.ByteId;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class implementing functionality for Group OSCORE dynamic context derivation.
 * If a request is received where there is no matching recipient context one may
 * be derived dynamically.
 *
 */
public class GroupDynamicContextDerivation {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(GroupDynamicContextDerivation.class);

	/**
	 * Perform dynamic context derivation for Group OSCORE.
	 * 
	 * @param db the context database used
	 * @param rid the RID of the sender of the request
	 * @param contextID the context ID in the request
	 * @return a newly derived recipient context
	 */
	public static OSCoreCtx derive(OSCoreCtxDB db, byte[] rid, byte[] contextID) {
		// Check if we have a public key for this RID
	
		// First get the Sender Context for this request
		OSCoreCtx ctx = db.getContextByIDContext(contextID);
	
		// Abort the procedure for non Group OSCORE sender contexts
		if (ctx == null || ctx instanceof GroupSenderCtx == false) {
			LOGGER.error("Dynamic context derivation failed: No context found for ID Context"
					+ Utils.toHexString(contextID));
			return null;
		}

		LOGGER.debug("Attempting dynamic context derivation for: " + Utils.toHexString(contextID) + ":"
				+ Utils.toHexString(rid));

		// Abort if we do not have a public key for this rid
		GroupSenderCtx senderCtx = (GroupSenderCtx) ctx;
		OneKey publicKey = senderCtx.commonCtx.getPublicKeyForRID(rid);
		if (publicKey == null) {
			LOGGER.error("Dynamic context derivation failed: No public key found for RID " + Utils.toHexString(rid));
			return null;
		}
	
		// Now add the new recipient context
		try {
			senderCtx.commonCtx.addRecipientCtx(rid, 32, publicKey);
		} catch (OSException e) {
			LOGGER.error("Dynamic context derivation failed: Failed to add generated context");
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
