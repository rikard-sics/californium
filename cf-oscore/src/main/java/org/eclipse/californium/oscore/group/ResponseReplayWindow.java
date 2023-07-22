package org.eclipse.californium.oscore.group;

import org.eclipse.californium.oscore.ErrorDescriptions;
import org.eclipse.californium.oscore.OSException;

/**
 * Class to implement logic for replay windows for long exchanges.
 * 
 */
public class ResponseReplayWindow {

	int lowest_recipient_seq = -1;
	final int recipient_replay_window_size = 32;
	int recipient_replay_window = 0;

	/**
	 * Checks and validates the sequence number for incoming messages.
	 * 
	 * @param seq the incoming Partial IV
	 * 
	 * @throws OSException if the Partial IV is replayed
	 */
	public synchronized void checkIncoming(int piv) throws OSException {

		if (piv < lowest_recipient_seq) {
			System.err.println("Message too old");
			throw new OSException(ErrorDescriptions.REPLAY_DETECT);
		}

		// Check validity
		boolean valid = false;
		if (piv >= lowest_recipient_seq + recipient_replay_window_size) {
			valid = true;
		} else {
			valid = ((recipient_replay_window >> (piv - lowest_recipient_seq)) & 1) == 0;
		}
		if (!valid) {
			System.err.println("Replayed response message detected");
			throw new OSException(ErrorDescriptions.REPLAY_DETECT);
		}

		// Update window
		int shift = piv - (lowest_recipient_seq + recipient_replay_window_size - 1);
		if (shift > 0) {
			recipient_replay_window >>= shift;
			lowest_recipient_seq += shift;
		}
		recipient_replay_window |= 1 << (piv - lowest_recipient_seq);
	}
}
