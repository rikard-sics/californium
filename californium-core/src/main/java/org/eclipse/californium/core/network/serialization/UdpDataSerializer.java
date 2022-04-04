/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Matthias Kovatsch - creator and main architect
 * Martin Lanter - architect and re-implementation
 * Dominique Im Obersteg - parsers and initial implementation
 * Daniel Pauli - parsers and initial implementation
 * Kai Hudalla - logging
 * Bosch Software Innovations GmbH - turn into utility class with static methods only
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The DataSerialized serializes outgoing messages to byte arrays.
 */
public final class UdpDataSerializer extends DataSerializer {
	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(UdpDataSerializer.class);

	static int messageCounter = 0;
	// Outgoing
	private static final String[] MESSAGES = { "EDHOC Message #1", "EDHOC Message #3", "OSCORE Request #1" };

	static String phase = "";
	public static void setPhase(String inPhase) {
		phase = inPhase;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * The serialized length is not relevant for UDP. Therefore write message
	 * direct to writer.
	 * 
	 * @since 2.6
	 */
	@Override
	protected void serializeMessage(DatagramWriter writer, Message message) {
		int mid = message.getMID();
		if (mid == Message.NONE) {
			IllegalArgumentException ex = new IllegalArgumentException("MID required for UDP serialization!");
			LOGGER.warn("UDP, {}:", message, ex);
			throw ex;
		}
		MessageHeader header = new MessageHeader(CoAP.VERSION, message.getType(), message.getToken(),
				message.getRawCode(), mid, -1);
		serializeHeader(writer, header);
		writer.writeCurrentByte();
		serializeOptionsAndPayload(writer, message.getOptions(), message.getPayload());

		if (phase.contains("Client3") || phase.contains("Client4")) {
			MESSAGES[0] = "EDHOC Message #1";
			MESSAGES[1] = "EDHOC Message #3 + OSCORE Request #1";
			MESSAGES[2] = "OSCORE Request #2";
		}

		String messageName = "";
		if (messageCounter <= 2) {
			messageName = MESSAGES[messageCounter];
			messageName = messageName + ": ";
		}

		if (message instanceof Request && phase.contains("Client")) {
			System.out.println(phase + ": " + messageName + "Request " + " CoAP Payload: " + message.getPayloadSize());
			System.out.println(phase + ": " + messageName + "Request " + " UDP Payload: " + writer.size());
		} else if (message instanceof Response && phase.contains("Client")) {
			System.out.println(phase + ": " + messageName + "Response " + " CoAP Payload: " + message.getPayloadSize());
			System.out.println(phase + ": " + messageName + "Response " + " UDP Payload: " + writer.size());
		}

		System.out.println("Counter: " + messageCounter);
		messageCounter++;
	}

	@Override 
	protected void serializeHeader(final DatagramWriter writer, final MessageHeader header) {
		writer.write(VERSION, VERSION_BITS);
		writer.write(header.getType().value, TYPE_BITS);
		writer.write(header.getToken().length(), TOKEN_LENGTH_BITS);
		writer.write(header.getCode(), CODE_BITS);
		writer.write(header.getMID(), MESSAGE_ID_BITS);
		writer.writeBytes(header.getToken().getBytes());
	}

	@Override
	protected void assertValidOptions(OptionSet options) {
		UdpDataParser.assertValidUdpOptions(options);
	}
}
