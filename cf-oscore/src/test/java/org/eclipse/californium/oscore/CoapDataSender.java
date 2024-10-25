/*******************************************************************************
 * Copyright (c) 2024 RISE and others.
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
 * Contributors:
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.io.IOException;
import java.text.DecimalFormat;
import java.util.Calendar;
import java.util.Random;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.exception.ConnectorException;

/**
 * 
 * Basic application regularly sending CoAP data using POST (No OSCORE for now)
 *
 */
public class CoapDataSender {

	private static String uri = "coap://localhost/.well-known/core";
	private final static int WAIT_BETWEEN_TRANSMISSIONS = 10 * 60 * 1000;

	private final static HashMapCtxDB db = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };
	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	private static final Random random = new Random();

	static DecimalFormat df = new DecimalFormat();

	public static void main(String[] args) throws OSException, ConnectorException, IOException, InterruptedException {

		// Parse URI from command line
		if (args.length != 0) {
			uri = args[0];
		}

		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null,
				MAX_UNFRAGMENTED_SIZE);
		db.addContext(uri, ctx);
		OSCoreCoapStackFactory.useAsDefault(db);
		CoapClient c = new CoapClient(uri);

		df.setMaximumFractionDigits(3);

		// Send data with regular intervals
		while (true) {
			Request req = new Request(Code.POST);
			req.setURI(uri);
			req.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
			float currentTemp = getSimulatedTemp();
			req.setPayload(df.format(currentTemp));

			// Send the actual request
			System.out.println(Utils.prettyPrint(req));
			CoapResponse resp = c.advanced(req);
			if (resp != null) {
				System.out.println(Utils.prettyPrint(resp));
			} else {
				System.err.println("No response received!");
			}

			Thread.sleep(WAIT_BETWEEN_TRANSMISSIONS);
		}
	}

	@SuppressWarnings("unused")
	private static void printResponse(CoapResponse resp) {
		if (resp != null) {
			System.out.println("RESPONSE CODE: " + resp.getCode().name() + " " + resp.getCode());
			if (resp.getPayload() != null) {
				System.out.print("RESPONSE PAYLOAD: ");
				for (byte b : resp.getPayload()) {
					System.out.print(Integer.toHexString(b & 0xff) + " ");
				}
				System.out.println();
			}
			System.out.println("RESPONSE TEXT: " + resp.getResponseText());
		} else {
			System.out.println("RESPONSE IS NULL");
		}
	}

	/**
	 * Retrieves a simulated temperature reading based on the current time
	 * 
	 * @return the simulated temp (in C)
	 */
	private static float getSimulatedTemp() {
		// Get the current hour and minute of the day
		Calendar calendar = Calendar.getInstance();
		int hour = calendar.get(Calendar.HOUR_OF_DAY);
		int minute = calendar.get(Calendar.MINUTE);

		// Convert current time to a fraction of the day (0.0 to 1.0)
		double timeOfDayFraction = (hour + (minute / 60.0)) / 24.0;

		// Temperature range
		double minTemp = 17.5;
		double maxTemp = 24.5;

		// Amplitude of the sine wave based on the temperature range
		double amplitude = (maxTemp - minTemp) / 2;

		// Midpoint temperature (average of min and max)
		double midpoint = minTemp + amplitude;

		// Calculate phase shift so that peak temperature is at 13:00
		double phaseShift = -Math.PI / 2;

		// Calculate the sine wave value based on the current time of day
		double normalizedTime = timeOfDayFraction * 2 * Math.PI;
		double sineValue = Math.sin(normalizedTime + phaseShift);

		// Compute the base temperature from the sine wave
		double baseTemp = midpoint + amplitude * sineValue;

		// Add some random noise for variability (-0.33 to +0.33)
		double noise = (random.nextDouble() * 0.66) - 0.33;

		// Return the final temperature with noise
		return (float) (baseTemp + noise);
	}
}
