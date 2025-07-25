/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.Type;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.*;

/**
 * This resource implements a test of specification for the
 * ETSI IoT CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class ObservePumping extends CoapResource {

	// Members ////////////////////////////////////////////////////////////////

	private final static String PADDING = "----------------------------------------------------------------";

	// The current time represented as string
	private String time;

	public ObservePumping(Type type, long notifyIntervalMillis) {
		super("obs-pumping" + (type==Type.NON ? "-non" : ""));
		setObservable(true);
		getAttributes().setTitle("Observable resource which changes every 5 seconds");
		getAttributes().addResourceType("observe");
		getAttributes().setObservable();
		setObserveType(type);
		addSupportedContentFormats(TEXT_PLAIN);

		// Set timer task scheduling
		Timer timer = new Timer("OBSERVE-PUMP", true);
		timer.schedule(new TimeTask(), 0, notifyIntervalMillis);
	}

	/*
	 * Defines a new timer task to return the current time
	 */
	private class TimeTask extends TimerTask {

		@Override
		public void run() {
			if (Math.random()>0.5) {
				time = String.format("%.31s\n%19s\n%.31s\n", PADDING, getTime(), PADDING);
			} else if (Math.random()>0.5) {
				time = String.format("%.63s\n%35s\n%.63s\n", PADDING, getTime(), PADDING);
			} else {
				time = String.format("%s", getTime());
			}
			
			// Call changed to notify subscribers
			changed();
		}
	}

	/*
	 * Returns the current time
	 * 
	 * @return The current time
	 */
	private String getTime() {
		DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
		Date time = new Date();
		return dateFormat.format(time);
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		
		exchange.setMaxAge(5);
		exchange.respond(CONTENT, time, TEXT_PLAIN);
	}

}
