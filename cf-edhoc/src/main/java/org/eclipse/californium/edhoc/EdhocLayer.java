/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
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
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.util.Set;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.AbstractLayer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;

/**
 * 
 * Applies EDHOC mechanics at stack layer.
 *
 */
public class EdhocLayer extends AbstractLayer {

	private static final boolean debugPrint = true;
	
	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(EdhocLayer.class);
	
	/**
	 * The OSCORE context database
	 */
	OSCoreCtxDB ctxDb;
	
	/**
	 * Map of existing EDHOC sessions
	 */
	HashMap<CBORObject, EdhocSession> edhocSessions;

	/**
	 * Map of the EDHOC peer public keys
	 */
	HashMap<CBORObject, OneKey> peerPublicKeys;
	
	/**
	 * Map of the EDHOC peer credentials
	 */
	HashMap<CBORObject, CBORObject> peerCredentials;
	
	/**
	 * Set of used EDHOC Connection IDs
	 */
	Set<CBORObject> usedConnectionIds;
	
	// Lookup identifier to be associated with the OSCORE Security Context
	private final String uriLocal = "coap://localhost";
	
	// The size of the Replay Window to use in an OSCORE Recipient Context
	private int OSCORE_REPLAY_WINDOW;
	
	// The size to consider for MAX_UNFRAGMENTED SIZE
	private int MAX_UNFRAGMENTED_SIZE;

	/**
	 * Build the EdhocLayer
	 * 
	 * @param ctxDb OSCORE context database
	 * @param edhocSessions map of current EDHOC sessions
	 * @param peerPublicKeys map containing the EDHOC peer public keys
	 * @param peerCredentials map containing the EDHOC peer credentials
	 * @param usedConnectionIds set containing the used EDHOC connection IDs
	 * @param OSCORE_REPLAY_WINDOW size of the Replay Window to use in an OSCORE Recipient Context
	 * @param MAX_UNFRAGMENTED_SIZE size of MAX_UNFRAGMENTED_SIZE to use in an OSCORE Security Context
	 */
	public EdhocLayer(OSCoreCtxDB ctxDb,
					  HashMap<CBORObject, EdhocSession> edhocSessions,
					  HashMap<CBORObject, OneKey> peerPublicKeys,
					  HashMap<CBORObject, CBORObject> peerCredentials,
			          Set<CBORObject> usedConnectionIds,
			          int OSCORE_REPLAY_WINDOW,
			          int MAX_UNFRAGMENTED_SIZE) {
		this.ctxDb = ctxDb;
		this.edhocSessions = edhocSessions;
		this.peerPublicKeys = peerPublicKeys;
		this.peerCredentials = peerCredentials;
		this.usedConnectionIds = usedConnectionIds;
		this.OSCORE_REPLAY_WINDOW = OSCORE_REPLAY_WINDOW;
		this.MAX_UNFRAGMENTED_SIZE = MAX_UNFRAGMENTED_SIZE;

		LOGGER.warn("Initializing EDHOC layer");
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		LOGGER.warn("Sending request through EDHOC layer");

		if (request.getOptions().hasOscore() && request.getOptions().hasEdhoc()) {
			LOGGER.warn("Combined EDHOC+OSCORE request");
			
			// Retrieve the Security Context used to protect the request
			OSCoreCtx ctx = getContextForOutgoing(exchange);
			
			// The connection identifier of this peer is its Recipient ID
			byte[] recipientId = ctx.getRecipientId();
			CBORObject connectionIdentifierInitiatorCbor = CBORObject.FromObject(recipientId);
			
			// Retrieve the EDHOC session associated to C_R and storing EDHOC message_3
			EdhocSession session = this.edhocSessions.get(connectionIdentifierInitiatorCbor);
			
			// Consistency checks
			if (session == null) {
				System.err.println("Unable to retrieve the EDHOC session when sending an EDHOC+OSCORE request\n");
				return;
			}
			
			byte[] connectionIdentifierInitiator = session.getConnectionId(); 
			if (!session.isInitiator() ||
				 session.getCurrentStep() != Constants.EDHOC_SENT_M3 ||		
				!Arrays.equals(recipientId, connectionIdentifierInitiator)) {
				
				System.err.println("Retrieved inconsistent EDHOC session when sending an EDHOC+OSCORE request");
				return;
			}
			
			// Extract EDHOC message_3, from the stored CBOR sequence (C_R, EDHOC message_3)
			byte[] storedSequence = session.getMessage3();
			CBORObject[] sequenceElements = CBORObject.DecodeSequenceFromBytes(storedSequence);
			byte[] edhocMessage3 = sequenceElements[1].EncodeToBytes();
			
			// Original OSCORE payload from the request
			byte[] oldOscorePayload = request.getPayload();
			
			if (debugPrint) {
				Util.nicePrint("EDHOC+OSCORE: EDHOC message_3", edhocMessage3);
				Util.nicePrint("EDHOC+OSCORE: Old OSCORE payload", oldOscorePayload);
			}
			
			// Build the new OSCORE payload, as composed of two concatenated elements
			// 1. A CBOR data item, i.e., EDHOC message_3 (of type Byte String)
			// 2. The original OSCORE payload
			
			int newOscorePayloadLength = edhocMessage3.length + oldOscorePayload.length;
			
			// Abort if the payload of the EDHOC+OSCORE request exceeds MAX_UNFRAGMENTED_SIZE
			int maxUnfragmentedSize = ctx.getMaxUnfragmentedSize();
		    if (newOscorePayloadLength > maxUnfragmentedSize) {
		        throw new IllegalStateException("The payload of the EDHOC+OSCORE request is exceeding MAX_UNFRAGMENTED_SIZE");
		    }
			
			byte[] newOscorePayload = new byte[newOscorePayloadLength];
			System.arraycopy(edhocMessage3, 0, newOscorePayload, 0, edhocMessage3.length);
			System.arraycopy(oldOscorePayload, 0, newOscorePayload, edhocMessage3.length, oldOscorePayload.length);
			
			
			if (debugPrint) {
				Util.nicePrint("EDHOC+OSCORE: New OSCORE payload", newOscorePayload);
			}
			
			// Set the new OSCORE payload as payload of the EDHOC+OSCORE request
			request.setPayload(newOscorePayload);
			
		}
		
		super.sendRequest(exchange, request);
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {

		LOGGER.warn("Sending response through EDHOC layer");

		super.sendResponse(exchange, response);
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {

		LOGGER.warn("Receiving request through EDHOC layer");

		if (request.getOptions().hasEdhoc()) {
			
			if (!request.getOptions().hasOscore()) {
    			String responseString = new String("Received a request including the EDHOC option but" +
    											   " not including the OSCORE option\n");
    			System.err.println(responseString);
    			sendErrorResponse(exchange, responseString, ResponseCode.BAD_REQUEST);
    			return;
			}
			
			if (request.getPayload() == null) {
    			String responseString = new String("Received a request including the EDHOC option but" +
    										       " not including a payload\n");
    			System.err.println(responseString);
    			sendErrorResponse(exchange, responseString, ResponseCode.BAD_REQUEST);
    			return;
			}
			
			LOGGER.warn("Combined EDHOC+OSCORE request");

			boolean error = false;
			
			// Retrieve the received payload combining EDHOC message_3 and the real OSCORE payload
			byte[] oldPayload = request.getPayload();
			
			if (debugPrint) {
				Util.nicePrint("EDHOC+OSCORE: received payload", oldPayload);
			}
			
			CBORObject edhocMessage3 = null;
			ByteArrayInputStream myStream = null;
			
			myStream = new ByteArrayInputStream(oldPayload);
			try {
				edhocMessage3 = CBORObject.Read(myStream);
			}
			catch (CBORException e) {
				System.err.println("CBORException: " + e.getMessage());
				error = true;
			}
			catch (NullPointerException e) {
				System.err.println("NullPointerException: " + e.getMessage());
				error = true;
			}
			
			if (edhocMessage3 == null || edhocMessage3.getType() != CBORType.ByteString) {
				error = true;
			}
			
			int oscoreCiphertextLen = oldPayload.length - edhocMessage3.EncodeToBytes().length;
			byte[] newPayload = new byte[oscoreCiphertextLen];
			
			int readBytes = -1;
			try {
				readBytes = myStream.read(newPayload, 0, oscoreCiphertextLen);
			}
			catch (NullPointerException e) {
				System.err.println("NullPointerException: " + e.getMessage());
				error = true;
			}
			catch (IndexOutOfBoundsException e) {
				System.err.println("IndexOutOfBoundsException: " + e.getMessage());
				error = true;
			}
			
			if (readBytes != oscoreCiphertextLen) {
				error = true;
			}
			
			// The EDHOC+OSCORE request is malformed
			if (error == true) {
				String responseString = new String("Invalid EDHOC+OSCORE request");
				System.err.println(responseString);
				sendErrorResponse(exchange, responseString, ResponseCode.BAD_REQUEST);
				return;
			}
			
			// Prepare the actual OSCORE request, by replacing the payload
			request.setPayload(newPayload);
			
			if (debugPrint) {
				Util.nicePrint("EDHOC+OSCORE: OSCORE request payload", newPayload);
			}
			
			
			// Rebuild the CBOR sequence (C_R, EDHOC message_3)

		    List<CBORObject> edhocObjectList = new ArrayList<>();

		    // Add C_R, by encoding the 'kid' from the OSCORE option
			byte[] kid = getKid(request.getOptions().getOscore());		    
			CBORObject cR = MessageProcessor.encodeIdentifier(kid);
		    edhocObjectList.add(cR);
		    
		    // Add EDHOC message_3, i.e., the CBOR data item retrieved from the received message
		    edhocObjectList.add(edhocMessage3);
		    
		    byte[] mySequence = Util.buildCBORSequence(edhocObjectList);
		    
			if (debugPrint) {
				Util.nicePrint("EDHOC+OSCORE: rebuilt CBOR sequence (C_R, EDHOC message_3)", mySequence);
			}
			
			CBORObject kidCbor = CBORObject.FromObject(kid);
			EdhocSession mySession = edhocSessions.get(kidCbor);
			
			// Consistency checks
    		if (mySession == null) {
    			String responseString = new String("Unable to retrieve the EDHOC session when"
    					                         + " receiving an EDHOC+OSCORE request\n");
				System.err.println(responseString);
				sendErrorResponse(exchange, responseString, ResponseCode.BAD_REQUEST);
            	return;
    		}

			byte[] connectionIdentifierInitiator = mySession.getPeerConnectionId();
			byte[] connectionIdentifierResponder = mySession.getConnectionId();
			if (mySession.isInitiator() ||
				mySession.getCurrentStep() != Constants.EDHOC_SENT_M2 ||
				!Arrays.equals(kid, connectionIdentifierResponder)) {
				
				System.err.println("Retrieved inconsistent EDHOC session when receiving an EDHOC+OSCORE request");
				return;
			}
    		   
    		// This EDHOC resource does not support the use of the EDHOC+OSCORE request
    		if (mySession.getApplicationProfile().getSupportCombinedRequest() == false) {
				System.err.println("This EDHOC resource does not support the use of the EDHOC+OSCORE request\n");
    			Util.purgeSession(mySession, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
    			
    			String errMsg = new String("This EDHOC resource does not support the use of the EDHOC+OSCORE request");
    			
    			byte[] nextMessage = MessageProcessor.writeErrorMessage(Constants.ERR_CODE_UNSPECIFIED_ERROR,
    																	Constants.EDHOC_MESSAGE_3,
												                        false, connectionIdentifierInitiator,
												                        errMsg, null);
				ResponseCode responseCode = ResponseCode.BAD_REQUEST;
    			sendErrorMessage(exchange, nextMessage, responseCode);
            	return;
    		}
			
    		// The combined request cannot be used if the Responder has to send message_4
    		if (mySession.getApplicationProfile().getUseMessage4() == true) {
				System.err.println("Cannot receive the combined EDHOC+OSCORE request if message_4 is expected\n");
    			Util.purgeSession(mySession, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
    			
    			String errMsg = new String("Cannot receive the combined EDHOC+OSCORE request if message_4 is expected");
    			byte[] nextMessage = MessageProcessor.writeErrorMessage(Constants.ERR_CODE_UNSPECIFIED_ERROR,
    																	Constants.EDHOC_MESSAGE_3,
												                        false, connectionIdentifierInitiator,
												                        errMsg, null);
				ResponseCode responseCode = ResponseCode.BAD_REQUEST;
    			sendErrorMessage(exchange, nextMessage, responseCode);
            	return;
    		}
		    
			
		    // Process EDHOC message_3
		    		    
		    List<CBORObject> processingResult = new ArrayList<CBORObject>();
			byte[] nextMessage = new byte[] {};
		    
			processingResult = MessageProcessor.readMessage3(mySequence, true, null, edhocSessions, peerPublicKeys,
                    										 peerCredentials, usedConnectionIds);

			if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
				String responseString = new String("Internal error when processing EDHOC Message 3");
				System.err.println(responseString);				
				sendErrorResponse(exchange, responseString, ResponseCode.INTERNAL_SERVER_ERROR);
				return;
			}
			
			// A non-zero length response payload would be an EDHOC Error Message
			
			nextMessage = processingResult.get(0).GetByteString();
			
			// The protocol has successfully completed
			if (nextMessage.length == 0) {

				cR = processingResult.get(1);
				mySession = edhocSessions.get(cR);
				
				if (mySession == null) {
					System.err.println("Inconsistent state before sending EDHOC Message 3");
					String responseString = new String("Inconsistent state before sending EDHOC Message 3");
					sendErrorResponse(exchange, responseString, ResponseCode.INTERNAL_SERVER_ERROR);
					return;
				}
				if (mySession.getCurrentStep() != Constants.EDHOC_AFTER_M3) {
					System.err.println("Inconsistent state after sending EDHOC Message 3");							
					Util.purgeSession(mySession, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
					String responseString = new String("Inconsistent state before sending EDHOC Message 3");
					sendErrorResponse(exchange, responseString, ResponseCode.BAD_REQUEST);
					return;
				}
				
				/* Invoke the EDHOC-Exporter to produce OSCORE input material */
				byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(mySession);
				byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(mySession);
				if (debugPrint) {
					Util.nicePrint("OSCORE Master Secret", masterSecret);
					Util.nicePrint("OSCORE Master Salt", masterSalt);
				}
				
				/* Setup the OSCORE Security Context */
				
				// The Sender ID of this peer is the EDHOC connection identifier of the other peer
				byte[] senderId = connectionIdentifierInitiator;
				
				// The Recipient ID of this peer is the EDHOC connection identifier of this peer
				byte[] recipientId = connectionIdentifierResponder;
				
				int selectedCipherSuite = mySession.getSelectedCipherSuite();
				AlgorithmID alg = EdhocSession.getAppAEAD(selectedCipherSuite);
				AlgorithmID hkdf = EdhocSession.getAppHkdf(selectedCipherSuite);
				
				OSCoreCtx ctx = null;
				try {
					ctx = new OSCoreCtx(masterSecret, false, alg, senderId, 
					recipientId, hkdf, OSCORE_REPLAY_WINDOW, masterSalt, null, MAX_UNFRAGMENTED_SIZE);					
				} catch (OSException e) {							
					Util.purgeSession(mySession, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
					String responseString = new String("Error when deriving the OSCORE Security Context");
					System.err.println(responseString + " " + e.getMessage());
					sendErrorResponse(exchange, responseString, ResponseCode.INTERNAL_SERVER_ERROR);
					return;
				}
				
				try {
					ctxDb.addContext(uriLocal, ctx);
				} catch (OSException e) {							
					Util.purgeSession(mySession, connectionIdentifierResponder, edhocSessions, usedConnectionIds);
					String responseString = new String("Error when adding the OSCORE Security Context to the context database");
					System.err.println(responseString + " " + e.getMessage());
					sendErrorResponse(exchange, responseString, ResponseCode.INTERNAL_SERVER_ERROR);
					return;
				}			        			        
				
				// Remove the EDHOC option
				request.getOptions().setEdhoc(false);
				
				// Perform any follow-up actions based on the processing results of EAD items
				mySession.getSideProcessor().eadProcessingFollowUp();
				
				// The next step is to pass the OSCORE request to the next layer for processing
			
			}
			// An EDHOC error message has to be returned in response to EDHOC message_3
			// The session has been possibly purged while attempting to process message_3
			else {
				int responseCodeValue = processingResult.get(1).AsInt32();
				ResponseCode responseCode = ResponseCode.valueOf(responseCodeValue);
				sendErrorMessage(exchange, nextMessage, responseCode);
				return;
			
			}
					    
		}
		
		super.receiveRequest(exchange, request);
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {

		LOGGER.warn("Receiving response through EDHOC layer");

		super.receiveResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.receiveEmptyMessage(exchange, message);
	}

	/**
	 * Returns the OSCORE Context that was used to protect this outgoing
	 * exchange (outgoing request or response).
	 * 
	 * @param e the exchange
	 * @return the OSCORE Context used to protect the exchange (if any)
	 */
	private OSCoreCtx getContextForOutgoing(Exchange e) {
		
		String uri = e.getRequest().getURI();
		if (uri == null) {
			return null;
		} else {
			try {
				return ctxDb.getContext(uri);
			} catch (OSException exception) {
				System.err.println("Error when retrieving the OSCORE Security Context " + exception.getMessage());
				return null;
			}
		}
	}

	/**
	 * Retrieve KID value from an OSCORE option.
	 * 
	 * @param oscoreOption the OSCORE option
	 * @return the KID value
	 */
	static byte[] getKid(byte[] oscoreOption) {
		if (oscoreOption.length == 0) {
			return null;
		}

		// Parse the flag byte
		byte flagByte = oscoreOption[0];
		int n = flagByte & 0x07;
		int k = flagByte & 0x08;
		int h = flagByte & 0x10;

		byte[] kid = null;
		int index = 1;

		// Partial IV
		index += n;

		// KID Context
		if (h != 0) {
			int s = oscoreOption[index];
			index += s + 1;
		}

		// KID
		if (k != 0) {
			kid = Arrays.copyOfRange(oscoreOption, index, oscoreOption.length);
		}

		return kid;
	}	
	
	/*
	 * Send a CoAP error message in response to the received EDHOC+OSCORE request
	 */
	private void sendErrorResponse(Exchange exchange, String message, ResponseCode code) {
		
		byte[] errorMessage = new byte[] {};
		errorMessage = message.getBytes(Constants.charset);

		Response errorResponse = new Response(code);
		errorResponse.setPayload(errorMessage);
		exchange.sendResponse(errorResponse);
		
	}
	
	/*
	 * Send an EDHOC Error Message in response to the received EDHOC+OSCORE request
	 */
	private void sendErrorMessage(Exchange exchange, byte[] nextMessage, ResponseCode responseCode) {
	
		if (!MessageProcessor.isErrorMessage(nextMessage, false)) {
			System.err.println("Inconsistent state before sending EDHOC Error Message");
			String responseString = new String("Inconsistent state before sending EDHOC Error Message");
			sendErrorResponse(exchange, responseString, ResponseCode.INTERNAL_SERVER_ERROR);
			return;
		}
		
		Response myResponse = new Response(responseCode);
		myResponse.getOptions().setContentFormat(Constants.APPLICATION_EDHOC_CBOR_SEQ);
		myResponse.setPayload(nextMessage);
		exchange.sendResponse(myResponse);
		return;
		
	}
	
}
