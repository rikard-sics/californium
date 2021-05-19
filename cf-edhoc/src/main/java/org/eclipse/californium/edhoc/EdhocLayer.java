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

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.Utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
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
	Map<CBORObject, EdhocSession> edhocSessions;

	/**
	 * Map of the EDHOC peer public keys
	 */
	Map<CBORObject, OneKey> peerPublicKeys;
	
	/**
	 * Map of the EDHOC peer credentials
	 */
	Map<CBORObject, CBORObject> peerCredentials;
	
	/**
	 * List of used EDHOC Connection IDs
	 */
	List<Set<Integer>> usedConnectionIds;
	
	// Lookup identifier to be associated with the OSCORE Security Context
	private final String uriLocal = "coap://localhost";
	
	// The size of the Replay Window to use in an OSCORE Recipient Context
	private int OSCORE_REPLAY_WINDOW;

	/**
	 * Build the EdhocLayer
	 * 
	 * @param ctxDb OSCORE context database
	 * @param edhocSessions map of current EDHOC sessions
	 * @param peerPublicKeys map containing the EDHOC peer public keys
	 * @param peerCredentials map containing the EDHOC peer credentials
	 * @param usedConnectionIds list containing the used EDHOC connection IDs
	 * @param OSCORE_REPLAY_WINDOW size of the Replay Window to use in an OSCORE Recipient Context
	 */
	public EdhocLayer(OSCoreCtxDB ctxDb,
					  Map<CBORObject, EdhocSession> edhocSessions,
			          Map<CBORObject, OneKey> peerPublicKeys,
			          Map<CBORObject, CBORObject> peerCredentials,
			          List<Set<Integer>> usedConnectionIds,
			          int OSCORE_REPLAY_WINDOW) {
		this.ctxDb = ctxDb;
		this.edhocSessions = edhocSessions;
		this.peerPublicKeys = peerPublicKeys;
		this.peerCredentials = peerCredentials;
		this.usedConnectionIds = usedConnectionIds;
		this.OSCORE_REPLAY_WINDOW = OSCORE_REPLAY_WINDOW;

		LOGGER.warn("Initializing EDHOC layer");
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		LOGGER.warn("Sending request through EDHOC layer");

		if (request.getOptions().hasOscore() && request.getOptions().hasEdhoc()) {
			LOGGER.warn("Combined EDHOC+OSCORE request");
			
			// Retrieve the Security Context used to protect the request
			OSCoreCtx ctx = getContextForOutgoing(exchange);
			
			// The connectionIdentifier C_I is the Recipient ID for this peer
			byte[] cI = ctx.getRecipientId();
			
			// Retrieve the EDHOC session associated to C_R and storing EDHOC message_3
			EdhocSession session = this.edhocSessions.get(CBORObject.FromObject(cI));
			
			// Consistency checks
			if (session == null) {
				System.err.println("Unable to retrieve the EDHOC session when sending an EDHOC+OSCORE request\n");
				return;
			}
			if (!session.isInitiator() || session.getCurrentStep() != Constants.EDHOC_SENT_M3 ||		
					!Arrays.equals(session.getPeerConnectionId(), ctx.getSenderId())) {
				
				System.err.println("Retrieved inconsistent EDHOC session when sending an EDHOC+OSCORE request");
				return;
			}
			
			// Extract CIPHERTEXT_3 as second element of EDHOC message_3
			byte[] message3 = session.getMessage3();
			CBORObject[] message3Elements = CBORObject.DecodeSequenceFromBytes(message3);
			byte[] ciphertext3 = message3Elements[1].GetByteString();
			
			// Original OSCORE payload from the request
			byte[] oldOscorePayload = request.getPayload();
			
			if (debugPrint) {
				Util.nicePrint("EDHOC+OSCORE: Message 3", message3);
				Util.nicePrint("EDHOC+OSCORE: CIPHERTEXT_3", ciphertext3);
				Util.nicePrint("EDHOC+OSCORE: Old OSCORE payload", oldOscorePayload);
			}
				
			// Build the new OSCORE payload, as a CBOR sequence of two elements
			// 1. A CBOR byte string, i.e. EDHOC CIPHERTEXT_3 as is
			// 2. A CBOR byte string, with value the original OSCORE payload
			byte[] ciphertext3CBOR = CBORObject.FromObject(ciphertext3).EncodeToBytes();
			byte[] oldOscorePayloadCBOR = CBORObject.FromObject(oldOscorePayload).EncodeToBytes();
			byte[] newOscorePayload = new byte[ciphertext3CBOR.length + oldOscorePayloadCBOR.length];
			System.arraycopy(ciphertext3CBOR, 0, newOscorePayload, 0, ciphertext3CBOR.length);
			System.arraycopy(oldOscorePayloadCBOR, 0, newOscorePayload, ciphertext3CBOR.length, oldOscorePayloadCBOR.length);
			
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

		if (request.getOptions().hasEdhoc() && request.getOptions().hasOscore()) {
			LOGGER.warn("Combined EDHOC+OSCORE request");
			
			
			boolean error = false;
			
			// Retrieve the received payload combining EDHOC CIPHERTEXT_3 and the real OSCORE payload
			byte[] oldPayload = request.getPayload();
			
			// CBOR objects included in the received CBOR sequence
			CBORObject[] receivedOjectList = CBORObject.DecodeSequenceFromBytes(oldPayload);
						
			if (receivedOjectList == null || receivedOjectList.length != 2) {
				error = true;
			}
			else if (receivedOjectList[0].getType() != CBORType.ByteString ||
					 receivedOjectList[1].getType() != CBORType.ByteString) {
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
			byte[] newPayload = receivedOjectList[1].GetByteString();
			request.setPayload(newPayload);
			
			if (debugPrint) {
				Util.nicePrint("EDHOC+OSCORE: received payload", oldPayload);
				Util.nicePrint("EDHOC+OSCORE: OSCORE request payload", newPayload);
			}
			
			
			// Rebuild the full EDHOC message_3

		    List<CBORObject> edhocObjectList = new ArrayList<>();
		    
		    // Add C_R, i.e. the 'kid' from the OSCORE option encoded as a bstr_identifier
			byte[] kid = getKid(request.getOptions().getOscore());
		    CBORObject cR = Util.encodeToBstrIdentifier(CBORObject.FromObject(kid));
		    edhocObjectList.add(cR);
		    
		    // Add CIPHERTEXT_3, i.e. the CBOR string as is from the received CBOR sequence
		    edhocObjectList.add(receivedOjectList[0]); // CIPHERTEXT_3
		    
		    // Assemble the full EDHOC message_3
		    byte[] edhocMessage3 = Util.buildCBORSequence(edhocObjectList);
		    
			if (debugPrint) {
				Util.nicePrint("EDHOC+OSCORE: rebuilt EDHOC message_3", edhocMessage3);
			}
			
			EdhocSession mySession = edhocSessions.get(CBORObject.FromObject(kid));
			
			// Consistency checks
    		if (mySession == null) {
    			String responseString = new String("Unable to retrieve the EDHOC session when receiving an EDHOC+OSCORE request\n");
				System.err.println(responseString);
				sendErrorResponse(exchange, responseString, ResponseCode.BAD_REQUEST);
            	return;
    		}
			if (mySession.isInitiator() || mySession.getCurrentStep() != Constants.EDHOC_SENT_M2 ||		
					!Arrays.equals(mySession.getConnectionId(), kid)) {
				
				System.err.println("Retrieved inconsistent EDHOC session when receiving an EDHOC+OSCORE request");
				return;
			}
    		
    		int correlation = mySession.getCorrelation();
    		
    		// The combined request cannot be used if the Responder has to send message_4
    		if (mySession.getApplicabilityStatement().getUseMessage4() == true) {
				System.err.println("Cannot receive the combined EDHOC+OSCORE request if message_4 is expected\n");
    			Util.purgeSession(mySession, CBORObject.FromObject(kid), edhocSessions, usedConnectionIds);
    			
    			String errMsg = new String("Cannot receive the combined EDHOC+OSCORE request if message_4 is expected");
    			byte[] nextMessage = MessageProcessor.writeErrorMessage(Constants.ERR_CODE_UNSPECIFIED,
    																	Constants.EDHOC_MESSAGE_3,
												                        correlation, null, errMsg, null);
				ResponseCode responseCode = ResponseCode.BAD_REQUEST;
    			sendErrorMessage(exchange, nextMessage, responseCode, correlation);
            	return;
    		}
		    
			
		    // Process EDHOC message_3
		    		    
		    List<CBORObject> processingResult = new ArrayList<CBORObject>();
			byte[] nextMessage = new byte[] {};
		    
			processingResult = MessageProcessor.readMessage3(edhocMessage3, null, edhocSessions, peerPublicKeys,
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
			
				// Deliver AD_3 to the application, if present
				if (processingResult.size() == 3 && processingResult.get(2).getType() == CBORType.Array) {
					// Elements of 'processingResult' are:
					//   i) A zero-length CBOR byte string, indicating successful processing;
					//  ii) The Connection Identifier of the Responder, i.e. C_R
					// iii) Optionally, the External Authorization Data EAD_3, as elements of a CBOR array
					
					// This inspected element of 'processingResult' should really be a CBOR Array at this point
					int length = processingResult.get(2).size();
					CBORObject[] ead3 = new CBORObject[length];
					for (int i = 0; i < length; i++) {
						ead3[i] = processingResult.get(2).get(i);
					}
					mySession.getEdp().processEAD3(ead3);
				}
				
				cR = processingResult.get(1);
				mySession = edhocSessions.get(cR);
				
				if (mySession == null) {
					System.err.println("Inconsistent state before sending EDHOC Message 3");
					String responseString = new String("Inconsistent state before sending EDHOC Message 3");
					sendErrorResponse(exchange, responseString, ResponseCode.INTERNAL_SERVER_ERROR);
					return;
				}
				if (mySession.getCurrentStep() != Constants.EDHOC_AFTER_M3) {
					System.err.println("Inconsistent state before sending EDHOC Message 3");							
					Util.purgeSession(mySession,
							          CBORObject.FromObject(mySession.getConnectionId()), edhocSessions, usedConnectionIds);
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
				byte[] senderId = mySession.getPeerConnectionId();
				
				// The Recipient ID of this peer is the EDHOC connection identifier of this peer
				byte[] recipientId = mySession.getConnectionId();
				
				int selectedCiphersuite = mySession.getSelectedCiphersuite();
				AlgorithmID alg = EdhocSession.getAppAEAD(selectedCiphersuite);
				AlgorithmID hkdf = EdhocSession.getAppHkdf(selectedCiphersuite);
				
				OSCoreCtx ctx = null;
				try {
					ctx = new OSCoreCtx(masterSecret, false, alg, senderId, 
					recipientId, hkdf, OSCORE_REPLAY_WINDOW, masterSalt, null);
				} catch (OSException e) {							
					Util.purgeSession(mySession,
									  CBORObject.FromObject(mySession.getConnectionId()), edhocSessions, usedConnectionIds);
					String responseString = new String("Error when deriving the OSCORE Security Context");
					System.err.println(responseString + " " + e.getMessage());
					sendErrorResponse(exchange, responseString, ResponseCode.INTERNAL_SERVER_ERROR);
					return;
				}
				
				try {
					ctxDb.addContext(uriLocal, ctx);
				} catch (OSException e) {							
					Util.purgeSession(mySession,
									  CBORObject.FromObject(mySession.getConnectionId()), edhocSessions, usedConnectionIds);
					String responseString = new String("Error when adding the OSCORE Security Context to the context database");
					System.err.println(responseString + " " + e.getMessage());
					sendErrorResponse(exchange, responseString, ResponseCode.INTERNAL_SERVER_ERROR);
					return;
				}			        			        
				
				// The next step is to pass the OSCORE request to the next layer for processing
			
			}
			// An EDHOC error message has to be returned
			else {
				int responseCodeValue = processingResult.get(1).AsInt32();
				ResponseCode responseCode = ResponseCode.valueOf(responseCodeValue);
				sendErrorMessage(exchange, nextMessage, responseCode, correlation);
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
		byte[] rid = e.getCryptographicContextID();
		if (rid == null) {
			return null;
		} else {
			return ctxDb.getContext(rid);
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
	private void sendErrorMessage(Exchange exchange, byte[] nextMessage, ResponseCode responseCode, int correlation) {

		// Most likely, the used correlation is 1, hence the flag is set to true
		// (Note that correlation 2 is just not applicable when using the EDHOC+OSCORE request)
		boolean correlationFlag = (correlation == Constants.EDHOC_CORR_0) ? false : true;
	
		if (!MessageProcessor.isErrorMessage(nextMessage, false, correlationFlag)) {
			System.err.println("Inconsistent state before sending EDHOC Error Message");
			String responseString = new String("Inconsistent state before sending EDHOC Error Message");
			sendErrorResponse(exchange, responseString, ResponseCode.INTERNAL_SERVER_ERROR);
			return;
		}
		
		Response myResponse = new Response(responseCode);
		myResponse.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
		myResponse.setPayload(nextMessage);
		exchange.sendResponse(myResponse);
		return;
		
	}
	
}
