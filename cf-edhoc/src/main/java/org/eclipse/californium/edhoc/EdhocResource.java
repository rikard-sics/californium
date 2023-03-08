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
 * This class is based on org.eclipse.californium.examples.HelloWorldServer
 * 
 * Contributors:
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/*
 * Definition of the EDHOC Resource
 */
class EdhocResource extends CoapResource {

	private EdhocEndpointInfo edhocEndpointInfo;
	private Set<CBORObject> ownIdCreds;
	
	private static final boolean debugPrint = true;
	
	public EdhocResource(String resourceIdentifier, EdhocEndpointInfo edhocEndpointInfo, Set<CBORObject> ownIdCreds) {
		
		// set resource identifier
		super(resourceIdentifier);

		// set the information about the EDHOC server hosting this EDHOC resource
		this.edhocEndpointInfo = edhocEndpointInfo;
		
		// set the collection of ID_CRED_X used for an authentication credential associated to this peer
		this.ownIdCreds = ownIdCreds;
		
		// set display name
		getAttributes().setTitle("EDHOC Resource");
	}

	@Override
	public void handleGET(CoapExchange exchange) {

		// respond to the request
		exchange.respond("Send me a POST request to run EDHOC!");
	}
	
	
	@Override
	public void handlePOST(CoapExchange exchange) {
		
		byte[] nextMessage = new byte[] {};
				
		URI edhocResourceUri = null;
		try {
			edhocResourceUri = new URI(exchange.advanced().getRequest().getURI());
		} catch (URISyntaxException e1) {
			String responseString = new String("Error when parsing the request target URI");
			System.err.println(responseString);
			
			nextMessage = responseString.getBytes(Constants.charset);
			Response genericErrorResponse = new Response(ResponseCode.INTERNAL_SERVER_ERROR);
			genericErrorResponse.setPayload(nextMessage);
			exchange.respond(genericErrorResponse);
			return;
		}
		
		// Retrieve the application profile to use
		String path = edhocResourceUri.getPath();
		AppProfile appProfile = edhocEndpointInfo.getAppProfiles().get(path);
		
		// Error when retrieving the application profile for this EDHOC resource
		if (appProfile == null) {
			String responseString = new String("Error when retrieving the application profile");
			System.err.println(responseString);
			
			nextMessage = responseString.getBytes(Constants.charset);
			Response genericErrorResponse = new Response(ResponseCode.INTERNAL_SERVER_ERROR);
			genericErrorResponse.setPayload(nextMessage);
			exchange.respond(genericErrorResponse);
			return;
			
		}
		
		byte[] message = exchange.getRequestPayload();
		
		boolean hasContentFormat = exchange.getRequestOptions().hasContentFormat();
		int contentFormat = exchange.getRequestOptions().getContentFormat();
		
		if ( (message == null && !hasContentFormat) ||
			 (message != null && hasContentFormat && contentFormat != Constants.APPLICATION_CID_EDHOC_CBOR_SEQ &&
			  contentFormat != Constants.APPLICATION_EDHOC_CBOR_SEQ) ) {
			// The server can start acting as Initiator and send an EDHOC Message 1 as a CoAP response
			processTriggerRequest(exchange, appProfile);
			return;
		}
		
		if ( message == null ||
			(message != null && hasContentFormat && contentFormat != Constants.APPLICATION_CID_EDHOC_CBOR_SEQ) ) {
			String responseString = new String("Error when receiving a request to the EDHOC resource"
					+ "An EDHOC message must be included in a request either without content-format "
					+ "or with content-format application/cid-edhoc+cbor-seq");
			System.err.println(responseString);
			
			nextMessage = responseString.getBytes(Constants.charset);
			Response genericErrorResponse = new Response(ResponseCode.BAD_REQUEST);
			genericErrorResponse.setPayload(nextMessage);
			exchange.respond(genericErrorResponse);
			return;
		}

		int messageType = MessageProcessor.messageType(message, true, edhocEndpointInfo.getEdhocSessions(), null);
		
		// Invalid EDHOC message type
		if (messageType == -1) {
			String responseString = new String("Invalid EDHOC message type");
			System.err.println(responseString);
			
			nextMessage = responseString.getBytes(Constants.charset);
			Response genericErrorResponse = new Response(ResponseCode.BAD_REQUEST);
			genericErrorResponse.setPayload(nextMessage);
			exchange.respond(genericErrorResponse);
			return;
			
		}
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>();

		
		// The received message is an actual EDHOC message
		
		String typeName = "";
		switch (messageType) {
			case Constants.EDHOC_ERROR_MESSAGE:
				typeName = new String("EDHOC Error Message");
				break;
			case Constants.EDHOC_MESSAGE_1:
			case Constants.EDHOC_MESSAGE_2:
			case Constants.EDHOC_MESSAGE_3:
			case Constants.EDHOC_MESSAGE_4:
				typeName = new String("EDHOC Message " + messageType);
				break;		
		}
		System.out.println("Determined EDHOC message type: " + typeName + "\n");
		
        // Since the incoming EDHOC message is transported as a CoAP request,
		// it is prepended by C_X, which does not have to be printed
		List<CBORObject> trimmedSequence = new ArrayList<CBORObject>();
		CBORObject[] objectListRequest = CBORObject.DecodeSequenceFromBytes(message);
		for (int i = 1; i < objectListRequest.length; i++) {
			trimmedSequence.add(objectListRequest[i]);
		}
		byte[] messageToPrint = Util.buildCBORSequence(trimmedSequence);
		Util.nicePrint(typeName, messageToPrint);

		
		/* Start handling EDHOC Message 1 */
		
		if (messageType == Constants.EDHOC_MESSAGE_1) {
			
			SideProcessor sideProcessor = new SideProcessor(edhocEndpointInfo.getTrustModel(),
															edhocEndpointInfo.getPeerCredentials(),
															edhocEndpointInfo.getEadProductionInput());
			
			processingResult = MessageProcessor.readMessage1(message, true,
															 edhocEndpointInfo.getSupportedCipherSuites(),
															 edhocEndpointInfo.getSupportedEADs(),
															 appProfile, sideProcessor);

			if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
				String responseString = new String("Internal error when processing EDHOC Message 1");
				System.err.println(responseString);
				
				nextMessage = responseString.getBytes(Constants.charset);
				Response genericErrorResponse = new Response(ResponseCode.INTERNAL_SERVER_ERROR);
				genericErrorResponse.setPayload(nextMessage);
				exchange.respond(genericErrorResponse);
				return;
			}
			
			EdhocSession session = null;
			int responseType = -1;
			
			// A non-zero length response payload would be an EDHOC Error Message
			nextMessage = processingResult.get(0).GetByteString();
			
			// Prepare EDHOC Message 2
			if (nextMessage.length == 0) {

				session = MessageProcessor.createSessionAsResponder(message, true,
																	edhocEndpointInfo.getKeyPairs(),
																    edhocEndpointInfo.getIdCreds(),
																    edhocEndpointInfo.getCreds(),
																    edhocEndpointInfo.getSupportedCipherSuites(),
																    edhocEndpointInfo.getSupportedEADs(),
																    edhocEndpointInfo.getUsedConnectionIds(),
																    appProfile, edhocEndpointInfo.getTrustModel(),
																    edhocEndpointInfo.getOscoreDb());
				
				// Provide the side processor object with the just created EDHOC session.
				// A reference to the sideProcessor is also going to be stored in the EDHOC session.
				sideProcessor.setEdhocSession(session);
				
				// Compute the EDHOC Message 2
				nextMessage = MessageProcessor.writeMessage2(session);

				byte[] connectionIdentifier = session.getConnectionId();
				
				// Deallocate the assigned Connection Identifier for this peer
				if (nextMessage == null || session.getCurrentStep() != Constants.EDHOC_BEFORE_M2) {
					Util.releaseConnectionId(connectionIdentifier, edhocEndpointInfo.getUsedConnectionIds(), session.getOscoreDb());
					session.deleteTemporaryMaterial();
					session = null;
					
					String responseString = new String("Inconsistent state before sending EDHOC Message 2");
					System.err.println(responseString);
					nextMessage = responseString.getBytes(Constants.charset);
					Response genericErrorResponse = new Response(ResponseCode.INTERNAL_SERVER_ERROR);
					genericErrorResponse.setPayload(nextMessage);
					exchange.respond(genericErrorResponse);
					return;
				}
				
				// Add the new session to the list of existing EDHOC sessions
				session.setCurrentStep(Constants.EDHOC_AFTER_M2);
				CBORObject connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
				edhocEndpointInfo.getEdhocSessions().put(connectionIdentifierCbor, session);
				
			}
			
			byte[] connectionIdentifier = null;
			if (session != null) {
				connectionIdentifier = session.getConnectionId();
			}
			
			responseType = MessageProcessor.messageType(nextMessage, false,
														edhocEndpointInfo.getEdhocSessions(), connectionIdentifier);
			
			if (responseType != Constants.EDHOC_MESSAGE_2 && responseType != Constants.EDHOC_ERROR_MESSAGE) {
				nextMessage = null;
			}
			
			if (nextMessage != null) {
				
				ResponseCode responseCode = ResponseCode.CHANGED;
				
				if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
					int responseCodeValue = processingResult.get(1).AsInt32();
					responseCode = ResponseCode.valueOf(responseCodeValue);
				}

				Response myResponse = new Response(responseCode);
				myResponse.getOptions().setContentFormat(Constants.APPLICATION_EDHOC_CBOR_SEQ);
				myResponse.setPayload(nextMessage);
				
				String myString = (responseType == Constants.EDHOC_MESSAGE_2) ? "EDHOC Message 2" : "EDHOC Error Message";
				System.out.println("Response type: " + myString + "\n");
				
				if (responseType == Constants.EDHOC_MESSAGE_2) {
			        System.out.println("Sent EDHOC Message 2\n");
				}
				if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
				    
					if (session != null) {
						// The reading of EDHOC Message 1 was successful, but the writing of EDHOC Message 2 was not
						
						// The session was created, but not added to the list of EDHOC sessions
						Util.releaseConnectionId(session.getConnectionId(),
								                 edhocEndpointInfo.getUsedConnectionIds(),
								                 session.getOscoreDb());
						session.deleteTemporaryMaterial();
						session = null;
					}
					
			        System.out.println("Sent EDHOC Error Message\n");
			        if (debugPrint) {
			        	Util.nicePrint("EDHOC Error Message", nextMessage);
			        }
				}
				
				if (responseType == Constants.EDHOC_MESSAGE_2) {
					session.setCurrentStep(Constants.EDHOC_SENT_M2);
				}
				
				exchange.respond(myResponse);
				return;
			}
			else {
				Util.purgeSession(session, session.getConnectionId(),
								  edhocEndpointInfo.getEdhocSessions(),
								  edhocEndpointInfo.getUsedConnectionIds());
				
				String responseString = new String("Inconsistent state after processing EDHOC Message 2");
				System.err.println(responseString);
				nextMessage = responseString.getBytes(Constants.charset);
				Response genericErrorResponse = new Response(ResponseCode.INTERNAL_SERVER_ERROR);
				genericErrorResponse.setPayload(nextMessage);
				exchange.respond(genericErrorResponse);
				
				return;
			}
			
		}
		/* End handling EDHOC Message 1 */
		
		
		/* Start handling EDHOC Message 2 */
		
		if (messageType == Constants.EDHOC_MESSAGE_2) {
			
			System.out.println("Handler for processing EDHOC Message 2");
			
			// Do nothing
			
		}
		
		
		/* Start handling EDHOC Message 3 */
		
		if (messageType == Constants.EDHOC_MESSAGE_3) {
			
			processingResult = MessageProcessor.readMessage3(message, true, null,
															 edhocEndpointInfo.getEdhocSessions(),
															 edhocEndpointInfo.getPeerPublicKeys(),
															 edhocEndpointInfo.getPeerCredentials(),
															 edhocEndpointInfo.getUsedConnectionIds());
			
			if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
				System.err.println("Internal error when processing EDHOC Message 3");
				return;
			}
			
			EdhocSession mySession = null;
			
			// A non-zero length response payload would be an EDHOC Error Message
			nextMessage = processingResult.get(0).GetByteString();
			
			// The EDHOC protocol has successfully completed
			if (nextMessage.length == 0) {
				
				CBORObject cR = processingResult.get(1);
				mySession = edhocEndpointInfo.getEdhocSessions().get(cR);
				
				if (mySession == null) {
					System.err.println("Inconsistent state before sending EDHOC Message 3");
					return;
				}
				if (mySession.getCurrentStep() != Constants.EDHOC_AFTER_M3) {
						System.err.println("Inconsistent state after sending EDHOC Message 3");							
						Util.purgeSession(mySession, mySession.getConnectionId(),
										  edhocEndpointInfo.getEdhocSessions(),
										  edhocEndpointInfo.getUsedConnectionIds());
						return;
				}
				
				if (mySession.getApplicationProfile().getUsedForOSCORE() == true) {
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
			        
			        if (Arrays.equals(senderId, recipientId)) {
						System.err.println("Error: the Sender ID coincides with the Recipient ID " +
											Utils.toHexString(senderId));
						Util.purgeSession(mySession, mySession.getConnectionId(),
										  edhocEndpointInfo.getEdhocSessions(),
										  edhocEndpointInfo.getUsedConnectionIds());
						return;
			        }
			        
			        int selectedCipherSuite = mySession.getSelectedCipherSuite();
			        AlgorithmID alg = EdhocSession.getAppAEAD(selectedCipherSuite);
			        AlgorithmID hkdf = EdhocSession.getAppHkdf(selectedCipherSuite);
			        
			        OSCoreCtx ctx = null;
			        try {
						ctx = new OSCoreCtx(masterSecret, false, alg, senderId, 
											recipientId, hkdf, edhocEndpointInfo.getOscoreReplayWindow(),
											masterSalt, null, edhocEndpointInfo.getOscoreMaxUnfragmentedSize());
						
					} catch (OSException e) {
						System.err.println("Error when deriving the OSCORE Security Context " + e.getMessage());						
						Util.purgeSession(mySession, mySession.getConnectionId(),
										  edhocEndpointInfo.getEdhocSessions(),
										  edhocEndpointInfo.getUsedConnectionIds());
						return;
					}
			        
			        try {
			        	edhocEndpointInfo.getOscoreDb().addContext(edhocEndpointInfo.getUri(), ctx);
					} catch (OSException e) {
						System.err.println("Error when adding the OSCORE Security Context to the context database " + e.getMessage());							
						Util.purgeSession(mySession, mySession.getConnectionId(),
										  edhocEndpointInfo.getEdhocSessions(),
										  edhocEndpointInfo.getUsedConnectionIds());
						return;
					}
		        
				}
		        
		        // Prepare the response to send back
		        Response myResponse = new Response(ResponseCode.CHANGED);
		        
		        if (mySession.getApplicationProfile().getUseMessage4() == false) {
			        // Just send an empty response back
		        	
		        	// Uncomment to have the response as a confirmable Separate Response
		        	// myResponse.setConfirmable(true);
		        	
					myResponse.setPayload(nextMessage);
					exchange.respond(myResponse);
					return;
					
			        /*
			        // Alternative sending an empty ACK instead
			        if (exchange.advanced().getRequest().isConfirmable())
			        	exchange.accept();
			        */
					
		        }
		        else {
		        	// message_4 has to be sent to the Initiator
		        	
					// Compute the EDHOC Message 4
					byte[] connectionIdentifierResponder = mySession.getConnectionId();
					nextMessage = MessageProcessor.writeMessage4(mySession);
					
					// Deallocate the assigned Connection Identifier for this peer
					if (nextMessage == null || mySession.getCurrentStep() != Constants.EDHOC_AFTER_M4) {
						System.err.println("Inconsistent state before sending EDHOC Message 4");
						Util.purgeSession(mySession, connectionIdentifierResponder,
										  edhocEndpointInfo.getEdhocSessions(),
										  edhocEndpointInfo.getUsedConnectionIds());
						return;
					}
					
					int responseType = MessageProcessor.messageType(nextMessage, false,
																	edhocEndpointInfo.getEdhocSessions(),
																	connectionIdentifierResponder);

					if (responseType == Constants.EDHOC_MESSAGE_4 || responseType == Constants.EDHOC_ERROR_MESSAGE) {
						
						myResponse.getOptions().setContentFormat(Constants.APPLICATION_EDHOC_CBOR_SEQ);
						myResponse.setConfirmable(true);
						myResponse.setPayload(nextMessage);
						
						String myString = (responseType == Constants.EDHOC_MESSAGE_4) ?
								                             "EDHOC Message 4" : "EDHOC Error Message";
						System.out.println("Response type: " + myString + "\n");
						
						if (responseType == Constants.EDHOC_MESSAGE_4) {

					        mySession.setCurrentStep(Constants.EDHOC_SENT_M4);
							exchange.respond(myResponse);
					        
					        System.out.println("Sent EDHOC Message 4\n");
					        
						}
						
						if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
					        
							int responseCodeValue = processingResult.get(1).AsInt32();
							ResponseCode responseCode = ResponseCode.valueOf(responseCodeValue);
					        sendErrorMessage(exchange, nextMessage, appProfile, responseCode);
					        
					        Util.purgeSession(mySession, connectionIdentifierResponder,
							        		  edhocEndpointInfo.getEdhocSessions(),
							        		  edhocEndpointInfo.getUsedConnectionIds());
					        
					        System.out.println("Sent EDHOC Error Message\n");
					        if (debugPrint) {
					        	Util.nicePrint("EDHOC Error Message", nextMessage);
					        }
					        
						}
						return;
					}
					else {
						System.err.println("Inconsistent state before sending EDHOC Message 4");
						Util.purgeSession(mySession, connectionIdentifierResponder,
										  edhocEndpointInfo.getEdhocSessions(),
										  edhocEndpointInfo.getUsedConnectionIds());
						return;
					}
					
				}
					
			}
			// An EDHOC error message has to be returned in response to EDHOC message_3
			// The session has been possibly purged while attempting to process message_3
			else {				
				int responseCodeValue = processingResult.get(1).AsInt32();
				ResponseCode responseCode = ResponseCode.valueOf(responseCodeValue);
				sendErrorMessage(exchange, nextMessage, appProfile, responseCode);
			}
			
			return;
			
		}
		
		
		/* Start handling EDHOC Error Message */
		if (messageType == Constants.EDHOC_ERROR_MESSAGE) {
            
        	CBORObject[] objectList = MessageProcessor.readErrorMessage(message, null, edhocEndpointInfo.getEdhocSessions());
        	
        	if (objectList != null) {
        	
	        	// The first element is always C_X.
	        	CBORObject cX = objectList[0];
	        	byte[] connectionIdentifier = MessageProcessor.decodeIdentifier(cX);
	        	
	    		if (connectionIdentifier == null) {
	    			System.err.println("Malformed or invalid connection identifier in EDHOC Error Message");
	    			return;
	    		}
	        	
	        	// Retrieve ERR_CODE
	        	int errorCode = objectList[1].AsInt32();
	        	System.out.println("ERR_CODE: " + errorCode + "\n");
	        	
	        	// Retrieve ERR_INFO
	    		if (errorCode == Constants.ERR_CODE_SUCCESS) {
	    			System.out.println("Success\n");
	    		}
	    		else if (errorCode == Constants.ERR_CODE_UNSPECIFIED_ERROR) {
		        	String errMsg = objectList[2].toString();
		        	System.out.println("ERR_INFO: " + errMsg + "\n");
	    		}
	    		else if (errorCode == Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
	    			CBORObject suitesR = objectList[2];
					if (suitesR.getType() == CBORType.Integer) {
			        	System.out.println("SUITES_R: " + suitesR.AsInt32() + "\n");
					}
					else if (suitesR.getType() == CBORType.Array) {
						System.out.print("SUITES_R: [ " );
						for (int i = 0; i < suitesR.size(); i++) {
							System.out.print(suitesR.get(i).AsInt32() + " " );
						}
						System.out.println("]\n");
					}
	    		}
	        	
	        	// The following simply deletes the EDHOC session. However, if the server was the Initiator 
	        	// and the EDHOC Error Message is a reply to an EDHOC Message 1, it would be fine to prepare a new
	        	// EDHOC Message 1 right away, keeping the same Connection Identifier C_I and this same session.
	        	// In fact, the session is marked as "used", hence new ephemeral keys would be generated when
	        	// preparing a new EDHOC Message 1. 
	        	
	    		CBORObject connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
	        	EdhocSession mySession = edhocEndpointInfo.getEdhocSessions().get(connectionIdentifierCbor);
	    		if (mySession == null) {
	    			System.err.println("EDHOC session to delete not found");
	    			return;
	    		}
	    		
	        	Util.purgeSession(mySession, connectionIdentifier,
	        					  edhocEndpointInfo.getEdhocSessions(),
	        					  edhocEndpointInfo.getUsedConnectionIds());
	        	
	        	// Just send an empty response back
	        	Response myResponse = new Response(ResponseCode.CHANGED);
	        	nextMessage = new byte[] {};
	        	
	        	// Uncomment to have the response as a confirmable Separate Response
	        	// myResponse.setConfirmable(true);
	        	
	        	myResponse.setPayload(nextMessage);
	        	exchange.respond(myResponse);
	        	
	        	/*
	        	// Alternative sending an empty ACK instead
		        if (exchange.advanced().getRequest().isConfirmable()) {
		        	exchange.accept();
		        }
		        */
        	
			}
        	
    		return;
			
		}
		

	}
	
	private void sendErrorMessage(CoapExchange exchange, byte[] nextMessage,
			                      AppProfile appProfile, ResponseCode responseCode) {
		
		int responseType = MessageProcessor.messageType(nextMessage, false, edhocEndpointInfo.getEdhocSessions(), null);
		
		if (responseType != Constants.EDHOC_ERROR_MESSAGE) {
			System.err.println("Inconsistent state before sending EDHOC Error Message");	
			return;
		}
		
		Response myResponse = new Response(responseCode);
		myResponse.getOptions().setContentFormat(Constants.APPLICATION_EDHOC_CBOR_SEQ);
		myResponse.setPayload(nextMessage);
		
		Util.nicePrint("EDHOC Error Message", nextMessage);
		
		exchange.respond(myResponse);
		
	}
	
	/*
	 * Process a "trigger request" targeting the EDHOC resource
	 */
	private void processTriggerRequest(CoapExchange request, AppProfile appProfile) {
		// Do nothing
		System.out.println("Entered processTriggerRequest()");
		
		// Here the server can start acting as Initiator and send an EDHOC Message 1 as a CoAP response
	}
	
}

