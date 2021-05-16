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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.core.CoapResource;
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
	
	private static final boolean debugPrint = true;
	
	public EdhocResource(String resourceIdentifier, EdhocEndpointInfo edhocEndpointInfo) {
		
		// set resource identifier
		super(resourceIdentifier);

		// set the information about the EDHOC server hosting this EDHOC resource
		this.edhocEndpointInfo = edhocEndpointInfo;
		
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
		
		// Retrieve the applicability statement to use
		AppStatement appStatement = edhocEndpointInfo.getAppStatements().get(exchange.advanced().getRequest().getURI());
		
		// Error when retrieving the applicability statement for this EDHOC resource
		if (appStatement == null) {
			String responseString = new String("Error when retrieving the applicability statement");
			nextMessage = responseString.getBytes(Constants.charset);
			Response genericErrorResponse = new Response(ResponseCode.INTERNAL_SERVER_ERROR);
			genericErrorResponse.setPayload(nextMessage);
			exchange.respond(genericErrorResponse);
			return;
			
		}
		
		if (exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_EDHOC) {
			// Then the server can start acting as Initiator and send an EDHOC Message 1 as a CoAP response
			processNonEdhocMessage(exchange, appStatement);	
		}
		
		// The content-format is application/edhoc so an actual EDHOC message is expected to be processed
			
		byte[] message = exchange.getRequestPayload();
		int messageType = MessageProcessor.messageType(message, true, edhocEndpointInfo.getEdhocSessions(), null, appStatement);
		
		// Invalid EDHOC message type
		if (messageType == -1) {
			String responseString = new String("Invalid EDHOC message type");
			nextMessage = responseString.getBytes(Constants.charset);
			Response genericErrorResponse = new Response(ResponseCode.BAD_REQUEST);
			genericErrorResponse.setPayload(nextMessage);
			exchange.respond(genericErrorResponse);
			return;
			
		}
		
		List<CBORObject> processingResult = new ArrayList<CBORObject>();
		
		// Possibly specify application data for AD_2, or null if none have to be provided
		byte[] ad2 = null;		
		
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
		Util.nicePrint(typeName, message);

		
		/* Start handling EDHOC Message 1 */
		
		if (messageType == Constants.EDHOC_MESSAGE_1) {
			
			// Determine the Correlation expected to be advertised in EDHOC Message 1			
			int expectedCorr = appStatement.getCorrelation() ? Constants.EDHOC_CORR_1 : Constants.EDHOC_CORR_0;
			
			processingResult = MessageProcessor.readMessage1(expectedCorr, message,
															 edhocEndpointInfo.getSupportedCiphersuites(),
															 appStatement);

			if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
				System.err.println("Internal error when processing EDHOC Message 1");
				return;
			}
			
			EdhocSession session = null;
			int responseType = -1;
						
			// A non-zero length response payload would be an EDHOC Error Message
			nextMessage = processingResult.get(0).GetByteString();
			
			// Prepare EDHOC Message 2
			if (nextMessage.length == 0) {
				
				// Deliver AD_1 to the application, if present
				if (processingResult.size() == 2) {
					processAD1(processingResult.get(1).GetByteString());
				}
				
				session = MessageProcessor.createSessionAsResponder(message, edhocEndpointInfo.getKeyPair(),
																    edhocEndpointInfo.getIdCred(), edhocEndpointInfo.getCred(),
																    edhocEndpointInfo.getSupportedCiphersuites(),
																    edhocEndpointInfo.getUsedConnectionIds(), appStatement);
				
				// Compute the EDHOC Message 2
				nextMessage = MessageProcessor.writeMessage2(session, ad2);

				byte[] connectionId = session.getConnectionId();
				
				// Deallocate the assigned Connection Identifier for this peer
				if (nextMessage == null || session.getCurrentStep() != Constants.EDHOC_BEFORE_M2) {
					System.err.println("Inconsistent state before sending EDHOC Message 2");
					Util.releaseConnectionId(connectionId, edhocEndpointInfo.getUsedConnectionIds());
					session.deleteTemporaryMaterial();
					session = null;
					return;
				}
				
				if(MessageProcessor.messageType(nextMessage, false, edhocEndpointInfo.getEdhocSessions(),
						                        connectionId, appStatement) == Constants.EDHOC_MESSAGE_2) {
					// Add the new session to the list of existing EDHOC sessions
					session.setCurrentStep(Constants.EDHOC_AFTER_M2);
					edhocEndpointInfo.getEdhocSessions().put(CBORObject.FromObject(connectionId), session);
				}
				
			}
			
			byte[] connectionIdentifier = null;
			if (session != null) {
				connectionIdentifier = session.getConnectionId();
			}
			
			responseType = MessageProcessor.messageType(nextMessage, false, edhocEndpointInfo.getEdhocSessions(),
														connectionIdentifier, appStatement);
			
			if (responseType != Constants.EDHOC_MESSAGE_2 && responseType != Constants.EDHOC_ERROR_MESSAGE) {
				nextMessage = null;
			}
			
			if (nextMessage != null) {
				Response myResponse = new Response(ResponseCode.CHANGED);
				myResponse.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
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
						Util.releaseConnectionId(session.getConnectionId(), edhocEndpointInfo.getUsedConnectionIds());
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
				System.err.println("Inconsistent state before after processing EDHOC Message 1");
				Util.purgeSession(session, CBORObject.FromObject(session.getConnectionId()),
																 edhocEndpointInfo.getEdhocSessions(),
																 edhocEndpointInfo.getUsedConnectionIds());
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
			
			processingResult = MessageProcessor.readMessage3(message, null,
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
				
				// Deliver AD_3 to the application, if present
				if (processingResult.size() == 3) {
					// Elements of 'processingResult' are:
					//   i) A zero-length CBOR byte string, indicating successful processing;
					//  ii) The Connection Identifier of the Responder, i.e. C_R
					// iii) Optionally, the Application Data AD_3
					processAD3(processingResult.get(2).GetByteString());
				}
				
				CBORObject cR = processingResult.get(1);
				mySession = edhocEndpointInfo.getEdhocSessions().get(cR);
				
				if (mySession == null) {
					System.err.println("Inconsistent state before sending EDHOC Message 3");
					return;
				}
				if (mySession.getCurrentStep() != Constants.EDHOC_AFTER_M3) {
						System.err.println("Inconsistent state before sending EDHOC Message 3");							
						Util.purgeSession(mySession, CBORObject.FromObject(mySession.getConnectionId()),
																		   edhocEndpointInfo.getEdhocSessions(),
																		   edhocEndpointInfo.getUsedConnectionIds());
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
										recipientId, hkdf, edhocEndpointInfo.getOscoreReplayWindow(), masterSalt, null);
				} catch (OSException e) {
					System.err.println("Error when deriving the OSCORE Security Context " + e.getMessage());						
					Util.purgeSession(mySession,
									  CBORObject.FromObject(mySession.getConnectionId()),
									  edhocEndpointInfo.getEdhocSessions(),
									  edhocEndpointInfo.getUsedConnectionIds());
					return;
				}
		        
		        try {
		        	edhocEndpointInfo.getOscoreDb().addContext(edhocEndpointInfo.getUri(), ctx);
				} catch (OSException e) {
					System.err.println("Error when adding the OSCORE Security Context to the context database " + e.getMessage());							
					Util.purgeSession(mySession,
									  CBORObject.FromObject(mySession.getConnectionId()),
									  edhocEndpointInfo.getEdhocSessions(),
									  edhocEndpointInfo.getUsedConnectionIds());
					return;
				}			        			        
		        
		        // Prepare the response to send back
		        Response myResponse = new Response(ResponseCode.CHANGED);
		        
		        if (mySession.getApplicabilityStatement().getUseMessage4() == false) {
			        // Just send an empty response back
		        	
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
					byte[] connectionId = mySession.getConnectionId();
					nextMessage = MessageProcessor.writeMessage4(mySession);
					
					// Deallocate the assigned Connection Identifier for this peer
					if (nextMessage == null || mySession.getCurrentStep() != Constants.EDHOC_AFTER_M4) {
						System.err.println("Inconsistent state before sending EDHOC Message 4");
						Util.purgeSession(mySession, CBORObject.FromObject(connectionId),
																		   edhocEndpointInfo.getEdhocSessions(),
																		   edhocEndpointInfo.getUsedConnectionIds());
						return;
					}
					
					int responseType = MessageProcessor.messageType(nextMessage, false,
																	edhocEndpointInfo.getEdhocSessions(),
                            										connectionId, appStatement);

					if (responseType == Constants.EDHOC_MESSAGE_4 || responseType == Constants.EDHOC_ERROR_MESSAGE) {
						
						myResponse.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
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
					        
					        sendErrorMessage(exchange, nextMessage, appStatement);
					        Util.purgeSession(mySession, CBORObject.FromObject(connectionId),
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
						Util.purgeSession(mySession, CBORObject.FromObject(connectionId),
										  edhocEndpointInfo.getEdhocSessions(),
										  edhocEndpointInfo.getUsedConnectionIds());
						return;
					}
					
				}
					
			}
			// An EDHOC error message has to be returned in response to EDHOC message_3
			// The session has been possibly purged while attempting to process message_3
			else {
				sendErrorMessage(exchange, nextMessage, appStatement);
			}
			
			return;
			
		}
		
		
		/* Start handling EDHOC Error Message */
		if (messageType == Constants.EDHOC_ERROR_MESSAGE) {
            
        	CBORObject[] objectList = MessageProcessor.readErrorMessage(message, null, edhocEndpointInfo.getEdhocSessions());
        	
        	if (objectList != null) {
        	
	        	// If the server acts as Responder, Correlation is 1, hence the first element is C_X as C_R.
	        	// If the server acts as Initiator, Correlation is 2, hence the first element is C_X as C_I.
	        	CBORObject cX = objectList[0]; 
	        	EdhocSession mySession = edhocEndpointInfo.getEdhocSessions().get(cX);
	        	CBORObject connectionIdentifier = Util.decodeFromBstrIdentifier(cX);
	        	
	        	String errMsg = objectList[1].toString();
	        	
	        	System.out.println("DIAG_MSG: " + errMsg + "\n");
	        	
	        	// The following simply deletes the EDHOC session. However, if the server was the Initiator 
	        	// and the EDHOC Error Message is a reply to an EDHOC Message 1, it would be fine to prepare a new
	        	// EDHOC Message 1 right away, keeping the same Connection Identifier C_I and this same session.
	        	// In fact, the session is marked as "used", hence new ephemeral keys would be generated when
	        	// preparing a new EDHOC Message 1. 
	        	
	        	Util.purgeSession(mySession, connectionIdentifier,
	        					  edhocEndpointInfo.getEdhocSessions(),
	        					  edhocEndpointInfo.getUsedConnectionIds());
	        	
	        	// If the request is confirmable, send an empty ack
		        if (exchange.advanced().getRequest().isConfirmable())
		        	exchange.accept();
        	
			}
        	
    		return;
			
		}
		

	}
	
	private void sendErrorMessage(CoapExchange exchange, byte[] nextMessage, AppStatement appStatement) {
		
		int responseType = MessageProcessor.messageType(nextMessage, false,
														edhocEndpointInfo.getEdhocSessions(),
														null, appStatement);
		
		if (responseType != Constants.EDHOC_ERROR_MESSAGE) {
			System.err.println("Inconsistent state before sending EDHOC Error Message");	
			return;
		}
		
		Response myResponse = new Response(ResponseCode.CHANGED);
		myResponse.getOptions().setContentFormat(Constants.APPLICATION_EDHOC);
		myResponse.setPayload(nextMessage);
		
		exchange.respond(myResponse);
		
	}
	
	/*
	 * Process application data conveyed in AD_1 in EDHOC Message 1
	 */
	private void processAD1(byte[] ad1) {
		// Do nothing
		System.out.println("Entered processAD1()");
	}
	
	/*
	 * Process application data conveyed in AD_2 in EDHOC Message 2
	 */
	private void processAD2(byte[] ad2) {
		// Do nothing
		System.out.println("Entered processAD2()");
	}
	
	/*
	 * Process application data conveyed in AD_3 in EDHOC Message 3
	 */
	private void processAD3(byte[] ad3) {
		// Do nothing
		System.out.println("Entered processAD3()");
	}
	
	/*
	 * Process a request targeting the EDHOC resource with content-format different than application/edhoc
	 */
	private void processNonEdhocMessage(CoapExchange request, AppStatement appStatement) {
		// Do nothing
		System.out.println("Entered processNonEdhocMessage()");
		
		// Here the server can start acting as Initiator and send an EDHOC Message 1 as a CoAP response
		
		// The correlation to use is either 0 or 2, depending on the applicability statement for this EDHOC resource
	}
	
}

