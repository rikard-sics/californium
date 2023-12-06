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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

class ClientEdhocExecutor {
	
	private final boolean debugPrint = true;

	// Used to store the created EDHOC session, to be accessible for the application
	private EdhocSession edhocSession = null;
	
	// Used to store the list of EDHOC cipher suites supported by the other peer, as learned
	// from an EDHOC error message with ERR_CODE = 1 received as a reply to EDHOC message_1 
	List<Integer> learnedPeerSupportedCipherSuites = new ArrayList<Integer>();
	
	// Used to store the application response to the EDHOC+OSCORE combined request, to be accessible for the application
	private CoapResponse appResponseToCombinedRequest = null;
	
	// Simpler version, for when the client does not use the EDHOC + OSCORE combined request
    /**
     *  Start EDHOC as a CoAP client, i.e., by sending EDHOC message_1 as a CoAP request
     *  
     * @param authenticationMethod   The authentication method to include in EDHOC message_1
     * @param peerSupportedCipherSuites   The EDHOC cipher suites supported by the other peer, as far as this peer knows
     * @param ownIdCreds   Each element is the ID_CRED_X used for an authentication credential associated to this peer
     * @param edhocEndpointInfo   The set of information for this EDHOC endpoint
     * @return  The result from this EDHOC execution.
     *          When EDHOC is used for OSCORE, it is true if EDHOC has completed successfully and the
     *          OSCORE Security Context has been correctly derived and installed. Otherwise, it is false.
     *          When EDHOC is not used for OSCORE, it is true if EDHOC has completed successfully. Otherwise, it is false.
     */
	public boolean startEdhocExchangeAsInitiator(final int authenticationMethod, List<Integer> peerSupportedCipherSuites,
												 final Set<CBORObject> ownIdCreds, EdhocEndpointInfo edhocEndpointInfo) {
		
		return startEdhocExchangeAsInitiator(authenticationMethod, peerSupportedCipherSuites, ownIdCreds,
											 edhocEndpointInfo, false, null, null, null, null);
		
	}
	
	// Extended version, for controlling the use of the EDHOC + OSCORE combined request
    /**
     *  Start EDHOC as a CoAP client, i.e., by sending EDHOC message_1 as a CoAP request
     *
     * @param authenticationMethod   The authentication method to include in EDHOC message_1
     * @param peerSupportedCipherSuites   The EDHOC cipher suites supported by the other peer, as far as this peer knows
     * @param ownIdCreds   Each element is the ID_CRED_X used for an authentication credential associated to this peer
     * @param edhocEndpointInfo   The set of information for this EDHOC endpoint
     * @param OSCORE_EDHOC_COMBINED   True if the EDHOC + OSCORE combined request has to be used, or false otherwise
     * @param edhocCombinedRequestURI   URI of the application resource to target with the EDHOC + OSCORE combined request
     * @param combinedRequestAppCode   CoAP method to use for the application request sent within
     * 								   an EDHOC + OSCORE combined request
     * @param combinedRequestAppType   CoAP message type to use (CON or NON) for the application request
     *                                 sent within an EDHOC + OSCORE combined request
     * @param combinedRequestAppPayload   Payload of the application request sent within
     *                                    an EDHOC + OSCORE combined request. It can be null
     * @return  The result from this EDHOC execution.
     *          When EDHOC is used for OSCORE, it is true if EDHOC has completed successfully and the
     *          OSCORE Security Context has been correctly derived and installed. Otherwise, it is false.
     *          When EDHOC is not used for OSCORE, it is true if EDHOC has completed successfully. Otherwise, it is false.
     */
	public boolean startEdhocExchangeAsInitiator(final int authenticationMethod, List<Integer> peerSupportedCipherSuites,
												 final Set<CBORObject> ownIdCreds, EdhocEndpointInfo edhocEndpointInfo,
												 boolean OSCORE_EDHOC_COMBINED, String edhocCombinedRequestURI,
												 Code combinedRequestAppCode, Type combinedRequestAppType,
												 byte[] combinedRequestAppPayload) {

		HashMap<CBORObject, EdhocSession> edhocSessions = edhocEndpointInfo.getEdhocSessions();
		Set<CBORObject> usedConnectionIds = edhocEndpointInfo.getUsedConnectionIds();
		HashMap<CBORObject, OneKey> peerPublicKeys = edhocEndpointInfo.getPeerPublicKeys();
		HashMap<CBORObject, CBORObject> peerCredentials = edhocEndpointInfo.getPeerCredentials();
		
		String edhocURI = edhocEndpointInfo.getUri();
		AppProfile appProfile = edhocEndpointInfo.getAppProfiles().get(edhocURI);
		
		URI targetUri = null;
		try {
			targetUri = new URI(edhocURI);
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			return false;
		}
		CoapClient client = new CoapClient(targetUri);
		
		/*
		// Simple sending of a GET request
		
		CoapResponse response = null;
		
		try {
			response = client.get();
		} catch (ConnectorException | IOException e) {
			System.err.println("Got an error: " + e);
		}
		
		if (response != null) {
		
			System.out.println(response.getCode());
			System.out.println(response.getOptions());
			if (args.length > 1) {
				try (FileOutputStream out = new FileOutputStream(args[1])) {
					out.write(response.getPayload());
				} catch (IOException e) {
					System.err.println("Error while writing the response payload to file: " +  e.getMessage());
				}
			} else {
				System.out.println(response.getResponseText());
				
				System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
				// access advanced API with access to more details through
				// .advanced()
				System.out.println(Utils.prettyPrint(response));
			}
		} else {
			System.out.println("No response received.");
		}
		*/
		
		// Simple test with a dummy payload
		/*
		byte[] requestPayload = { (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03 };
		
		Request edhocMessage1 = new Request(Code.POST, Type.CON);
		edhocMessage1.setPayload(requestPayload);
		
		// Submit the request
		System.out.println("\nSent EDHOC Message1\n");
		CoapResponse edhocMessage2;
		try {
			edhocMessage2 = client.advanced(edhocMessage1);
		} catch (ConnectorException e) {
			System.err.println("ConnectorException when sending EDHOC Message1");
			return;
		} catch (IOException e) {
			System.err.println("IOException when sending EDHOC Message1");
			return;
		}
		
		byte[] responsePayload = edhocMessage2.getPayload();
		System.out.println("\nResponse: " + new String(responsePayload) + "\n");
		*/		
		
		
		/* Prepare and send EDHOC Message 1 */
		
		EdhocSession session = MessageProcessor.createSessionAsInitiator(authenticationMethod,
																		 edhocEndpointInfo.getKeyPairs(),
																		 edhocEndpointInfo.getIdCreds(),
																		 edhocEndpointInfo.getCreds(),
																		 edhocEndpointInfo.getSupportedCipherSuites(),
																		 peerSupportedCipherSuites,
																		 edhocEndpointInfo.getSupportedEADs(),
																		 edhocEndpointInfo.getEadProductionInput(),
																		 edhocEndpointInfo.getUsedConnectionIds(),
																		 appProfile, edhocEndpointInfo.getTrustModel(),
																		 edhocEndpointInfo.getOscoreDb());
		
		SideProcessor sideProcessor = new SideProcessor(edhocEndpointInfo.getTrustModel(),
														edhocEndpointInfo.getPeerCredentials(),
														edhocEndpointInfo.getEadProductionInput());
		
		// Provide the side processor object with the just created EDHOC session.
		// A reference to the sideProcessor is also going to be stored in the EDHOC session.
		sideProcessor.setEdhocSession(session);
		
		// Store a reference to the EDHOC session, to be accessible for the application after EDHOC completion
		this.edhocSession = session;
		
		// At this point, the initiator may overwrite the information in the EDHOC session about the supported cipher suites
		// and the selected cipher suite, based on a previously received EDHOC Error Message
		
		byte[] nextPayload = MessageProcessor.writeMessage1(session);
		
		if (nextPayload == null || session.getCurrentStep() != Constants.EDHOC_BEFORE_M1) {
			System.err.println("Inconsistent state before sending EDHOC Message 1");
			session.deleteTemporaryMaterial();
			session = null;
			client.shutdown();
			return false;
		}
		
		// Add the new session to the list of existing EDHOC sessions
		session.setCurrentStep(Constants.EDHOC_AFTER_M1);
		
		// Compute and store the hash of EDHOC Message 1
		// The first byte 0xf5 sent in the CoAP request must be skipped
		byte[] hashInput = new byte[nextPayload.length - 1];
		System.arraycopy(nextPayload, 1, hashInput, 0, hashInput.length);
		session.setHashMessage1(hashInput);

		byte[] connectionIdentifier = session.getConnectionId();
		CBORObject connectionIdentifierCbor = CBORObject.FromObject(connectionIdentifier);
		edhocSessions.put(connectionIdentifierCbor, session);
		
		Request edhocMessageReq = new Request(Code.POST, Type.CON);
		edhocMessageReq.getOptions().setContentFormat(Constants.APPLICATION_CID_EDHOC_CBOR_SEQ);
		edhocMessageReq.setPayload(nextPayload);
		
		System.out.println("Sent EDHOC Message 1\n");
		
		CoapResponse edhocMessageResp;
		try {
			session.setCurrentStep(Constants.EDHOC_SENT_M1);
			edhocMessageResp = client.advanced(edhocMessageReq);
		} catch (ConnectorException e) {
			System.err.println("ConnectorException when sending EDHOC Message 1");
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			client.shutdown();
			return false;
		} catch (IOException e) {
			System.err.println("IOException when sending EDHOC Message 1");
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			client.shutdown();
			return false;
		}
		
		boolean discontinue = false;
		int responseType = -1;
		byte[] responsePayload = null; 
		
		if (edhocMessageResp != null)
		responsePayload = edhocMessageResp.getPayload();
		
		if (responsePayload == null) {
			discontinue = true;
		}
		else {
			responseType = MessageProcessor.messageType(responsePayload, false, edhocSessions, connectionIdentifier);
			if (responseType != Constants.EDHOC_MESSAGE_2 && responseType != Constants.EDHOC_ERROR_MESSAGE)
			discontinue = true;
		}
		if (discontinue == true) {
			System.err.println("Received invalid reply to EDHOC Message 1");
			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			client.shutdown();
			return false;
		}
		
		String myString = (responseType == Constants.EDHOC_MESSAGE_2) ? "EDHOC Message 2" : "EDHOC Error Message";
		System.out.println("Determined EDHOC message type: " + myString + "\n");
		Util.nicePrint("EDHOC message " + responseType, responsePayload);
		
		
		/* Process the received response */
		
		// This response relates to the previous request through the CoAP Token.
		// Hence, the Initiator knows what session to refer to, from which the correct C_I can be retrieved
		
		nextPayload = new byte[] {};
		
		// The received message is an EDHOC Error Message
		if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
			
			CBORObject[] objectList = MessageProcessor.readErrorMessage(responsePayload, connectionIdentifier, edhocSessions);
			processErrorMessageAsResponse(objectList, Constants.EDHOC_MESSAGE_1);

			Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
			client.shutdown();
			return false;
		
		}
		
		// The received message is an EDHOC Message 2
		if (responseType == Constants.EDHOC_MESSAGE_2) {
		
			OSCoreCtx ctx = null;
			List<CBORObject> processingResult = new ArrayList<CBORObject>();
			
			/* Start handling EDHOC Message 2 */
			
			processingResult = MessageProcessor.readMessage2(responsePayload, false, connectionIdentifier, edhocSessions,
									 						 peerPublicKeys, peerCredentials, usedConnectionIds, ownIdCreds);
			
			if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
				System.err.println("Error when processing EDHOC Message 2");
				Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
				client.shutdown();
				return false;
			}
			
			// A non-zero length response payload would be an EDHOC Error Message
			nextPayload = processingResult.get(0).GetByteString();
			
			// Prepare EDHOC Message 3
			if (nextPayload.length == 0) {
			
				session.setCurrentStep(Constants.EDHOC_AFTER_M2);
				
				nextPayload = MessageProcessor.writeMessage3(session);
				
				if (nextPayload == null || session.getCurrentStep() != Constants.EDHOC_AFTER_M3) {
					System.err.println("Inconsistent state before sending EDHOC Message 3");
					Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
					client.shutdown();
					return false;
				}
			
			}
			
			int requestType = MessageProcessor.messageType(nextPayload, true, edhocSessions, connectionIdentifier);
			
			if (requestType != Constants.EDHOC_MESSAGE_3 && requestType != Constants.EDHOC_ERROR_MESSAGE) {
				System.err.println("Error when producing EDHOC message_3");
				Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
				client.shutdown();
				return false;
			}
			
			myString = (requestType == Constants.EDHOC_MESSAGE_3) ? "EDHOC Message 3" : "EDHOC Error Message";
			
			if (requestType == Constants.EDHOC_MESSAGE_3) {
			
				System.out.println("Sent EDHOC Message 3\n");
				
				if (session.getApplicationProfile().getUsedForOSCORE() == true) {
				
					/* Invoke the EDHOC-Exporter to produce OSCORE input material */
					byte[] masterSecret = EdhocSession.getMasterSecretOSCORE(session);
					byte[] masterSalt = EdhocSession.getMasterSaltOSCORE(session);
					if (debugPrint) {
						Util.nicePrint("OSCORE Master Secret", masterSecret);
						Util.nicePrint("OSCORE Master Salt", masterSalt);
					}
					
					/* Setup the OSCORE Security Context */
					
					// The Sender ID of this peer is the EDHOC connection identifier of the other peer
					byte[] senderId = session.getPeerConnectionId();
					
					int selectedCipherSuite = session.getSelectedCipherSuite();
					AlgorithmID alg = EdhocSession.getAppAEAD(selectedCipherSuite);
					AlgorithmID hkdf = EdhocSession.getAppHkdf(selectedCipherSuite);
					
					byte[] recipientId = connectionIdentifier;
					if (Arrays.equals(senderId, recipientId)) {
						System.err.println("Error: the Sender ID coincides with the Recipient ID " + Utils.toHexString(senderId));
						Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
						client.shutdown();
						return false;
					}
					try {
						int OSCORE_REPLAY_WINDOW = edhocEndpointInfo.getOscoreReplayWindow();
						int MAX_UNFRAGMENTED_SIZE = edhocEndpointInfo.getOscoreMaxUnfragmentedSize();
						
						ctx = new OSCoreCtx(masterSecret, true, alg, senderId, recipientId, hkdf,
						           			OSCORE_REPLAY_WINDOW, masterSalt, null, MAX_UNFRAGMENTED_SIZE);
					} catch (OSException e) {
						System.err.println("Error when deriving the OSCORE Security Context " + e.getMessage());
						Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
						client.shutdown();
						return false;
					}
					
					try {
						edhocEndpointInfo.getOscoreDb().addContext(edhocURI, ctx);
					} catch (OSException e) {
						System.err.println("Error when adding the OSCORE Security Context to the context database " + e.getMessage());
						Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
						client.shutdown();
						return false;
					}
				
				}
			
			}
			else if (requestType == Constants.EDHOC_ERROR_MESSAGE) {
			
				// The Error Message was generated while reading EDHOC Message 2,
				
				Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
				edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
				System.out.println("Sent EDHOC Error Message\n");
				
				if (debugPrint) {
				
					// Since the EDHOC error message is transported in a CoAP request, do not print the prepended C_R
					
					byte[] sequenceBytesToPrint;
					CBORObject[] objectList = null;
					
					try {
						objectList = CBORObject.DecodeSequenceFromBytes(nextPayload);
					}
					catch (Exception e) {
						System.err.println("Error while preparing an EDHOC error message");
						client.shutdown();
						return false;
					}
					
					List<CBORObject> trimmedSequence = new ArrayList<CBORObject>();
					
					for (int i = 1; i < objectList.length; i++) {
						trimmedSequence.add(objectList[i]);
					}
					sequenceBytesToPrint = Util.buildCBORSequence(trimmedSequence);
					Util.nicePrint("EDHOC Error Message", sequenceBytesToPrint);
				
				}
			
			}
			
			CoapResponse edhocMessageResp2 = null;
			
			try {
				Request edhocMessageReq2 = new Request(Code.POST, Type.CON);
				edhocMessageReq2.setPayload(nextPayload);
				
				// If EDHOC message_3 has to be combined with the first
				// OSCORE-protected request include the EDHOC option in the request
				if (OSCORE_EDHOC_COMBINED == true && requestType == Constants.EDHOC_MESSAGE_3 &&
				    session.getApplicationProfile().getUsedForOSCORE() == true &&
				    session.getApplicationProfile().getSupportCombinedRequest() == true) {
				
					// The combined request cannot be used if the Responder has to send message_4
					if (session.getApplicationProfile().getUseMessage4() == true) {
						System.err.println("Cannot send the EDHOC + OSCORE combined request if message_4 is expected\n");
						Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
						edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
						client.shutdown();
						return false;
					}
					
					client = new CoapClient(edhocCombinedRequestURI);
					CoapResponse protectedResponse = null;
					edhocMessageReq2 = new Request(combinedRequestAppCode, combinedRequestAppType);
					if ((combinedRequestAppCode == Code.POST || combinedRequestAppCode == Code.PUT ||
					     combinedRequestAppCode == Code.FETCH || combinedRequestAppCode == Code.PATCH ||
					     combinedRequestAppCode == Code.IPATCH) && combinedRequestAppPayload != null) {
						edhocMessageReq2.setPayload(combinedRequestAppPayload);
					}
					edhocMessageReq2.getOptions().setOscore(Bytes.EMPTY);
					
					edhocMessageReq2.getOptions().setEdhoc(true);
					session.setMessage3(nextPayload);
					
					try {
						// Send the EDHOC+OSCORE combined request
						System.out.println("Sent EDHOC Message 3 as part of an EDHOC+OSCORE combined request\n");
						session.setCurrentStep(Constants.EDHOC_SENT_M3);
						protectedResponse = client.advanced(edhocMessageReq2);
					} catch (ConnectorException e) {
						System.err.println("ConnectorException when sending a protected request\n");
						Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
						edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
						client.shutdown();
						return false;
					} catch (IOException e) {
						System.err.println("IOException when sending a protected request\n");
						Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
						edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
						client.shutdown();
						return false;
					}
	
					boolean error = false;
					byte[] myPayload = null;
					
					if (protectedResponse != null) {						
						if (protectedResponse.advanced().isError() && !protectedResponse.getOptions().hasOscore()) {
							// This error response was produced by the server before a possible successful decryption with OSCORE.
							// Hence, this is a CoAP error response not protected with OSCORE. Later checks assess whether this is
							// specifically an EDHOC error message. Regardless, the ongoing EDHOC session is going to be purged.
							
							System.out.println(Utils.prettyPrint(protectedResponse) + "\n");
							error = true;
						}
						
						myPayload = protectedResponse.getPayload();
					}

					if (myPayload != null) {
					
						int contentFormat = protectedResponse.getOptions().getContentFormat();
						int restCode = protectedResponse.getCode().value;
						
						// Check if it is an EDHOC Error Message returned by the server
						// when processing the EDHOC+OSCORE combined request
						if (contentFormat == Constants.APPLICATION_EDHOC_CBOR_SEQ &&
						    ((restCode == ResponseCode.BAD_REQUEST.value) || (restCode == ResponseCode.INTERNAL_SERVER_ERROR.value)) ) {

							responseType = MessageProcessor.messageType(myPayload, false, edhocSessions, connectionIdentifier);
							
							if (responseType == Constants.EDHOC_ERROR_MESSAGE) {
								System.err.println("Received an EDHOC Error Message");
								CBORObject[] objectList = MessageProcessor.readErrorMessage(myPayload, connectionIdentifier,
																							edhocSessions);
								processErrorMessageAsResponse(objectList, Constants.EDHOC_MESSAGE_3);
							}
							else {
								System.err.println("Received invalid reply to the EDHOC+OSCORE combined request");
							}
						
						}
					
					}
					
					if (error == true) {
						Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
						edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
						client.shutdown();
						return false;
					}
					
					this.appResponseToCombinedRequest = protectedResponse;
					session.cleanMessage3();
				
				} // End preparing the EDHOC+OSCORE combined request, if that was the intention
				else {
				
					if (requestType == Constants.EDHOC_ERROR_MESSAGE) {
						// The request to send is an EDHOC Error Message
						edhocMessageReq2.setConfirmable(true);
						edhocMessageReq2.setURI(targetUri);
						edhocMessageResp2 = client.advanced(edhocMessageReq2);
						client.shutdown();
						return false;
					}
					// The request to send is EDHOC message_3
					session.setCurrentStep(Constants.EDHOC_SENT_M3);
					edhocMessageReq2.getOptions().setContentFormat(Constants.APPLICATION_CID_EDHOC_CBOR_SEQ);
					edhocMessageResp2 = client.advanced(edhocMessageReq2);
				
				}
			
			} catch (ConnectorException e) {
				System.err.println("ConnectorException when sending " + myString + "\n");
				Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
				edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
				client.shutdown();
				return false;
			} catch (IOException e) {
				System.err.println("IOException when sending "  + myString + "\n");
				Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
				edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
				client.shutdown();
				return false;
			}
			
			// Wait for a possible response. For how long?
			
			// Only an EDHOC message_4 or an EDHOC Error Message is a legitimate EDHOC message at this point
			if (edhocMessageResp2 != null) {
				responseType = -1;
				responsePayload = null;
				boolean expectMessage4 = session.getApplicationProfile().getUseMessage4();
				
				if (edhocMessageResp2 != null) {
					responsePayload = edhocMessageResp2.getPayload();
				}
				
				if (responsePayload == null) {
					discontinue = true;
				}
				else {
					responseType = MessageProcessor.messageType(responsePayload, false, edhocSessions, connectionIdentifier);
					
					// It is always consistent to receive an Error Message
					if (responseType != Constants.EDHOC_ERROR_MESSAGE) {
					
						if (responseType == Constants.EDHOC_MESSAGE_4) {
							if (expectMessage4 == false) {
								discontinue = true;
							}
							// Else it is fine, i.e., it is message_4 and it is expected
						}
						else {
							// Any other message than message_4 and Error Message
							if (expectMessage4 == true) {
								System.err.println("Received invalid reply to EDHOC Message 3 while expecting Message 4");
								System.err.println("responseType: " + responseType);
								discontinue = true;
							}
							else {
								// This is a generic response received as reply to EDHOC Message 3
								processResponseAfterEdhoc(edhocMessageResp2);
							}
						}
					
					}
					// It is an EDHOC Error Message
					else {
						System.err.println("Received an EDHOC Error Message");
						Util.nicePrint("EDHOC Error Message", responsePayload);
						CBORObject[] objectList = MessageProcessor.readErrorMessage(responsePayload, connectionIdentifier, edhocSessions);
						processErrorMessageAsResponse(objectList, Constants.EDHOC_MESSAGE_3);
						discontinue = true;
					}
				
				}
				if (discontinue == true) {
					Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
					edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
					client.shutdown();
					return false;
				}
				
				if (responseType == Constants.EDHOC_MESSAGE_4) {
					processingResult = MessageProcessor.readMessage4(responsePayload, false, connectionIdentifier,
					                                    			 edhocSessions, usedConnectionIds);
					
					if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
						System.err.println("Error when processing EDHOC Message 4");
						Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
						edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
						client.shutdown();
						return false;
					}
					
					// A non-zero length response payload would be an EDHOC Error Message
					byte[] nextMessage = processingResult.get(0).GetByteString();
					
					// The EDHOC message_4 was successfully processed
					if (nextMessage.length == 0) {
					
						// If message_4 was a Confirmable response, send an empty ACK
						
						if (edhocMessageResp2.advanced().isConfirmable()) {
							edhocMessageResp2.advanced().acknowledge();
						}
					
					}
					// An EDHOC error message has to be returned in reply to EDHOC message_4
					else {
						Request edhocMessageReq3 = new Request(Code.POST, Type.CON);
						edhocMessageReq3.setPayload(nextMessage);
						
						try {
							edhocMessageResp = client.advanced(edhocMessageReq3);
						} catch (ConnectorException e) {
							System.err.println("ConnectorException when sending EDHOC Error Message");
						} catch (IOException e) {
							System.err.println("IOException when sending EDHOC Error Message");
						}
						Util.purgeSession(session, connectionIdentifier, edhocSessions, usedConnectionIds);
						edhocEndpointInfo.getOscoreDb().removeContext(ctx); // Delete the previously derived OSCORE Security Context
						client.shutdown();
						return false;
					}
				
				}
			
			} // End handling of reception of EDHOC message_4 or EDHOC error message, after having sent EDHOC message_3
							
		} // End handling of reception of EDHOC message_2

		client.shutdown();
		return true;
		
	} // End of startEdhocExchangeAsInitiator()
	
	
	/*
	 * Process a generic response received as reply to EDHOC Message 3
	 */
	private void processResponseAfterEdhoc(CoapResponse msg) {
		// Do nothing
		System.out.println("ResponseAfterEdhoc()");
	}
	
	
	/*
	 * Process an EDHOC Error Message as a CoAP response
	 */
	private void processErrorMessageAsResponse(CBORObject[] objectList, int messageNumber) {

    	if (objectList != null) {
    		
    		int index = 0;
    		
        	// Retrieve ERR_CODE
        	int errorCode = objectList[index].AsInt32();
        	System.out.println("ERR_CODE: " + errorCode + "\n");
        	index++;
        	
        	// Retrieve ERR_INFO
    		if (errorCode == Constants.ERR_CODE_UNSPECIFIED_ERROR) {
	        	String errMsg = objectList[index].toString();
	        	System.out.println("DIAG_MSG: " + errMsg + "\n");
    		}
    		else if (errorCode == Constants.ERR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
    			learnedPeerSupportedCipherSuites = new ArrayList<Integer>();
    			CBORObject suitesR = objectList[index];
    			
				if (suitesR.getType() == CBORType.Integer) {
					int suite = suitesR.AsInt32();
					learnedPeerSupportedCipherSuites.add(Integer.valueOf(suite));
		        	System.out.println("SUITES_R: " + suite + "\n");
				}
				else if (suitesR.getType() == CBORType.Array) {
					System.out.print("SUITES_R: [ " );
					for (int i = 0; i < suitesR.size(); i++) {
						int suite = suitesR.get(i).AsInt32();
						learnedPeerSupportedCipherSuites.add(Integer.valueOf(suite));
						System.out.print(suite + " " );
					}
					System.out.println("]\n");
				}
    		}

    	}
		
	}
	
    /**
     *  Retrieve the EDHOC session associated with this EDHOC exchange
     *  
     * @return  The EDHOC session associated with this EDHOC exchange
     */
	public EdhocSession getEdhocSession() {
		return this.edhocSession;
	}
	
    /**
     * Retrieve the list of EDHOC cipher suites supported by the other peer, as learned
	 * from an EDHOC error message with ERR_CODE = 1 received as a reply to EDHOC message_1 
     *  
     * @return  The learned list of EDHOC cipher suites supported by the other peer
     */
	public List<Integer> getLearnedPeerSupportedCipherSuites() {		
		return this.learnedPeerSupportedCipherSuites;
	}
	
    /**
     *  Retrieve the application response to the EDHOC+OSCORE combined request
     *  
     * @return  The result application response to the EDHOC+OSCORE combined request
     */
	public CoapResponse getAppResponseToCombinedRequest() {		
		return this.appResponseToCombinedRequest;
	}
		
}
