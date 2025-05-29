package org.eclipse.californium.edhoc;

import java.util.HashMap;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.HashMapCtxDB;

import com.upokecenter.cbor.CBORObject;

/*
 * Collection of all the information related to an EDHOC endpoint.
 * 
 * For an EDHOC server, one instance is used for one or many of its EDHOC resources.
 * 
 * For an EDHOC client, one instance is used for one or many EDHOC sessions with the EDHOC resource of a server.
 */
public class EdhocEndpointInfo {
	
	// Authentication credentials of this peer
    //
    // At the top level, authentication credential are sorted by key usage of the authentication keys.
    // The outer map has label SIGNATURE_KEY or ECDH_KEY for distinguishing the two key usages. 
    
    // The asymmetric key pairs of this peer (one per supported curve)
	private HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
    
    // The identifiers of the authentication credentials of this peer
	private HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
    
    // The authentication credentials of this peer (one per supported curve)
	private HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
	
	// Public keys of other peers
	// 
	// The map label is a CBOR Map used as ID_CRED_X
	private HashMap<CBORObject, OneKey> peerPublicKeys;
	
	// Authentication credentials of other peers
	// 
	// The map label is a CBOR Map used as ID_CRED_X
	// The map value is a CBOR Byte String, with value the serialization of CRED_X
	private HashMap<CBORObject, CBORObject> peerCredentials;

	// Existing EDHOC Sessions, including completed ones
	// The map label is C_X, i.e. the connection identifier offered to the other peer, as a CBOR byte string
	private HashMap<CBORObject, EdhocSession> edhocSessions;
	
	// Each element is a used Connection Identifier offered to the other peers.
	// Connection Identifiers are stored as CBOR integers (if numeric) or as CBOR byte strings (if binary)
	private Set<CBORObject> usedConnectionIds;
	
	// List of supported cipher suites
	private List<Integer> supportedCipherSuites;
	
	// Set of supported EAD items
	private Set<Integer> supportedEADs;
	
	// This data structure collects instructions provided by the application for producing EAD items
	// to include in outgoing EDHOC messages. The production of these EAD items is not related to or
	// triggered by the consumption of other EAD items included in incoming EDHOC messages.
	// 
	// This data structure can be null if the application does not specify the production of any of such EAD items. 
	//
	// The outer map key indicates the outgoing EDHOC message in question.
	//
	// Each inner list specifies a sequence of element pairs (CBOR integer, CBOR map).
	// The CBOR integer specifies the ead_label in case of non-critical EAD item,
	// or the corresponding negative value in case of critical EAD item.
	// The CBOR map provides input on how to produce the EAD item,
	// with the map keys from a namespace specific of the ead_label.
	private HashMap<Integer, List<CBORObject>> eadProductionInput;
	
	// The trust model for validating authentication credentials of other peers
	private int trustModel;
	
	// The database of OSCORE Security Contexts
	private HashMapCtxDB db;
	
	// URI of the EDHOC resource, also used as lookup identifier associated with the created OSCORE Security Context
	private String uri;
	
	// The size of the Replay Window to use in an OSCORE Recipient Context
	private int OSCORE_REPLAY_WINDOW;
	
	// The size of MAX_UNFRAGMENTED_SIZE to use in an OSCORE Security Context
	private int MAX_UNFRAGMENTED_SIZE;
	
	// The collection of application profiles - The lookup key is the full URI of the EDHOC resource
	private HashMap<String, AppProfile> appProfiles;
		
	public EdhocEndpointInfo(HashMap<Integer, HashMap<Integer, CBORObject>> idCreds,
							 HashMap<Integer, HashMap<Integer, CBORObject>> creds,
							 HashMap<Integer, HashMap<Integer, OneKey>> keyPairs,
							 HashMap<CBORObject, OneKey> peerPublicKeys,
							 HashMap<CBORObject, CBORObject> peerCredentials,
							 HashMap<CBORObject, EdhocSession> edhocSessions,
							 Set<CBORObject> usedConnectionIds, List<Integer> supportedCipherSuites,
							 Set<Integer> supportedEADs, HashMap<Integer, List<CBORObject>> eadProductionInput,
							 int trustModel, HashMapCtxDB db, String uri, int OSCORE_REPLAY_WINDOW,
							 int MAX_UNFRAGMENTED_SIZE, HashMap<String, AppProfile> appProfiles) {

		
		this.keyPairs = keyPairs;
		this.idCreds = idCreds;
		this.creds = creds;
						
		this.peerPublicKeys = peerPublicKeys;
		this.peerCredentials = peerCredentials;
		this.edhocSessions = edhocSessions;
		this.usedConnectionIds = usedConnectionIds;
		this.supportedCipherSuites = supportedCipherSuites;
		this.supportedEADs = supportedEADs;
		this.eadProductionInput = eadProductionInput;
		this.trustModel = trustModel;
		this.db = db;
		this.uri = uri;
		this.OSCORE_REPLAY_WINDOW = OSCORE_REPLAY_WINDOW;
		this.MAX_UNFRAGMENTED_SIZE = MAX_UNFRAGMENTED_SIZE;
		this.appProfiles = appProfiles;
		
	}
	
	//Return a reference to the set of EDHOC sessions
	public HashMap<CBORObject, EdhocSession> getEdhocSessions() {
		return edhocSessions;
	}

	// Return a reference to the set of Application Profiles
	public HashMap<String, AppProfile> getAppProfiles() {
		return appProfiles;
	}
	
	// Return the identity key pair
	public HashMap<Integer, HashMap<Integer, OneKey>> getKeyPairs() {
		return this.keyPairs;
	}
	
	// Return the ID_CRED used by this peer
	public HashMap<Integer, HashMap<Integer, CBORObject>> getIdCreds() {
		return this.idCreds;
	}
	
	// Return the CRED used by this peer
	public HashMap<Integer, HashMap<Integer, CBORObject>> getCreds() {
		return this.creds;
	}
	
	// Return the set of peer public keys
	public HashMap<CBORObject, OneKey> getPeerPublicKeys() {
		return peerPublicKeys;
	}
	
	// Return the set of peer credentials
	public HashMap<CBORObject, CBORObject> getPeerCredentials() {
		return peerCredentials;
	}
	
	// Return the default OSCORE Replay Window size
	public int getOscoreReplayWindow() {
		return OSCORE_REPLAY_WINDOW;
	}
	
	// Return the default MAX_UNFRAGMENTED_SIZE
		public int getOscoreMaxUnfragmentedSize() {
			return MAX_UNFRAGMENTED_SIZE;
		}
	
	// Return the database of OSCORE Security Contexts
	public HashMapCtxDB getOscoreDb() {
		return db;
	}
	
	// Return the lookup identifier for the Security Context
	public String getUri() {
		return uri;
	}
	
	// Return the set of supported cipher suites
	public List<Integer> getSupportedCipherSuites() {
		return supportedCipherSuites;
	}
		
	// Return the set of used Connection Identifiers
	public Set<CBORObject> getUsedConnectionIds() {
		return usedConnectionIds;
	}
	
	// Return the set of supported EAD items
	public Set<Integer> getSupportedEADs() {
		return supportedEADs;
	}
	
	// Return the information to produce EAD items for outgoing messages
	public HashMap<Integer, List<CBORObject>> getEadProductionInput() {
		return eadProductionInput;
	}
	
	// Return the trust model used for validating authentication credentials of other peers
	public int getTrustModel() {
		return trustModel;
	}
	
}
