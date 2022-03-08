package org.eclipse.californium.edhoc;

import java.util.List;
import java.util.Map;
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
	
    // The ID_CRED used for the identity key of this peer
    private CBORObject idCred;
	
    // The CRED used for the identity key of this peer
    private byte[] cred;
	
    // The long-term asymmetric key pair of this peer
	private OneKey keyPair;
	
	// Long-term public keys of authorized peers
	// The map label is a CBOR Map used as ID_CRED_X
	private Map<CBORObject, OneKey> peerPublicKeys;
	
	// CRED of the long-term public keys of authorized peers
	// The map label is a CBOR Map used as ID_CRED_X
	// The map value is a CBOR byte string, with value the serialization of CRED
	// (i.e. the serialization of what the other peer stores as CRED in its Session)
	private Map<CBORObject, CBORObject> peerCredentials;

	// Existing EDHOC Sessions, including completed ones
	// The map label is C_X, i.e. the connection identifier offered to the other peer, as a CBOR byte string
	private Map<CBORObject, EdhocSession> edhocSessions;
	
	// Each element is a used Connection Identifier offered to the other peers.
	// Connection Identifiers are stored as CBOR integers (if numeric) or as CBOR byte strings (if binary)
	private Set<CBORObject> usedConnectionIds;
	
	// List of supported ciphersuites
	private List<Integer> supportedCiphersuites;
	
	// The database of OSCORE Security Contexts
	private HashMapCtxDB db;
	
	// Lookup identifier to be associated with the OSCORE Security Context
	private String uri;
	
	// The size of the Replay Window to use in an OSCORE Recipient Context
	private int OSCORE_REPLAY_WINDOW;
	
	// The size of MAX_UNFRAGMENTED_SIZE to use in an OSCORE Security Context
	private int MAX_UNFRAGMENTED_SIZE;
	
	// The collection of application profiles - The lookup key is the full URI of the EDHOC resource
	private Map<String, AppProfile> appProfiles;
	
	// The processor of External Authorization Data
	private EDP edp;
	
	
	public EdhocEndpointInfo(CBORObject idCred,
							 byte[] cred, OneKey keyPair, Map<CBORObject, OneKey> peerPublicKeys,
							 Map<CBORObject, CBORObject> peerCredentials, Map<CBORObject, EdhocSession> edhocSessions,
							 Set<CBORObject> usedConnectionIds, List<Integer> supportedCiphersuites, HashMapCtxDB db,
							 String uri, int OSCORE_REPLAY_WINDOW, int MAX_UNFRAGMENTED_SIZE,
							 Map<String, AppProfile> appProfiles, EDP edp) {
				
		this.idCred = idCred;
		this.cred = cred;
		this.keyPair = keyPair;
		this.peerPublicKeys = peerPublicKeys;
		this.peerCredentials = peerCredentials;
		this.edhocSessions = edhocSessions;
		this .usedConnectionIds = usedConnectionIds;
		this.supportedCiphersuites = supportedCiphersuites;
		this.db = db;
		this.uri = uri;
		this.OSCORE_REPLAY_WINDOW = OSCORE_REPLAY_WINDOW;
		this.MAX_UNFRAGMENTED_SIZE = MAX_UNFRAGMENTED_SIZE;
		this.appProfiles = appProfiles;
		this.edp = edp;
		
	}
	
	//Return a reference to the set of EDHOC sessions
	public Map<CBORObject, EdhocSession> getEdhocSessions() {
		return edhocSessions;
	}

	// Return a reference to the set of Application Profiles
	public Map<String, AppProfile> getAppProfiles() {
		return appProfiles;
	}
	
	// Return a reference to the processor of External Authorization Data
	public EDP getEdp() {
		return edp;
	}
	
	// Return the identity key pair
	public OneKey getKeyPair() {
		return keyPair;
	}
	
	// Return the ID_CRED used by this peer
	public CBORObject getIdCred() {
		return idCred;
	}
	
	// Return the CRED used by this peer
	public byte[] getCred() {
		return cred;
	}
	
	// Return the set of peer public keys
	public Map<CBORObject, OneKey> getPeerPublicKeys() {
		return peerPublicKeys;
	}
	
	// Return the set of peer credentials
	public Map<CBORObject, CBORObject> getPeerCredentials() {
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
	
	// Return the set of supported ciphersuites
	public List<Integer> getSupportedCiphersuites() {
		return supportedCiphersuites;
	}
	
	// Return the set of used Connection Identifiers
	public Set<CBORObject> getUsedConnectionIds() {
		return usedConnectionIds;
	}
	
}
