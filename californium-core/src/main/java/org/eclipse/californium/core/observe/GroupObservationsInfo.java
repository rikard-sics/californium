/*******************************************************************************
 * Group observation state for multicast notifications
 * (draft-ietf-core-observe-multicast-notifications).
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.RandomTokenGenerator;
import org.eclipse.californium.core.network.TokenGenerator;
import org.eclipse.californium.core.network.TokenGenerator.Scope;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.Bytes;

/**
 * Singleton holding server-side group observation state for resources.
 * Tracks ongoing group observation setups, pending multicast notification
 * tokens, active group observations, and clients awaiting informative responses.
 */
public class GroupObservationsInfo {

	/**
	 * Tracks which resources have a group observation setup in progress.
	 */
	private Map<String, Boolean> ongoingGroupObservationSetup;

	/**
	 * Tokens of phantom requests that the server has sent to itself and is
	 * waiting to receive. Keyed by resource URI path. Entries are removed
	 * once the group observation starts.
	 */
	private Map<String, Token> pendingMulticastNotificationTokens;

	/**
	 * Active group observations keyed by resource URI path.
	 */
	private Map<String, ObservationInfo> ongoingGroupObservations;

	/**
	 * Clients waiting for the informative response (5.03), keyed by resource URI.
	 */
	private Map<String, List<CoapExchange>> pendingClients;

	/**
	 * Number of clients observing a resource
	 */
	private Map<String, AtomicInteger> observerCounters;
	
	private static final int GRP_PORT = 61616;
	

	private Map<Token, InetSocketAddress> multicastAdressByToken;
	
	//use argument Token to get multicast adress, change at Observe Layer as well. IfPhantom rewuest should use this to verify if it is phantomrequest
	public InetSocketAddress getMulticastAdressByToken(Token token) {
		return multicastAdressByToken.get(token);
	}
	
	public boolean isMulticastAdressByToken(Token token) {
		return multicastAdressByToken.containsKey(token);
	}
	
	public void setMulticastAdressByToken(Token token, InetSocketAddress multicastAdress) {
		if (token != null) {
			multicastAdressByToken.put(token, multicastAdress);
		}
	}
	
	

	public void incrementObserverCount(String uri) {
		observerCounters.get(uri).incrementAndGet();
	}


	public boolean isOngoingGroupObservation(String uri) {
		return this.ongoingGroupObservations.containsKey(uri);
	}

	private static GroupObservationsInfo instance;

	private final TokenGenerator tokenGenerator;

	/** The server's own OSCORE sender ID, used for phantom request recognition. */
	private byte[] senderId;

	private GroupObservationsInfo() {
		this.ongoingGroupObservationSetup = new ConcurrentHashMap<>();
		this.pendingMulticastNotificationTokens = new ConcurrentHashMap<>();
		this.ongoingGroupObservations = new ConcurrentHashMap<>();
		this.pendingClients = new ConcurrentHashMap<>();
		this.observerCounters = new ConcurrentHashMap<>();
		this.multicastAdressByToken = new ConcurrentHashMap<>();


		this.tokenGenerator = new RandomTokenGenerator(Configuration.createStandardWithoutFile());
	}

	public static synchronized GroupObservationsInfo getInstance() {
		if (instance == null) {
			instance = new GroupObservationsInfo();
		}
		return instance;
	}

	/**
	 * Reset the singleton instance (for testing).
	 */
	public static synchronized void init() {
		instance = null;
	}

	public boolean isTokenPendingProcess(Token token) {
		return pendingMulticastNotificationTokens.containsValue(token);
	}

	public void setGroupObservationSetupInProgress(String uriPath, boolean inProgress) {
		if (uriPath != null) {
			ongoingGroupObservationSetup.put(uriPath, inProgress);
		}
	}

	public boolean isGroupObservationSetupInProgress(String uri) {
		return Boolean.TRUE.equals(ongoingGroupObservationSetup.get(uri));
	}

	public byte[] getSenderId() {
		return senderId;
	}

	public void setSenderId(byte[] senderId) {
		this.senderId = senderId;
	}

	/**
	 * Allocate a token for multicast notifications and mark it as pending.
	 *
	 * @param uriPath resource URI path
	 * @return allocated token
	 */
	public synchronized Token allocateMulticastToken(String uriPath) {
		if (uriPath == null) {
			return null;
		}
		Token existing = pendingMulticastNotificationTokens.get(uriPath);
		if (existing != null) {
			return existing;
		}
		Token token = getFreeMulticastNotificationToken();
		pendingMulticastNotificationTokens.put(uriPath, token);
		return token;
	}

	public Token getPendingToken(String uriPath) {
		return pendingMulticastNotificationTokens.get(uriPath);
	}

	/**
	 * Transition from pending to active group observation.
	 */
	public void startGroupObservation(String uriPath, ObservationInfo info) {
		if (uriPath == null || info == null) {
			return;
		}
		pendingMulticastNotificationTokens.remove(uriPath);
		ongoingGroupObservations.put(uriPath, info);
		observerCounters.computeIfAbsent(uriPath, k -> new AtomicInteger(0));
				
	}

	public ObservationInfo getGroupObservationInfo(String uriPath) {
		return ongoingGroupObservations.get(uriPath);
	}

	/**
	 * Add a client exchange waiting for an informative response.
	 *
	 * @param uriPath resource URI path
	 * @param exchange the client's exchange
	 */
	public void addPendingClient(String uriPath, CoapExchange exchange) {
		if (uriPath == null || exchange == null) {
			return;
		}
	
		pendingClients.computeIfAbsent(uriPath, k -> new ArrayList<>()).add(exchange);
	}

	/**
	 * Get and remove all pending client exchanges for a resource.
	 */
	public List<CoapExchange> removePendingClients(String uriPath) {
		List<CoapExchange> clients = pendingClients.remove(uriPath);
		return clients != null ? clients : new ArrayList<>();
	}

	/**
	 * Get pending client exchanges without removing them.
	 */
	public List<CoapExchange> getPendingClients(String uriPath) {
		List<CoapExchange> clients = pendingClients.get(uriPath);
		return clients != null ? new ArrayList<>(clients) : new ArrayList<>();
	}

	public ObservationInfo removeGroupObservation(String uriPath) {
		if (uriPath == null) {
			return null;
		}
		pendingMulticastNotificationTokens.remove(uriPath);
		return ongoingGroupObservations.remove(uriPath);
	}

	/**
	 * Generate a token not already in use by pending or ongoing observations.
	 */
	private Token getFreeMulticastNotificationToken() {
		Token token;
		do {
			token = tokenGenerator.createToken(Scope.LONG_TERM);
		} while (isTokenInUse(token));
		return token;
	}

	private boolean isTokenInUse(Token token) {
		if (token == null) {
			return false;
		}
		if (pendingMulticastNotificationTokens.containsValue(token)) {
			return true;
		}
		for (ObservationInfo info : ongoingGroupObservations.values()) {
			if (info != null && token.equals(info.getToken())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Creates a phantom request for multicast group observation setup.
	 * <p>
	 * The phantom request is a self-generated observe request sent to the
	 * server's own address. Like any outgoing request it has no source
	 * context, so that, when OSCORE is used, its OSCORE option is finalized
	 * before computing the external_aad (Group OSCORE, Section 3.4). When it
	 * is received, the ObserveLayer recognizes it and redirects the source
	 * to the multicast group address.
	 *
	 * @param resource the resource to observe
	 * @param multicastToken the token allocated for multicast notifications
	 * @param triggeringCoapExchange the original client exchange that triggered setup
	 * @param hasOscore whether OSCORE protection is used
	 * @return the phantom request ready to be injected
	 */
	public Request createPhantomRequest(Resource resource, Token multicastToken,
			CoapExchange triggeringCoapExchange, boolean hasOscore) {
		
		Request phantomRequest = Request.newGet();
		phantomRequest.setToken(multicastToken);
		phantomRequest.setObserve();
		phantomRequest.getOptions().setUriPath(resource.getURI());
		phantomRequest.setType(Type.NON);
		if (hasOscore) {
			phantomRequest.getOptions().setOscore(Bytes.EMPTY);
		}

		InetSocketAddress localAddress = triggeringCoapExchange.advanced().getEndpoint().getAddress();
		phantomRequest.setDestinationContext(new AddressEndpointContext(localAddress));
		
		phantomRequest.setMultiResponse(true);
		phantomRequest.setServerInjection(true);
		
		return phantomRequest;
	}
}
