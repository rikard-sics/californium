package org.eclipse.californium.core.observe;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.elements.util.DatagramWriter;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 * Represents the informative response payload (5.03 Service Unavailable)
 * as defined in draft-ietf-core-observe-multicast-notifications.
 * 
 * informative_response_payload = {
 *    0 => array, ; 'tp_info' (transport-specific information)
 *  ? 1 => bstr,  ; 'ph_req' (transport-independent information)
 *  ? 2 => bstr,  ; 'last_notif' (transport-independent information)
 *  ? 3 => uint,  ; 'next_not_before'
 *  ? 4 => ~time  ; 'ending'
 * }
 */
public class ObservationInfo {

    // CBOR key 0 — REQUIRED: transport protocol information
    private TpInfo tpInfo;

    // CBOR key 1 — OPTIONAL: bytes of phantom request
    private byte[] phReq;

    // CBOR key 2 — OPTIONAL: byte serialization of the last multicast notification
    private byte[] lastNotifBytes;

    // OSCORE request option bytes from the phantom request, needed for
    // encrypting last_notif at the resource layer.
    private byte[] requestOscoreOption;

    // Sequence number (Partial IV) from the phantom request's OSCORE option.
    private int requestSequenceNumber;

    // CBOR key 3 — OPTIONAL: seconds until next notification
    private Long nextNotBefore;

    // CBOR key 4 — OPTIONAL: ending time of group observatio
    private Long ending;

    public ObservationInfo() {
    }

    public ObservationInfo(TpInfo tpInfo) {
        this.tpInfo = tpInfo;
    }

    public ObservationInfo(InetSocketAddress serverAddress, InetSocketAddress multicastAddress, Token token) {
        // Section 4.2: tp_info MUST NOT provide link-local or site-local addresses
        validateNotLinkLocalOrSiteLocal(serverAddress, "server");
        validateNotLinkLocalOrSiteLocal(multicastAddress, "multicast");
        this.tpInfo = new TpInfo(serverAddress, multicastAddress, token);
    }

    /**
     * Validates that the given address is not link-local or site-local.
     * Per Section 4.2: informative response MUST NOT provide link-local or
     * site-local addresses in tp_info.
     */
    private static void validateNotLinkLocalOrSiteLocal(InetSocketAddress address, String label) {
        if (address == null || address.getAddress() == null) {
            return;
        }
        InetAddress addr = address.getAddress();
        if (addr.isLinkLocalAddress()) {
            throw new IllegalArgumentException(
                    "tp_info " + label + " address " + addr.getHostAddress()
                    + " is link-local (RFC Section 4.2)");
        }
        if (addr instanceof java.net.Inet6Address && addr.isSiteLocalAddress()) {
            throw new IllegalArgumentException(
                    "tp_info " + label + " address " + addr.getHostAddress()
                    + " is site-local (RFC Section 4.2)");
        }
    }

    public Token getToken() {
        return this.tpInfo.token;
    }

    public TpInfo getTpInfo() {
        return tpInfo;
    }

    public void setTpInfo(TpInfo tpInfo) {
        this.tpInfo = tpInfo;
    }

    public byte[] getPhReq() {
        return phReq;
    }

    public void setPhReq(byte[] phReq) {
        this.phReq = phReq;
    }

    public byte[] getRequestOscoreOption() {
        return requestOscoreOption;
    }

    public void setRequestOscoreOption(byte[] requestOscoreOption) {
        this.requestOscoreOption = requestOscoreOption;
    }

    public int getRequestSequenceNumber() {
        return requestSequenceNumber;
    }

    public void setRequestSequenceNumber(int requestSequenceNumber) {
        this.requestSequenceNumber = requestSequenceNumber;
    }

    /**
     * Gets the transport-independent serialization of the last multicast notification.
     *
     * @return the serialized bytes, or {@code null}
     */
    public byte[] getLastNotifBytes() {
        return lastNotifBytes;
    }

    /**
     * Sets the transport-independent serialization of the last multicast notification.
     * 
     * @param lastNotifBytes serialized as per Section 4.2.2:
     *        code byte + serialized options + optional (0xFF + payload)
     */
    public void setLastNotifBytes(byte[] lastNotifBytes) {
        this.lastNotifBytes = lastNotifBytes;
    }

    /**
     * Sets last_notif from bytes of a Californium {@link Response}  
     * @param response the last multicast notification response
     */
    public void setLastNotif(Response response) {
        if (response == null) {
            this.lastNotifBytes = null;
            return;
        }
        this.lastNotifBytes = serializeTransportIndependent(response);
    }

    public Long getNextNotBefore() {
        return nextNotBefore;
    }

    public void setNextNotBefore(Long nextNotBefore) {
        this.nextNotBefore = nextNotBefore;
    }

    public Long getEnding() {
        return ending;
    }

    public void setEnding(Long ending) {
        this.ending = ending;
    }

    /**
     * Serializes this ObservationInfo to CBOR bytes.
     * 
     * CBOR structure (draft-ietf-core-observe-multicast-notifications-13, Section 11):
     * 
     * informative_response_payload = {
     *    0 => array, ; 'tp_info'
     *  ? 1 => bstr,  ; 'ph_req'
     *  ? 2 => bstr,  ; 'last_notif'
     *  ? 3 => uint,  ; 'next_not_before'
     *  ? 4 => ~time  ; 'ending'
     * }
    
     * 
     * @return CBOR encoded bytes
     * @throws IllegalStateException if tp_info is not set
     */
    public byte[] toCbor() {
        if (tpInfo == null) {
            throw new IllegalStateException("missing tp_info");
        }
        CBORObject map = CBORObject.NewMap();

        // 0 => tp_info (REQUIRED)
        map.set(0, tpInfo.toCbor());

        // 1 => ph_req (OPTIONAL)
        if (phReq != null) {
            map.set(1, CBORObject.FromObject(phReq));
        }

        // 2 => last_notif (OPTIONAL)
        if (lastNotifBytes != null) {
            map.set(2, CBORObject.FromObject(lastNotifBytes));
        }

        // 3 => next_not_before (OPTIONAL)
        if (nextNotBefore != null) {
            map.set(3, CBORObject.FromObject(nextNotBefore.longValue()));
        }

        // 4 => ending (OPTIONAL)
        if (ending != null) {
            map.set(4, CBORObject.FromObject(ending.longValue()));
        }

        return map.EncodeToBytes();
    }

    /**
     * Serializes a CoAP Response to the transport-independent format defined in
     * in Section 4.2.2
     * 
     * The format is the concatenation of:
     * 	A single byte: the Code field value
     *	The byte serialization of the complete sequence of CoAP options<
     * 	If the message has a non-zero length payload: 0xFF followed by the payload
     * 
     * @param response the CoAP response to serialize
     * @return the transport-independent byte serialization
     */
    public static byte[] serializeTransportIndependent(Response response) {
        DatagramWriter writer = new DatagramWriter();
        writer.writeByte((byte) response.getRawCode());
        DataSerializer.serializeOptionsAndPayload(writer, response.getOptions(), response.getPayload());
        return writer.toByteArray();
    }

    /**
     * Extracts the transport-independent bytes from a full UDP CoAP wire-format message.
     *
     * UDP wire format: [Ver|Type|TKL (1 byte)] [Code (1 byte)] [MID (2 bytes)] [Token (TKL bytes)] [Options...] [0xFF Payload]
     * Transport-independent (Section 4.2.2): [Code (1 byte)] [Options...] [0xFF Payload]
     *
     * @param wireBytes the full serialized CoAP message
     * @return the transport-independent byte serialization (code + options + optional payload)
     */
    public static byte[] extractTransportIndependent(byte[] wireBytes) {
        if (wireBytes == null || wireBytes.length < 4) {
            throw new IllegalArgumentException("Wire bytes too short for CoAP header");
        }
        int tkl = wireBytes[0] & 0x0F;
        int code = wireBytes[1] & 0xFF;
        // Header is 4 bytes, then tkl bytes of token, then options+payload
        int dataStart = 4 + tkl;
        if (dataStart > wireBytes.length) {
            throw new IllegalArgumentException("Wire bytes too short for indicated token length");
        }
        // Build: code (1 byte) + options + optional payload
        byte[] result = new byte[1 + (wireBytes.length - dataStart)];
        result[0] = (byte) code;
        System.arraycopy(wireBytes, dataStart, result, 1, wireBytes.length - dataStart);
        return result;
    }

    /**
     * Parse ObservationInfo from CBOR bytes.
     * 
     * @param cborBytes the CBOR encoded bytes
     * @return parsed ObservationInfo
     * @throws IllegalArgumentException if the CBOR structure is invalid
     */
    public static ObservationInfo fromCbor(byte[] cborBytes) {
        if (cborBytes == null) {
            throw new IllegalArgumentException("cborBytes must not be null");
        }
        return fromCbor(CBORObject.DecodeFromBytes(cborBytes));
    }

    /**
     * Parse ObservationInfo from a CBOR map object.
     * 
     * @param map the CBOR map
     * @return parsed ObservationInfo
     * @throws IllegalArgumentException if the CBOR structure is invalid
     */
    public static ObservationInfo fromCbor(CBORObject map) {
        if (map == null || map.getType() != CBORType.Map) {
            throw new IllegalArgumentException("ObservationInfo must be a CBOR map");
        }

        ObservationInfo info = new ObservationInfo();

        // key 0: tp_info (REQUIRED)
        CBORObject tpInfoObj = map.get(CBORObject.FromObject(0));
        if (tpInfoObj == null) {
            throw new IllegalArgumentException("Missing required key 0 (tp_info)");
        }
        info.setTpInfo(TpInfo.fromCbor(tpInfoObj));

        // key 1: ph_req (OPTIONAL)
        CBORObject phReqObj = map.get(CBORObject.FromObject(1));
        if (phReqObj != null) {
            info.setPhReq(phReqObj.GetByteString());
        }

        // key 2: last_notif (OPTIONAL)
        CBORObject lastNotifObj = map.get(CBORObject.FromObject(2));
        if (lastNotifObj != null) {
            info.setLastNotifBytes(lastNotifObj.GetByteString());
        }

        // key 3: next_not_before (OPTIONAL)
        CBORObject nnbObj = map.get(CBORObject.FromObject(3));
        if (nnbObj != null) {
            info.setNextNotBefore(nnbObj.AsInt64Value());
        }

        // key 4: ending (OPTIONAL)
        CBORObject endingObj = map.get(CBORObject.FromObject(4));
        if (endingObj != null) {
            info.setEnding(endingObj.AsInt64Value());
        }

        return info;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ObservationInfo{\n");
        sb.append("  tpInfo=").append(tpInfo).append(",\n");
        if (phReq != null) {
            sb.append("  phReq=").append(phReq.length).append(" bytes,\n");
        }
        if (lastNotifBytes != null) {
            sb.append("  lastNotif=").append(lastNotifBytes.length).append(" bytes,\n");
        }
        if (nextNotBefore != null) {
            sb.append("  nextNotBefore=").append(nextNotBefore).append(",\n");
        }
        if (ending != null) {
            sb.append("  ending=").append(ending).append(",\n");
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Represents the {@code tp_info} CBOR array for CoAP over UDP:
     * {@code [ tpi_server, tpi_client, tpi_token ]}
     */
    public static class TpInfo {
        private Cri tpiServer;
        private Cri tpiClient;
        private Token token;

        public TpInfo() {
        }

        public TpInfo(InetSocketAddress serverAddress, InetSocketAddress multicastAddress, Token token) {
            this.tpiServer = new Cri(serverAddress);
            this.tpiClient = new Cri(multicastAddress);
            this.token = token;
        }

        public Cri getTpiServer() { return tpiServer; }
        public void setTpiServer(Cri tpiServer) { this.tpiServer = tpiServer; }
        public Cri getTpiClient() { return tpiClient; }
        public void setTpiClient(Cri tpiClient) { this.tpiClient = tpiClient; }
        public Token getToken() { return token; }
        public void setToken(Token token) { this.token = token; }

        /** Serializes tp_info to a CBOR array. */
        CBORObject toCbor() {
            CBORObject array = CBORObject.NewArray();
            if (tpiServer != null) array.Add(tpiServer.toCbor());
            if (tpiClient != null) array.Add(tpiClient.toCbor());
            if (token != null) array.Add(CBORObject.FromObject(token.getBytes()));
            return array;
        }

        static TpInfo fromCbor(CBORObject array) {
            if (array == null || array.getType() != CBORType.Array) {
                throw new IllegalArgumentException("tp_info must be a CBOR array");
            }
            if (array.size() < 3) {
                throw new IllegalArgumentException("tp_info must have at least 3 elements for CoAP/UDP");
            }
            TpInfo tp = new TpInfo();
            tp.setTpiServer(Cri.fromCbor(array.get(0)));
            tp.setTpiClient(Cri.fromCbor(array.get(1)));
            CBORObject tokenObj = array.get(2);
            if (tokenObj.getType() != CBORType.ByteString) {
                throw new IllegalArgumentException("tp_info[2] (tpi_token) must be a byte string");
            }
            tp.setToken(Token.fromProvider(tokenObj.GetByteString()));
            return tp;
        }

        @Override
        public String toString() {
            return "TpInfo{server=" + tpiServer + ", client=" + tpiClient + ", token=" + token + "}";
        }
    }

    /**
     * Constrained Resource Identifier (CRI RFC 9290)
     * CBOR array: {@code [ scheme, host-ip, port? ]}
     */
    public static class Cri {
        public static final int SCHEME_COAP = -1;
        public static final int SCHEME_COAPS = -2;

        private int schemeId;
        private InetAddress host;
        private int port;

        public Cri() { this.schemeId = SCHEME_COAP; }

        public Cri(InetSocketAddress address) {
            this.schemeId = SCHEME_COAP;
            this.host = address.getAddress();
            this.port = address.getPort();
        }

        public Cri(int schemeId, InetAddress host, int port) {
            this.schemeId = schemeId;
            this.host = host;
            this.port = port;
        }

        public int getSchemeId() { return schemeId; }
        public void setSchemeId(int schemeId) { this.schemeId = schemeId; }
        public InetAddress getHost() { return host; }
        public void setHost(InetAddress host) { this.host = host; }
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }

        public byte[] getHostBytes() {
            return host != null ? host.getAddress() : null;
        }

        public boolean isDefaultPort() {
            return port == CoAP.DEFAULT_COAP_PORT;
        }

        public InetSocketAddress toSocketAddress() {
            return new InetSocketAddress(host, port);
        }

        /** Serializes CRI to CBOR array: [ scheme-id, authority ] where authority = [ host-ip, ?port ] */
        CBORObject toCbor() {
            CBORObject cri = CBORObject.NewArray();
            cri.Add(schemeId);
            // authority = [ host-ip, ?port ]
            CBORObject authority = CBORObject.NewArray();
            if (host != null) {
                authority.Add(CBORObject.FromObject(host.getAddress()));
            }
            if (!isDefaultPort()) {
                authority.Add(port);
            }
            cri.Add(authority);
            return cri;
        }

        static Cri fromCbor(CBORObject array) {
            if (array == null || array.getType() != CBORType.Array || array.size() < 2) {
                throw new IllegalArgumentException("CRI must be a CBOR array with at least [scheme-id, authority]");
            }
            Cri cri = new Cri();
            cri.setSchemeId(array.get(0).AsInt32Value());

            // authority = [ host-ip, ?port ]
            CBORObject authority = array.get(1);
            if (authority.getType() != CBORType.Array || authority.size() < 1) {
                throw new IllegalArgumentException("CRI authority must be an array with at least [host]");
            }

            byte[] hostBytes = authority.get(0).GetByteString();
            if (hostBytes.length != 4 && hostBytes.length != 16) {
                throw new IllegalArgumentException("CRI host must be 4 (IPv4) or 16 (IPv6) bytes, got " + hostBytes.length);
            }
            try {
                InetAddress hostAddr = InetAddress.getByAddress(hostBytes);
                // Section 4.2/5.2: tp_info MUST NOT contain link-local or site-local addresses
                if (hostAddr.isLinkLocalAddress()) {
                    throw new IllegalArgumentException(
                            "CRI host " + hostAddr.getHostAddress() + " is link-local (RFC Section 4.2)");
                }
                if (hostAddr instanceof java.net.Inet6Address && hostAddr.isSiteLocalAddress()) {
                    throw new IllegalArgumentException(
                            "CRI host " + hostAddr.getHostAddress() + " is site-local (RFC Section 4.2)");
                }
                cri.setHost(hostAddr);
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Invalid CRI host", e);
            }

            if (authority.size() >= 2) {
                cri.setPort(authority.get(1).AsInt32Value());
            } else {
                cri.setPort(cri.getSchemeId() == SCHEME_COAPS
                        ? CoAP.DEFAULT_COAP_SECURE_PORT : CoAP.DEFAULT_COAP_PORT);
            }
            return cri;
        }

        @Override
        public String toString() {
            String scheme = (schemeId == SCHEME_COAP) ? "coap"
                    : (schemeId == SCHEME_COAPS) ? "coaps" : String.valueOf(schemeId);
            return scheme + "://" + (host != null ? host.getHostAddress() : "null") + ":" + port;
        }
    }
}
