package org.eclipse.californium.cose;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.CertificateVerificationResult;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.ServerNames;

public class MyVerifier implements NewAdvancedCertificateVerifier {

    @Override
    public List<CertificateType> getSupportedCertificateType() {
        List<CertificateType> supported = new ArrayList<CertificateType>();
        supported.add(CertificateType.RAW_PUBLIC_KEY);
        return supported;
    }

    @Override
    public CertificateVerificationResult verifyCertificate(ConnectionId cid, ServerNames serverName,
            Boolean clientUsage, boolean truncateCertificatePath, CertificateMessage message, DTLSSession session) {
        PublicKey publicKey = message.getPublicKey();
        return new CertificateVerificationResult(cid, publicKey, null);
    }

    @Override
    public List<X500Principal> getAcceptedIssuers() {
        return CertPathUtil.toSubjects(null);
    }

    @Override
    public void setResultHandler(HandshakeResultHandler resultHandler) {
        // TODO Auto-generated method stub

    }

}
