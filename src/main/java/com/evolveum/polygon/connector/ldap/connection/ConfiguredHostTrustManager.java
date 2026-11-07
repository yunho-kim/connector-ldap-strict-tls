/* SPDX-License-Identifier: Apache-2.0 */
package com.evolveum.polygon.connector.ldap.connection;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.X509ExtendedTrustManager;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;

/** Retain PKIX/JSSE checks and verify the configured endpoint without reverse DNS. */
final class ConfiguredHostTrustManager extends X509ExtendedTrustManager {
    private final X509ExtendedTrustManager delegate;
    private final String expectedHost;
    private final DefaultHostnameVerifier verifier = new DefaultHostnameVerifier();

    ConfiguredHostTrustManager(X509ExtendedTrustManager delegate, String expectedHost) {
        this.delegate = Objects.requireNonNull(delegate);
        if (expectedHost == null || expectedHost.isBlank()) {
            throw new IllegalArgumentException("Configured LDAP TLS host is required");
        }
        this.expectedHost = expectedHost;
    }

    private void verifyEndpoint(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("LDAP server certificate is required");
        }
        try {
            verifier.verify(expectedHost, chain[0]);
        } catch (SSLException e) {
            throw new CertificateException("Configured LDAP endpoint identity mismatch for " + expectedHost, e);
        }
    }

    @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
        verifyEndpoint(chain);
    }
    @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        delegate.checkServerTrusted(chain, authType, socket);
        verifyEndpoint(chain);
    }
    @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        delegate.checkServerTrusted(chain, authType, engine);
        verifyEndpoint(chain);
    }
    @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }
    @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
    }
    @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, engine);
    }
    @Override public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
}
