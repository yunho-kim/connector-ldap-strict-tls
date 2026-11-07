/* SPDX-License-Identifier: Apache-2.0 */
package com.evolveum.polygon.connector.ldap.connection;

import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/** Real PKIX certificates and loopback TLS; no directory or external network. */
public class TestConfiguredHostTrustManager {
    private static final char[] TEST_PASSWORD = "temporary-fixture-only".toCharArray();
    private KeyStore serverKeys;
    private X509Certificate trustedCertificate;
    private X509Certificate unknownCertificate;
    private X509ExtendedTrustManager trust;

    @BeforeClass
    public void createTemporaryCertificates() throws Exception {
        Path root = Files.createTempDirectory(Path.of("target"), "strict-tls-");
        serverKeys = createKeyStore(root.resolve("server.p12"));
        trustedCertificate = (X509Certificate) serverKeys.getCertificate("server");
        unknownCertificate = (X509Certificate) createKeyStore(root.resolve("unknown.p12")).getCertificate("server");
        KeyStore anchors = KeyStore.getInstance("PKCS12");
        anchors.load(null, null);
        anchors.setCertificateEntry("test-anchor", trustedCertificate);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(anchors);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509ExtendedTrustManager) {
                trust = (X509ExtendedTrustManager) manager;
            }
        }
        Assert.assertNotNull(trust);
    }

    private KeyStore createKeyStore(Path file) throws Exception {
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "2", "-dname", "CN=unrelated.invalid", "-ext",
                "SAN=dns:dc1.example.test,ip:127.0.0.1,ip:::1", "-storetype", "PKCS12",
                "-keystore", file.toString(), "-storepass", new String(TEST_PASSWORD), "-noprompt")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        Assert.assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Fixture generation timed out");
        Assert.assertEquals(process.exitValue(), 0, "Fixture generation failed");
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream stream = Files.newInputStream(file)) {
            keys.load(stream, TEST_PASSWORD);
        }
        return keys;
    }

    @DataProvider
    public Object[][] validIdentities() {
        return new Object[][] {{"dc1.example.test"}, {"127.0.0.1"}, {"::1"}};
    }

    @Test(dataProvider = "validIdentities")
    public void acceptsTrustedMatchingSAN(String host) throws Exception {
        new ConfiguredHostTrustManager(trust, host).checkServerTrusted(new X509Certificate[] {trustedCertificate}, "RSA");
    }

    @DataProvider
    public Object[][] mismatchedIdentities() {
        return new Object[][] {{"dc2.example.test"}, {"127.0.0.2"}, {"::2"}, {"localhost"}, {"unrelated.invalid"}};
    }

    @Test(dataProvider = "mismatchedIdentities")
    public void rejectsTrustedButMismatchedSAN(String host) {
        Assert.expectThrows(CertificateException.class, () -> new ConfiguredHostTrustManager(trust, host)
                .checkServerTrusted(new X509Certificate[] {trustedCertificate}, "RSA"));
    }

    @Test
    public void rejectsUntrustedCertificateEvenWithMatchingName() {
        Assert.expectThrows(CertificateException.class, () -> new ConfiguredHostTrustManager(trust, "dc1.example.test")
                .checkServerTrusted(new X509Certificate[] {unknownCertificate}, "RSA"));
    }

    @Test
    public void rejectsMissingConfiguredHost() {
        Assert.expectThrows(IllegalArgumentException.class, () -> new ConfiguredHostTrustManager(trust, " "));
    }

    @DataProvider
    public Object[][] handshakeIdentities() {
        return new Object[][] {{"dc1.example.test", true}, {"127.0.0.1", true},
                {"dc2.example.test", false}, {"localhost", false}};
    }

    @Test(dataProvider = "handshakeIdentities")
    public void verifiesConfiguredHostInActualTLSHandshake(String host, boolean permitted) throws Exception {
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(serverKeys, TEST_PASSWORD);
        SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(keys.getKeyManagers(), null, null);
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, new TrustManager[] {new ConfiguredHostTrustManager(trust, host)}, null);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (SSLServerSocket listener = (SSLServerSocket) serverContext.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            listener.setSoTimeout(5000);
            Future<?> server = executor.submit(() -> {
                try (SSLSocket accepted = (SSLSocket) listener.accept()) {
                    accepted.setSoTimeout(5000);
                    accepted.startHandshake();
                } catch (Exception expectedClientRejection) {
                    if (permitted) {
                        throw new RuntimeException(expectedClientRejection);
                    }
                }
            });
            try (SSLSocket client = (SSLSocket) clientContext.getSocketFactory()
                    .createSocket("127.0.0.1", listener.getLocalPort())) {
                client.setSoTimeout(5000);
                if (permitted) {
                    client.startHandshake();
                } else {
                    Assert.expectThrows(SSLException.class, client::startHandshake);
                }
            }
            server.get(10, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
    }
}
