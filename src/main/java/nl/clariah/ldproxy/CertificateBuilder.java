package nl.clariah.ldproxy;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificateBuilder {
    private static final PrivateKey privateKey;
    private static final ContentSigner contentSigner;
    private static final X509Certificate certificate;
    private static final JcaX509CertificateConverter certificateConverter;

    static {
        try {
            final Provider bcProvider = new BouncyCastleProvider();
            Security.addProvider(bcProvider);

            // Load the key store
            char[] keyStorePassword = System.getProperty("keyStorePassword").toCharArray();
            String alias = System.getProperty("keyStoreAlias");
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(Files.newInputStream(Paths.get(System.getProperty("keyStore"))), keyStorePassword);

            // Obtain our private key, signer and certificate from the keystore
            privateKey = (PrivateKey) keyStore.getKey(alias, keyStorePassword);
            contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
            certificate = (X509Certificate) keyStore.getCertificate(alias);
            certificateConverter = new JcaX509CertificateConverter().setProvider(bcProvider);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyStore createForgedCertificateFor(Principal serverDN, BigInteger serialNumber) throws CertificateException {
        try {
            // Build a new certificate using our certificate DN (not the remote server's DN)
            JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    certificate.getIssuerX500Principal(),
                    serialNumber,
                    certificate.getNotBefore(),
                    certificate.getNotAfter(),
                    new X500Principal(serverDN.getName()),
                    certificate.getPublicKey());

            X509Certificate forgedCertificate = certificateConverter.getCertificate(certificateBuilder.build(contentSigner));

            // Create a new keystore with our forged certificate
            KeyStore keyStore = KeyStore.getInstance("jks");
            keyStore.load(null, null);
            keyStore.setKeyEntry("forged", privateKey, "".toCharArray(), new Certificate[]{forgedCertificate});

            return keyStore;
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
