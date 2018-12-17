import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertificateHandler {

    // Gets the X509 certificate from the input parameter
    public static X509Certificate getCertificate(String input) throws IOException, CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream certInput = new FileInputStream(input);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certInput);
        certInput.close();
        return certificate;
    }

    // Generates certificate from byte []
    public static X509Certificate generateCertificate(byte[] preCert) throws CertificateException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(preCert);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    // Encodes the certificate to send to the server
    public static String encodeCertificate(X509Certificate certificate) throws CertificateEncodingException {
        //certificate.getEncoded();
        byte[] encodedCert = Base64.getEncoder().encode(certificate.getEncoded());
        return new String(encodedCert);
    }

    // Decodes certificate with Base64
    public static X509Certificate decodeCertificate(String encodedCert) throws CertificateException {
        byte[] decodedCert = Base64.getDecoder().decode(encodedCert.getBytes());
        return CertificateHandler.generateCertificate(decodedCert);
    }

    // Verifies certificate with CAs public key and user certificate
    public static void verifyCertificate(X509Certificate caCert, X509Certificate clientCert) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey publicKey = caCert.getPublicKey();
        clientCert.verify(publicKey);
    }
}
