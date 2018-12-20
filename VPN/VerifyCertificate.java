import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;

public class VerifyCertificate {
    private static CertificateFactory certificateFactory;
    private static FileInputStream caInputStream;
    private static X509Certificate caCertificate;
    private static FileInputStream userInputStream;
    private static X509Certificate userCertificate;
    public final X509Certificate certificate;

    VerifyCertificate(){
        this.certificate = userCertificate;
    }

    public static void main(String args[]) {


        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        try {
            caInputStream = new FileInputStream(args[0]);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            caCertificate = (X509Certificate) certificateFactory.generateCertificate(caInputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        System.out.println(caCertificate);

        try {
            caInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            userInputStream = new FileInputStream(args[1]);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        try {
            userCertificate = (X509Certificate) certificateFactory.generateCertificate(userInputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        System.out.println(userCertificate);

        try {
            userInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        String caDN = getDnForCertificate(caCertificate);
        String userDN = getDnForCertificate(userCertificate);

        PublicKey publicKey = caCertificate.getPublicKey();

        int i = 0;

        try {
            caCertificate.verify(publicKey);

        } catch (InvalidKeyException e) {
            e.printStackTrace();
            System.out.println("Incorrect key");
            System.out.println("Fail");
            i++;
        } catch (CertificateException e) {
            e.printStackTrace();
            System.out.println("Encoding errors");
            System.out.println("Fail");
            i++;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("Unsupported signature algorithm");
            System.out.println("Fail");
            i++;
        } catch (SignatureException e) {
            e.printStackTrace();
            System.out.println("Signature errors");
            System.out.println("Fail");
            i++;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            System.out.println("Incorrect provider");
            System.out.println("Fail");
            i++;
        }

        try {
            userCertificate.verify(publicKey);
        } catch (CertificateException e) {
            e.printStackTrace();
            System.out.println("Incorrect key");
            System.out.println("Fail");
            i++;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("Unsupported signature algorithm");
            System.out.println("Fail");
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            i++;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            System.out.println("Incorrect provider");
            System.out.println("Fail");
            i++;
        } catch (SignatureException e) {
            e.printStackTrace();
            System.out.println("Signature errors");
            System.out.println("Fail");
            i++;
        }

        try {
            caCertificate.checkValidity();
        } catch (CertificateExpiredException e) {
            e.printStackTrace();
            System.out.println("Certificate has expired");
            System.out.println("Fail");
            i++;
        } catch (CertificateNotYetValidException e) {
            e.printStackTrace();
            System.out.println("Certificate not yet vaild");
            System.out.println("Fail");
            i++;
        }
        try {
            userCertificate.checkValidity();
        } catch (CertificateExpiredException e) {
            e.printStackTrace();
            System.out.println("Certificate has expired");
            System.out.println("Fail");
            i++;
        } catch (CertificateNotYetValidException e) {
            e.printStackTrace();
            System.out.println("Certificate not yet vaild");
            System.out.println("Fail");
            i++;
        }

        System.out.println(caDN);
        System.out.println(userDN);

        if (i == 0) {
            System.out.println("Pass");
        }
    }
    //method from https://www.programcreek.com/java-api-examples/?class=java.security.cert.X509Certificate&method=getSubjectDN, Example 2
    private static String getDnForCertificate(X509Certificate certificate) {
        if (certificate != null && certificate.getSubjectDN() != null) {
            return certificate.getSubjectDN().getName();
        }
        return "Unable to get DN";
    }
}
