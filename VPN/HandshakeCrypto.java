import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

    public static CertificateFactory fact;
    public static X509Certificate certificate;
    public static FileInputStream certifcateFile;
    public static FileInputStream privateKeyFile;


    /*
        The encrypt method takes a plaintext as a byte
        array, and returns the corresponding cipher text as a byte array.
    */

    public static byte[] encrypt(byte[] plaintext, Key key) {
        Cipher cipher;
        byte[] cipherText = null;

        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(plaintext);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        return cipherText;
    }

    // The decrypt method does the decryption.
    public static byte[] decrypt(byte[] ciphertext, Key key) {
        Cipher cipher;
        byte[] plainText = null;

        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            plainText = cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return plainText;
    }

    // The getPublicKeyFromCertFile method extracts a public key from a certificate file.
    public static PublicKey getPublicKeyFromCertFile(String certfile) {
        try {
            fact = CertificateFactory.getInstance("X.509");
            certifcateFile = new FileInputStream(certfile);
            certificate = (X509Certificate) fact.generateCertificate(certifcateFile);

        } catch (CertificateException | FileNotFoundException e) {
            e.printStackTrace();
        }
        return certificate.getPublicKey();
    }

    // The getPrivateKeyFromKeyFile method extracts a private key from a key file
    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(keyfile);
        byte[] privKeyBytes = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
}

