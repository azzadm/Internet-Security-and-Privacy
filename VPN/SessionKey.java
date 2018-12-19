import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionKey {

    private SecretKey secretKey;

    // Source from http://tutorials.jenkov.com/java-cryptography/index.html
    SessionKey(Integer keylength) throws NoSuchAlgorithmException {

        //Creating a KeyGenerator object
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");

        //Creating a SecureRandom object
        SecureRandom secureRandom = new SecureRandom();

        //Initializing the KeyGenerator
        keyGen.init(keylength, secureRandom);

        //Creating/Generating a key

        this.secretKey = keyGen.generateKey();
    }

    SecretKey getSecretKey() {
        return this.secretKey;
    }

    String encodeKey() {
        // base64 Encoded version of the key
        byte encoded[] = secretKey.getEncoded();

        String encodedKey = Base64.getEncoder().encodeToString(encoded);
        return encodedKey;
    }

    SessionKey(String encodedkey) {
        // Decode the base64 Encoded string
        byte[] decodedKey = Base64.getDecoder().decode(encodedkey);
        // Rebuild key using SecretKeySpec
        this.secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static byte[] encryptSessionKey(SessionKey sessionKey, PublicKey publicKey) throws Exception {
        String sessionKeyString = sessionKey.encodeKey();
        byte[] sessionKeyBytes = sessionKeyString.getBytes("utf-8");
        byte[] encryptedBytes = HandshakeCrypto.encrypt(sessionKeyBytes, publicKey);

        System.out.println("sessionkey: " + sessionKeyString);
        //String encryptedSessionKey = new String(encryptedBytes, ENCODING);
        //System.out.println("encrypted: " + encryptedSessionKey);

        return encryptedBytes;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(key1.encodeKey());
        if (key1.getSecretKey().equals(key2.getSecretKey())) {
            System.out.println("Pass");
        } else {
            System.out.println("Fail");
        }
    }


}