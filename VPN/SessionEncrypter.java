import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private SessionIV sessionIV;
    Cipher cipher;

    public SessionEncrypter(SessionKey sessionKey, SessionIV sessionIV) throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.sessionKey = sessionKey;
        this.sessionIV = sessionIV;
    }


    CipherOutputStream openCipherOutputStream(OutputStream output) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, this.sessionKey.getSecretKey(), sessionIV.getSessionIVSpec());
        CipherOutputStream cipherOutputStream = new CipherOutputStream(output, cipher);
        return cipherOutputStream;
    }

}