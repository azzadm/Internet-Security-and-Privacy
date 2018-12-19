
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {
    private SessionKey sessionKey;
    private SessionIV sessionIV;



    SessionDecrypter(SessionKey sessionKey, SessionIV sessionIV) {

        this.sessionKey = sessionKey;
        this.sessionIV = sessionIV;
    }

    CipherInputStream openCipherInputStream(InputStream input) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, this.sessionKey.getSecretKey(),sessionIV.getSessionIVSpec() );
        CipherInputStream cipherInputStream = new CipherInputStream(input, cipher);

        return cipherInputStream;
    }

}
