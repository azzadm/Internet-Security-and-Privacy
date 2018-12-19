/**
 * ForwardThread handles the TCP forwarding between a socket input stream (source)
 * and a socket output stream (destination). It reads the input stream and forwards
 * everything to the output stream. If some of the streams fails, the forwarding
 * is stopped and the parent thread is notified to close all its connections.
 */

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ForwardThread extends Thread {
    private static final int READ_BUFFER_SIZE = 8192;

    private int crypt = -1;
    private final int encryption = 0;
    private final int decryption = 1;
    InputStream mInputStream = null;
    OutputStream mOutputStream = null;
    private ForwardServerClientThread mParent = null;
    private SessionEncrypter sessionEncrypter;
    private SessionDecrypter sessionDecrypter;

    /**
     * Creates a new traffic forward thread specifying its input stream,
     * output stream and parent thread
     */
    public ForwardThread(ForwardServerClientThread aParent, InputStream aInputStream, OutputStream aOutputStream, int crypt) throws NoSuchPaddingException, NoSuchAlgorithmException {
        mInputStream = aInputStream;
        mOutputStream = aOutputStream;
        mParent = aParent;
        this.crypt = crypt;
        this.sessionEncrypter = new SessionEncrypter(Handshake.sessionKey, Handshake.sessionIV);
        this.sessionDecrypter = new SessionDecrypter(Handshake.sessionKey, Handshake.sessionIV);
    }

    /**
     * Runs the thread. Until it is possible, reads the input stream and puts read
     * data in the output stream. If reading can not be done (due to exception or
     * when the stream is at his end) or writing is failed, exits the thread.
     */
    public void run() {
        byte[] buffer = new byte[READ_BUFFER_SIZE];
        try {
            while (true) {
                System.out.println(crypt);
                if (crypt == encryption) {
                    System.out.println("ENCRYPTING");
                    int bytesRead = mInputStream.read(buffer);
                    if (bytesRead == -1)
                        break;
                    CipherOutputStream cryptoout = this.sessionEncrypter.openCipherOutputStream(mOutputStream);
                    cryptoout.write(buffer, 0, bytesRead);

                } else if (crypt == decryption) {
                    System.out.println("DECRYPTING");
                    CipherInputStream cryptoin = this.sessionDecrypter.openCipherInputStream(mInputStream);
                    int bytesRead = cryptoin.read(buffer);
                    if (bytesRead == -1)
                        break;
                    mOutputStream.write(buffer, 0, bytesRead);
                }
            }
            // Read/write failed --> connection is broken --> exit the thread


            // Notify parent thread that the connection is broken and forwarding should stop
            mParent.connectionBroken();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}
