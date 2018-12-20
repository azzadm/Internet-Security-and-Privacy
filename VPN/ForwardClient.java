/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */


import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ForwardClient {
    private static final boolean ENABLE_LOGGING = true;
    private static final int DEFAULTSERVERPORT = 2206;
    private static final String DEFAULTSERVERHOST = "localhost";
    private static final String PROGRAMNAME = "ForwardClient";
    private static Arguments arguments;


    private static final String thisDirectory = System.getProperty("user.dir") + "\\";
    private static String CA;
    private static String clientCertificate;
    private static String clientPrivate;
    private static String serverPrivate;


    private static int serverPort;
    private static String serverHost;

    private static void doHandshake() throws Exception {

        /* Connect to forward server server */
        System.out.println("Connect to " + arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */


        // Extract clientCert from the input parameter, and call method getCertificate
        X509Certificate cert = CertificateHandler.getCertificate((thisDirectory + clientCertificate));

        // Send clientHello message
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter("MessageType", "ClientHello");
        clientHello.putParameter("Certificate", CertificateHandler.encodeCertificate(cert));
        clientHello.send(socket);

        System.out.println("Waiting for incoming data from server...");

        // Recieve serverHello message
        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(socket);
        if (serverHello.getParameter("MessageType").equals("ServerHello")) {
            X509Certificate clientCert = CertificateHandler.generateCertificate(serverHello.getParameter("Certificate"));

            // Verify serverCertificate
            CertificateHandler.verifyCertificate(CertificateHandler.getCertificate(CA), clientCert);


        } else {
            System.out.println("error");
        }

        // send forward message
        HandshakeMessage forward = new HandshakeMessage();
        forward.putParameter("MessageType", "Forward");
        forward.putParameter("TargetHost", arguments.get("targethost"));
        forward.putParameter("TargetPort", arguments.get("targetport"));
        forward.send(socket);

        clientPrivate = arguments.get("key");

        // Recieve session message
        HandshakeMessage session = new HandshakeMessage();
        session.recv(socket);
        if (session.getParameter("MessageType").equals("Session")) {
            PrivateKey clientPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(thisDirectory + clientPrivate);

            // decode and decrypt session key
            String encodedKeyString = session.getParameter("SessionKey");
            byte[] encryptedKeyBytes = Base64.getDecoder().decode(encodedKeyString);
            byte[] decryptedKeyBytes = HandshakeCrypto.decrypt(encryptedKeyBytes, clientPrivateKey);
            String encodedSessionKey = new String(decryptedKeyBytes, "UTF-8");

            Handshake.sessionKey = new SessionKey(encodedSessionKey);

            // decode and decrypt sessionIV
            String encodedIVString = session.getParameter("SessionIV");
            byte[] encryptedIVBytes = Base64.getDecoder().decode(encodedIVString);
            byte[] decryptedBytes = HandshakeCrypto.decrypt(encryptedIVBytes, clientPrivateKey);
            String encodedSessionIV = new String(decryptedBytes, "UTF-8");
            Handshake.sessionIV = new SessionIV(encodedSessionIV);

            System.out.println("Handshake completeded, close socket");


        } else {
            System.out.println("Invalid handshake");
            socket.close();

        }


        socket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect.
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead.
         */
        serverHost = Handshake.serverHost;
        serverPort = Handshake.serverPort;
    }


    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }

    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    private static void startForwardClient() throws Exception {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;

        try {
            /* Create a new socket. This is to where the user should connect.
             * ForwardClient sets up port forwarding between this socket
             * and the ServerHost/ServerPort learned from the handshake */
            listensocket = new ServerSocket();
            /* Let the system pick a port number */
            listensocket.bind(null);
            /* Tell the user, so the user knows where to connect */
            tellUser(listensocket);

            Socket clientSocket = listensocket.accept();
            String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
            log("Accepted client from " + clientHostPort);
            forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort);
            forwardThread.start();

        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            throw e;
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    private static void log(String aMessage) {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) throws Exception {
        System.out.println(thisDirectory + clientCertificate);
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            CA = arguments.get("cacert");
            clientCertificate = arguments.get("usercert");
            System.out.println("CA directory: " + thisDirectory + CA);
            System.out.println("Server Certificate directory: " + thisDirectory + clientCertificate);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch (IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        try {
            startForwardClient();
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
    }
}
