/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server
 * and adapted for IK2206.
 * <p>
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 * <p>
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ForwardServer {
    private static final boolean ENABLE_LOGGING = true;
    private static final int DEFAULTSERVERPORT = 2206;
    private static final String DEFAULTSERVERHOST = "localhost";
    private static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;

    private ServerSocket handshakeSocket;

    private static final String thisDirectory = System.getProperty("user.dir") + "\\";
    private static String CA;
    private static String serverCertificate;


    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    private X509Certificate clientCert;


    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */


    private void doHandshake() throws Exception {

        Socket clientSocket = handshakeSocket.accept();
        System.out.println(clientSocket);
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        System.out.println(clientHostPort);
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */


        // Receive clientHello message
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.recv(clientSocket);
        if (clientHello.getParameter("MessageType").equals("ClientHello")) {
            clientCert = CertificateHandler.generateCertificate(clientHello.getParameter("Certificate"));
            CertificateHandler.verifyCertificate(CertificateHandler.getCertificate((thisDirectory + CA)), clientCert);


            // Send serverHello message
            X509Certificate cert = CertificateHandler.getCertificate(serverCertificate);
            HandshakeMessage serverHello = new HandshakeMessage();
            serverHello.putParameter("MessageType", "ServerHello");
            serverHello.putParameter("Certificate", CertificateHandler.encodeCertificate(cert));
            serverHello.send(clientSocket);
        } else {
            System.out.println("Error on clientHello message handshake");
        }


        // Recieve forward message
        HandshakeMessage forward = new HandshakeMessage();
        forward.recv(clientSocket);
        if (forward.getParameter("MessageType").equals("Forward")) {
            //Handshake.setTargetHost(forward.getParameter("TargetHost"));
            //Handshake.setTargetPort(Integer.parseInt(forward.getParameter("TargetPort")));
        } else {
            System.out.println("Error on forward message handshake");
        }

        // Values for session message
        PublicKey clientPublicKey = clientCert.getPublicKey();

        // Encrypt and encode sessionKey
        SessionKey sessionKey = new SessionKey(128);
        Handshake.sessionKey = sessionKey;

        byte[] encryptedBytesKey = SessionKey.encryptSessionKey(sessionKey, clientPublicKey);
        String encodedSessionKey = Base64.getEncoder().encodeToString(encryptedBytesKey);

        //Encrypt and encode sessionIV
        SessionIV sessionIV = new SessionIV();
        Handshake.sessionIV = sessionIV;
        byte[] encryptedBytesIV = SessionIV.encryptSessionIV(sessionIV, clientPublicKey);
        String encodedSessionIV = Base64.getEncoder().encodeToString(encryptedBytesIV);


        // Send session message

        HandshakeMessage sessionMessage = new HandshakeMessage();
        sessionMessage.putParameter("MessageType", "Session");
        sessionMessage.putParameter("SessionKey", encodedSessionKey);
        sessionMessage.putParameter("SessionIV", encodedSessionIV);
        sessionMessage.send(clientSocket);


        System.out.println("Handshake completed, close socket");

        clientSocket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* listenSocket is a new socket where the ForwardServer waits for the
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort).
         * (This may give "Address already in use" errors, but that's OK for now.)
         */
        listenSocket = new ServerSocket();
        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
        targetHost = Handshake.targetHost;
        targetPort = Handshake.targetPort;
    }


    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
            throws Exception {

        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port);
        }

        log("Nakov Forward Server started on TCP port " + port);

        // Accept client connections and process them until stopped
        while (true) {
            ForwardServerClientThread forwardThread;
            try {
                System.out.println("Im here");
                doHandshake();

                forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort);
                forwardThread.start();
            } catch (IOException e) {
                throw e;
            }
        }
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    private void log(String aMessage) {
        if (ENABLE_LOGGING)
            System.out.println(aMessage);
    }

    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
    }

    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
            throws Exception {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        CA = arguments.get("cacert");
        serverCertificate = arguments.get("usercert");
        System.out.println("CA directory: " + thisDirectory + CA);
        System.out.println("Server Certificate directory: " + thisDirectory + serverCertificate);

        ForwardServer srv = new ForwardServer();
        try {
            srv.startForwardServer();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}