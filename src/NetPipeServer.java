import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert","usercertname");
        arguments.setArgumentSpec("cacert","cacertname");
        arguments.setArgumentSpec("key","keyname");
        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException {
        parseArgs(args);
        ServerSocket serverSocket = null;

        int port = Integer.parseInt(arguments.get("port"));
        String usercert = arguments.get("usercert");
        String cacert = arguments.get("cacert");
        String key = arguments.get("key");

        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
        ServerHandshake serverHandshake = new ServerHandshake();
        serverHandshake.receiveClientHello(socket, cacert);
        serverHandshake.sendServerHello(socket, usercert);
        serverHandshake.receiveSession(socket, key);
        serverHandshake.sendServerFinished(socket, key);
        serverHandshake.receiveClientFinished(socket);
        SessionKey sessionKey = new SessionKey(ServerHandshake.sessionKeyByte);
        SessionCipher sessionCipherEncrypted = new SessionCipher(sessionKey,ServerHandshake.sessionIVByte, Cipher.ENCRYPT_MODE);
        SessionCipher sessionCipherDecrypted = new SessionCipher(sessionKey,ServerHandshake.sessionIVByte, Cipher.DECRYPT_MODE);
        CipherOutputStream encryptedOutputStream = sessionCipherEncrypted.openEncryptedOutputStream(socket.getOutputStream());
        CipherInputStream decryptedInputStream = sessionCipherDecrypted.openDecryptedInputStream(socket.getInputStream());
        Forwarder.forwardStreams(System.in, System.out, decryptedInputStream, encryptedOutputStream, socket);
    }
}
