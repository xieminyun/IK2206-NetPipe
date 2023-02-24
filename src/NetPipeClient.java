import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
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
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, SignatureException, NoSuchProviderException, ClassNotFoundException, IllegalBlockSizeException, InvalidParameterSpecException, BadPaddingException, InvalidKeySpecException {
        Socket socket = null;
        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        String usercert = arguments.get("usercert");
        String cacert = arguments.get("cacert");
        String key = arguments.get("key");

        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        ClientHandshake clientHandshake = new ClientHandshake();
        clientHandshake.sendClientHello(socket, usercert);
        clientHandshake.receiveServerHello(socket,cacert);
        clientHandshake.clientSession(socket);
        clientHandshake.receiveServerFinished(socket);
        clientHandshake.sendClientFinished(socket, key);
        SessionKey sessionKey = new SessionKey(ClientHandshake.sessionKeyByte);
        SessionCipher sessionCipherEncrypted = new SessionCipher(sessionKey,ClientHandshake.sessionIVByte, Cipher.ENCRYPT_MODE);
        SessionCipher sessionCipherDecrypted = new SessionCipher(sessionKey,ClientHandshake.sessionIVByte, Cipher.DECRYPT_MODE);
        CipherOutputStream encryptedOutputStream = sessionCipherEncrypted.openEncryptedOutputStream(socket.getOutputStream());
        CipherInputStream decryptedInputStream = sessionCipherDecrypted.openDecryptedInputStream(socket.getInputStream());
        Forwarder.forwardStreams(System.in, System.out, decryptedInputStream, encryptedOutputStream, socket);
    }
}
