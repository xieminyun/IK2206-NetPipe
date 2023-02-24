import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;

public class ServerHandshake {
    public HandshakeDigest sentMsgDigest;
    public HandshakeDigest receivedMsgDigest;
    public HandshakeCertificate clientCert;
    SimpleDateFormat dateFormat;
    Calendar calendar;
    public static byte[] sessionKeyByte;
    public static byte[] sessionIVByte;

    public ServerHandshake() throws NoSuchAlgorithmException {
        calendar = Calendar.getInstance();
        dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sentMsgDigest = new HandshakeDigest();
        receivedMsgDigest = new HandshakeDigest();
    }

    public void receiveClientHello(Socket socket, String caCertName) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        HandshakeMessage recvClientHello = HandshakeMessage.recv(socket);
        if (recvClientHello.getType().equals(HandshakeMessage.MessageType.CLIENTHELLO)) {
            String encodedReceivedCert = recvClientHello.getParameter("Certificate");
            byte[] receivedCertByte = Base64.getDecoder().decode(encodedReceivedCert);
            HandshakeCertificate receivedCert = new HandshakeCertificate(receivedCertByte);
            HandshakeCertificate caCert = new HandshakeCertificate(caCertName);
            receivedCert.verify(caCert);
            clientCert = receivedCert;
            receivedMsgDigest.update(recvClientHello.getBytes());
            System.out.println("ClientHello received and verified");
        }
    }

    public void sendServerHello(Socket socket, String serverCertName) throws CertificateException, IOException {
        HandshakeMessage serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        HandshakeCertificate serverCert = new HandshakeCertificate(serverCertName);
        String encodedServerCert = Base64.getEncoder().encodeToString(serverCert.getBytes());
        serverHello.putParameter("Certificate", encodedServerCert);
        serverHello.send(socket);
        sentMsgDigest.update(serverHello.getBytes());
        System.out.println("serverHello sent");
    }

    public void receiveSession(Socket socket, String key) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        HandshakeMessage recvSession = HandshakeMessage.recv(socket);
        if (recvSession.getType().equals(HandshakeMessage.MessageType.SESSION)) {
            String encodedSessionKey = recvSession.getParameter("SessionKey");
            String encodedSessionIV = recvSession.getParameter("SessionIV");
            byte[] encryptedSessionKey = Base64.getDecoder().decode(encodedSessionKey);
            Path keyFilePath = Paths.get(key);
            byte[] privateKeyByte = Files.readAllBytes(keyFilePath);
            HandshakeCrypto handshakeCrypto = new HandshakeCrypto(privateKeyByte);
            sessionKeyByte = handshakeCrypto.decrypt(encryptedSessionKey);
            byte[] encryptedSessionIV = Base64.getDecoder().decode(encodedSessionIV);
            sessionIVByte = handshakeCrypto.decrypt(encryptedSessionIV);
            receivedMsgDigest.update(recvSession.getBytes());
            System.out.println("Session message received");
        }
    }

    public void sendServerFinished(Socket socket, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        HandshakeMessage serverFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        Path keyFilePath = Paths.get(key);
        byte[] privateKeyByte = Files.readAllBytes(keyFilePath);
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(privateKeyByte);
        byte[] digest = sentMsgDigest.digest();
        byte[] signature = handshakeCrypto.sign(digest);
        String encodedSign = Base64.getEncoder().encodeToString(signature);
        serverFinished.putParameter("Signature", encodedSign);
        String timeStamp = dateFormat.format(calendar.getTime());
        byte[] timestampUTF8 = timeStamp.getBytes(StandardCharsets.UTF_8);
        byte[] signedTimeStamp = handshakeCrypto.sign(timestampUTF8);
        String encodedTimeStamp = Base64.getEncoder().encodeToString(signedTimeStamp);
        serverFinished.putParameter("TimeStamp",encodedTimeStamp);
        serverFinished.send(socket);
    }

    public void receiveClientFinished(Socket socket) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        HandshakeMessage fromClient = HandshakeMessage.recv(socket);
        if (fromClient.getType().equals(HandshakeMessage.MessageType.CLIENTFINISHED)) {
            String encodedReceivedSign = fromClient.getParameter("Signature");
            byte[] receivedSignByte = Base64.getDecoder().decode(encodedReceivedSign);
            HandshakeCrypto handshakeCrypto = new HandshakeCrypto(clientCert);
            byte[] receivedDigest = handshakeCrypto.decryptSign(receivedSignByte);
            byte[] prevDigest = receivedMsgDigest.digest();
            String encodedReceivedTimeStamp = fromClient.getParameter("TimeStamp");
            byte[] recvSignedTimeStampUTF8 = Base64.getDecoder().decode(encodedReceivedTimeStamp);
            byte[] recvTimeStampUTF8 = handshakeCrypto.decryptSign(recvSignedTimeStampUTF8);
            String receivedTimeStamp = new String(recvTimeStampUTF8);
            String timeStamp = dateFormat.format(calendar.getTime());
            System.out.println("Time of sending the messaage:" + receivedTimeStamp);
            System.out.println("Current Time:" + timeStamp);
            if(receivedDigest.equals(prevDigest)) {
                System.out.println("ClientFinished received and verified");
            } else{
                System.out.println("ClientFinished received but is not consistent with the previous message");
            }
        }
    }
}
