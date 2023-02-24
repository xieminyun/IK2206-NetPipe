import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.management.StringValueExp;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;

public class ClientHandshake {
    public HandshakeCertificate clientCert;
    public HandshakeCertificate serverCert;
    public HandshakeDigest sentMsgDigest;
    public HandshakeDigest receivedMsgDigest;
    SimpleDateFormat dateFormat;
    Calendar calendar;
    public static byte[] sessionKeyByte;
    public static byte[] sessionIVByte;

    public ClientHandshake() throws NoSuchAlgorithmException {
        calendar = Calendar.getInstance();
        dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        sentMsgDigest = new HandshakeDigest();
        receivedMsgDigest = new HandshakeDigest();
    }

    public void sendClientHello(Socket socket, String clientCertName) throws CertificateException, IOException {
        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        clientCert = new HandshakeCertificate(clientCertName);
        String encodedClientCert = Base64.getEncoder().encodeToString(clientCert.getBytes());
        clientHello.putParameter("Certificate", encodedClientCert);
        clientHello.send(socket);
        sentMsgDigest.update(clientHello.getBytes());
        System.out.println("ClientHello sent");
    }

    public void receiveServerHello(Socket socket, String caCertName) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        HandshakeMessage fromServer = HandshakeMessage.recv(socket);
        if (fromServer.getType().equals(HandshakeMessage.MessageType.SERVERHELLO)) {
            String encodedReceivedCert = fromServer.getParameter("Certificate");
            byte[] receivedCertByte = Base64.getDecoder().decode(encodedReceivedCert);
            HandshakeCertificate receivedCert = new HandshakeCertificate(receivedCertByte);
            HandshakeCertificate caCert = new HandshakeCertificate(caCertName);
            receivedCert.verify(caCert);
            receivedMsgDigest.update(fromServer.getBytes());
            serverCert = receivedCert;
            System.out.println("ServerHello received and verified");
        }
    }

    public void clientSession(Socket socket) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidParameterSpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        HandshakeMessage session = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        SessionKey sessionKey = new SessionKey(128);
        SessionCipher sessionCipher = new SessionCipher(sessionKey);
        sessionKeyByte = sessionKey.getKeyBytes();
        sessionIVByte = sessionCipher.getIVBytes();
        HandshakeCrypto clientCrypto = new HandshakeCrypto(serverCert);
        byte[] sessionKeyEncrypted = clientCrypto.encrypt(sessionKeyByte);
        byte[] sessionIVEncrypted = clientCrypto.encrypt(sessionIVByte);
        String encodedSessionKey = Base64.getEncoder().encodeToString(sessionKeyEncrypted);
        session.putParameter("SessionKey", encodedSessionKey);
        String encoededSessionIV = Base64.getEncoder().encodeToString(sessionIVEncrypted);
        session.putParameter("SessionIV", encoededSessionIV);
        session.send(socket);
        sentMsgDigest.update(session.getBytes());
        System.out.println("Session message sent");
    }

    public void receiveServerFinished(Socket socket) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        HandshakeMessage fromServer = HandshakeMessage.recv(socket);
        if (fromServer.getType().equals(HandshakeMessage.MessageType.SERVERFINISHED)) {
            String encodedReceivedSign = fromServer.getParameter("Signature");
            byte[] receivedSignByte = Base64.getDecoder().decode(encodedReceivedSign);
            HandshakeCrypto handshakeCrypto = new HandshakeCrypto(serverCert);
            byte[] receivedDigest = handshakeCrypto.decryptSign(receivedSignByte);
            byte[] prevDigest = receivedMsgDigest.digest();
            String encodedReceivedTimeStamp = fromServer.getParameter("TimeStamp");
            byte[] recvSignedTimeStampUTF8 = Base64.getDecoder().decode(encodedReceivedTimeStamp);
            byte[] recvTimeStampUTF8 = handshakeCrypto.decryptSign(recvSignedTimeStampUTF8);
            String receivedTimeStamp = new String(recvTimeStampUTF8);
            String timeStamp = dateFormat.format(calendar.getTime());
            System.out.println("Time of sending the messaage:" + receivedTimeStamp);
            System.out.println("Current Time:" + timeStamp);
            if(receivedDigest.equals(prevDigest)) {
                System.out.println("ServerFinish received and verified");
            } else{
                System.out.println("ServerFinish received but is not consistent with the previous message");
            }
        }
    }

    public void sendClientFinished(Socket socket, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        HandshakeMessage clientFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        Path keyFilePath = Paths.get(key);
        byte[] privateKeyByte = Files.readAllBytes(keyFilePath);
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(privateKeyByte);
        byte[] digest = sentMsgDigest.digest();
        byte[] signature = handshakeCrypto.sign(digest);
        String encodedSign = Base64.getEncoder().encodeToString(signature);
        clientFinished.putParameter("Signature", encodedSign);
        String timeStamp = dateFormat.format(calendar.getTime());
        byte[] timestampUTF8 = timeStamp.getBytes(StandardCharsets.UTF_8);
        byte[] signedTimeStamp = handshakeCrypto.sign(timestampUTF8);
        String encodedTimeStamp = Base64.getEncoder().encodeToString(signedTimeStamp);
        clientFinished.putParameter("TimeStamp",encodedTimeStamp);
        clientFinished.send(socket);
    }

/*    public boolean compareTimeStamp(String TimeStamp, String recvTimeStamp){
        if(!TimeStamp.substring(0,14).equals(recvTimeStamp.substring(0,14))){
            return false;
        }
        if((int)TimeStamp.charAt(15))
    }*/

}
