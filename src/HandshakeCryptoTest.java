import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

public class HandshakeCryptoTest {
    static String PRIVATEKEYFILE = "private-pkcs8.der";
    static String CERTFILE = "cert-pkcs1.pem";
    static String PLAINTEXT = "Time flies like an arrow. Fruit flies like a banana.";
    static String ENCODING = "UTF-8"; /* For converting between strings and byte arrays */

    @Test
    public void testPublicEncryptPrivateDecryptGivesPlaintext() throws FileNotFoundException, IOException, NoSuchAlgorithmException,
                                                                       InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException,
                                                                       NoSuchPaddingException, BadPaddingException, CertificateException {
		/* Read certficate from file and create public-key encrypter */
        FileInputStream certInputStream = new FileInputStream(CERTFILE);
        HandshakeCertificate encryptCertificate = new HandshakeCertificate(certInputStream);
        HandshakeCrypto encrypter = new HandshakeCrypto(encryptCertificate);
		/* Read private key from file and create private-key decrypter */
        FileInputStream keyInputStream = new FileInputStream(PRIVATEKEYFILE);
        byte[] keybytes = keyInputStream.readAllBytes();
        HandshakeCrypto decrypter = new HandshakeCrypto(keybytes);

        /* Encode plaintext string as bytes */
        byte[] plaininputbytes = PLAINTEXT.getBytes(ENCODING);
        /* Encrypt it */
        byte[] cipherbytes = encrypter.encrypt(plaininputbytes);
        /* Then decrypt back */
        byte[] plainoutputbytes = decrypter.decrypt(cipherbytes);
        /* Decode bytes into string */
        String plainoutput = new String(plainoutputbytes, ENCODING);
		/* Check decrypted ciphertext is the same as original plaintext */
        assertEquals(PLAINTEXT, plainoutput, "Decrypted ciphertext matches plaintext");
    }

    @Test
    public void testPrivateEncryptPublicDecryptGivesPlaintext() throws FileNotFoundException, IOException, NoSuchAlgorithmException,
                                                                       InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException,
                                                                       NoSuchPaddingException, BadPaddingException, CertificateException {
		/* Read certficate from file and create public-key decrypter */
        FileInputStream certInputStream = new FileInputStream(CERTFILE);
        HandshakeCertificate decryptCertificate = new HandshakeCertificate(certInputStream);
        HandshakeCrypto decrypter = new HandshakeCrypto(decryptCertificate);
		/* Read private key from file and create private-key encrypter */
        FileInputStream keyInputStream = new FileInputStream(PRIVATEKEYFILE);
        byte[] keybytes = keyInputStream.readAllBytes();
        HandshakeCrypto encrypter = new HandshakeCrypto(keybytes);

        /* Encode plaintext string as bytes */
        byte[] plaininputbytes = PLAINTEXT.getBytes(ENCODING);
        /* Encrypt it */
        byte[] cipherbytes = encrypter.encrypt(plaininputbytes);
        /* Then decrypt back */
        byte[] plainoutputbytes = decrypter.decrypt(cipherbytes);
        /* Decode bytes into string */
        String plainoutput = new String(plainoutputbytes, ENCODING);
		/* Check decrypted ciphertext is the same as original plaintext */
        assertEquals(PLAINTEXT, plainoutput, "Decrypted ciphertext matches plaintext");
    }
}
