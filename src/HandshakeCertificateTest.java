import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;


public class HandshakeCertificateTest  {
    static String testCertificateFile = "server.pem";
    static String testCACertificateFile = "ca.pem";

    @Test
    void testCertFromFile() throws FileNotFoundException, CertificateException, CertificateEncodingException {

		/* Read user certificate from file and create HandshakeCertificate */
        FileInputStream instream = new FileInputStream(testCertificateFile);
        HandshakeCertificate handshakeCertificate1 = new HandshakeCertificate(instream);
		/* Extract X509 certificate and encode it as a byte array */
        X509Certificate cert1 = handshakeCertificate1.getCertificate();
        byte[] certBytes1 = handshakeCertificate1.getBytes();
		/* Create another HandshakeCertificate from the byte array */
        HandshakeCertificate handshakeCertificate2 = new HandshakeCertificate(certBytes1);
        X509Certificate cert2 = handshakeCertificate2.getCertificate();
		/* Check that the two certificates are the same */
        assertEquals(cert1, cert2);
    }

    @Test
    void testByteArrayFromFile() throws FileNotFoundException, IOException, CertificateException, CertificateEncodingException {
		/* Read user certificate from file and create HandshakeCertificate */
        FileInputStream instream = new FileInputStream(testCertificateFile);
        HandshakeCertificate handshakeCertificate1 = new HandshakeCertificate(instream);
		/* Extract X509 certificate and encode it as a byte array */
        X509Certificate cert1 = handshakeCertificate1.getCertificate();
        byte[] certBytes1 = handshakeCertificate1.getBytes();
		/* Create another HandshakeCertificate from the byte array */
        HandshakeCertificate handshakeCertificate2 = new HandshakeCertificate(certBytes1);
        byte[] certBytes2 = handshakeCertificate2.getBytes();
		/* Check that the two byte arrays are the same */
        assertArrayEquals(certBytes1, certBytes2);
    }

    @Test
    void testVerifyCertificate() throws FileNotFoundException, IOException, CertificateException,
                                        CertificateEncodingException, NoSuchAlgorithmException,
                                        InvalidKeyException, NoSuchProviderException, SignatureException {
		/* Read user certificate from file and create HandshakeCertificate */
        FileInputStream userinstream = new FileInputStream(testCertificateFile);
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(userinstream);
		/* Read CA certificate from file and create HandshakeCertificate */
        FileInputStream cainstream = new FileInputStream(testCACertificateFile);
        HandshakeCertificate CAHandshakeCertificate = new HandshakeCertificate(cainstream);
		/* Verify that user certificate is signed by CA */
        handshakeCertificate.verify(CAHandshakeCertificate);
    }

    @Test
    void testCAVerifyCertificate() throws FileNotFoundException, IOException, CertificateException,
                                        CertificateEncodingException, NoSuchAlgorithmException,
                                        InvalidKeyException, NoSuchProviderException, SignatureException {
		/* Read CA certificate from file and create HandshakeCertificate */
        FileInputStream instream = new FileInputStream(testCACertificateFile);
        HandshakeCertificate handshakeCACertificate = new HandshakeCertificate(instream);
		/* Verify that CA certificate is signed by CA */
        handshakeCACertificate.verify(handshakeCACertificate);
    }

    @Test
    void testVerifyFailCertificate() throws FileNotFoundException, IOException, CertificateException,
                                        CertificateEncodingException, NoSuchAlgorithmException,
                                        InvalidKeyException, NoSuchProviderException, SignatureException {
		/* Read user certificate from file and create HandshakeCertificate */
        FileInputStream userinstream = new FileInputStream(testCertificateFile);
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(userinstream);
		/* Check that verification fails if checking for self-signed certificate */  
		assertThrows(SignatureException.class, () -> {
				handshakeCertificate.verify(handshakeCertificate);
			}
			);
    }

    @Test
    void testCN() throws FileNotFoundException, IOException,
                         CertificateException, CertificateEncodingException {
        String TESTCN = "client.ik2206.kth.se";
		/* Read user certificate from file and create HandshakeCertificate */
        FileInputStream instream = new FileInputStream(testCertificateFile);
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(instream);
		/* Check that CN is client name */
        assertEquals(handshakeCertificate.getCN(), TESTCN);
    }

    @Test
    void testEmail() throws FileNotFoundException, IOException,
                            CertificateException, CertificateEncodingException {
		/* Read user certificate from file and create HandshakeCertificate */
        String TESTEMAIL = "client@ik2206.kth.se";
        FileInputStream instream = new FileInputStream(testCertificateFile);
        HandshakeCertificate handshakeCertificate = new HandshakeCertificate(instream);
		/* Check that CN email is client email */
        assertEquals(handshakeCertificate.getEmail(), TESTEMAIL);
    }
}
