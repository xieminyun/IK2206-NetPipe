import javax.crypto.interfaces.PBEKey;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    public X509Certificate x509Certificate;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        x509Certificate = (X509Certificate) certificateFactory.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        InputStream instream = new ByteArrayInputStream(certbytes);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        x509Certificate = (X509Certificate) certificateFactory.generateCertificate(instream);
    }

    HandshakeCertificate(String certName) throws CertificateException, FileNotFoundException {
        FileInputStream instream = new FileInputStream(certName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        x509Certificate = (X509Certificate) certificateFactory.generateCertificate(instream);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        return x509Certificate.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return x509Certificate;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        this.x509Certificate.verify(cacert.getCertificate().getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        String subject = String.valueOf(this.getCertificate().getSubjectX500Principal());
        String cnName = search(subject,"CN");
        return cnName;
    }

    /*
     * return email address of subject
     */
    public String getEmail() {
        String subject = String.valueOf(this.getCertificate().getSubjectX500Principal());
        String emailName = search(subject,"EMAILADDRESS");
        return emailName;
    }

    public String search(String s, String key){
        String[]tokens=s.split(", |=");
        HashMap<String,String> map=new HashMap<>();
        for (int i=0;i+1<tokens.length;)
        {
            map.put(tokens[i],tokens[++i]);
            i++;
        }
        return map.get(key);
    }
}
