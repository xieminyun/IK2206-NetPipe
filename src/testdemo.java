import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.HashMap;

public class testdemo {
    public static void main(String[] args) throws FileNotFoundException, CertificateException {
        String testCertificateFile = "CA.pem";
        FileInputStream instream = new FileInputStream(testCertificateFile);
        HandshakeCertificate cert = new HandshakeCertificate(instream);
        System.out.println(cert.getCertificate().toString());
        System.out.println(cert.getCertificate().toString().getBytes());
        System.out.println(Byte.valueOf(cert.getCertificate().toString()));
  /*      byte [] certBytes = cert.getBytes();
        String subject = String.valueOf(cert.getCertificate().getSubjectX500Principal());
        System.out.println(subject);
        HandshakeCertificate certFromBytes = new HandshakeCertificate(certBytes);
        String subjectFromByte = String.valueOf(certFromBytes.getCertificate().getSubjectX500Principal());*/
        /*String emailName = search(subject,"EMAILADDRESS");
        System.out.println(emailName);
        String cnName = search(subject,"CN");
        System.out.println(cnName);*/
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
