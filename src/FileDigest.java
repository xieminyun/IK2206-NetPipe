import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class FileDigest {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        String path = "";
        if (args.length > 0){
            path = path + args[0];
        }
        File file = new File(path);
        FileInputStream inputStream = new FileInputStream(path);
        int length = (int) file.length();
        byte[] input = new byte[length];
        input = inputStream.readNBytes(length);
        HandshakeDigest handshakeDigest = new HandshakeDigest();
        handshakeDigest.update(input);
        byte[] output = handshakeDigest.digest();
        String encode = Base64.getEncoder().encodeToString(output);
        System.out.println(encode);
    }
}
