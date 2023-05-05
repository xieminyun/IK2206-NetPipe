import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class test {
    public static void main(String[] args) {
        Calendar calendar = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timeStamp = dateFormat.format(calendar.getTime());
        byte[] timeStampUtf8 = timeStamp.getBytes(StandardCharsets.UTF_8);
        String timeStampStr = new String(timeStampUtf8);
        System.out.println(timeStamp);
        System.out.println(timeStampStr);
        System.out.println(timeStamp.charAt(18));
        System.out.println((int)timeStamp.charAt(18));

    }
}
