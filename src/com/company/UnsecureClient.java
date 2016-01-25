import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;

/**
 * Created by Hedgehog on 30.06.2015.
 */
public class UnsecureClient {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {

        String ip = args[0]; // localhost
        //String ip = "localhost";
        int port = 15020;



        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, new SecureRandom());

        SSLSocketFactory ssf = context.getSocketFactory();

        Socket s = ssf.createSocket(ip, port);

        SSLSession session = ((SSLSocket) s).getSession();

        java.security.cert.Certificate[] cchain = session.getPeerCertificates();
        System.out.println("The Certificates used by peer");
        for (int i = 0; i < cchain.length; i++) {
            System.out.println(((X509Certificate) cchain[i]).getSubjectDN());
        }
        System.out.println("Peer host is " + session.getPeerHost());
        System.out.println("Cipher is " + session.getCipherSuite());
        System.out.println("Protocol is " + session.getProtocol());
        System.out.println("ID is " + new BigInteger(session.getId()));
        System.out.println("Session created in " + session.getCreationTime());
        System.out.println("Session accessed in " + session.getLastAccessedTime());

        s.close();
    }
}
