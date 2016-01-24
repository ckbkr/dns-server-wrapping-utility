import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by Hedgehog on 24.06.2015.
 */
public class ClientMain {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        for( String arg : args ){
            System.out.println(arg);
        }

        String keyStoreFile = args[0];

        String ip = "5.45.101.66"; // localhost
        //String ip = "localhost";
        int port = 15020;


        System.out.println(TrustManagerFactory.getDefaultAlgorithm());
        System.out.println(KeyManagerFactory.getDefaultAlgorithm());

        KeyStore trustStore = KeyStore.getInstance("JKS");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustStore.load(new FileInputStream("TSCerts"), "Lukas1990".toCharArray());
        trustManagerFactory.init(trustStore);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyStore.load(new FileInputStream(keyStoreFile), "Lukas1990".toCharArray());
        keyManagerFactory.init(keyStore, "Lukas1990".toCharArray());

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        SSLSocketFactory ssf = context.getSocketFactory();

        Socket s = ssf.createSocket(ip, port);

        SSLSession session = ((SSLSocket) s).getSession();

        Certificate[] cchain = session.getPeerCertificates();
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