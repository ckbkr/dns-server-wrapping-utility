package com.company;

import javax.net.ssl.*;
import javax.security.cert.Certificate;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

public class ServerMain {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException, InterruptedException {

        DateFormat dateFormat = new SimpleDateFormat("[yyyy/MM/dd HH:mm:ss]");

        if ( args.length < 4 ){
            System.out.println("Usage: java -jar DNSUpdate.jar port CertName CertPass KeyStoreName KeyStorePass");
            return;
        }

        int port = Integer.decode(args[0]);

        String sCerts = args[1];
        String sCertsPass = args[2];
        String sKeyStore = args[3];
        String sKeyStorePass = args[4];

        KeyStore trustStore = KeyStore.getInstance("JKS");
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustStore.load(new FileInputStream(sCerts), sCertsPass.toCharArray());
        trustManagerFactory.init(trustStore);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyStore.load(new FileInputStream(sKeyStore), sKeyStorePass.toCharArray());
        keyManagerFactory.init(keyStore, sKeyStorePass.toCharArray());

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        SSLServerSocket serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(port);
        System.out.println("Server ready... " + serverSocket);

        System.out
                .println("Supported Cipher Suites: "
                        + Arrays.toString(((SSLServerSocketFactory) SSLServerSocketFactory
                        .getDefault())
                        .getSupportedCipherSuites()));

        // Add Client authentication
        serverSocket.setNeedClientAuth(true);
        // Set timeout for blocking opteration
        serverSocket.setSoTimeout(30000);

        System.out.println("Running on: "+ Integer.toString(port));
        while (true) {
            final Object lock = new Object();
            Semaphore mutex = new Semaphore(1);
            mutex.acquire();
            SSLSocket client;
            System.out.println("Waiting for a client");
            try{
                client = (SSLSocket) serverSocket.accept();
                client.addHandshakeCompletedListener(new HandshakeCompletedListener() {
                    @Override
                    public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent) {
                        System.out.println("Handshake Complete");
                        mutex.release();
                    }
                });
            } catch( java.net.SocketTimeoutException e ){
                continue;
            }

            SSLSession sslSession = client.getSession();

            String cipherSuite = sslSession.getCipherSuite();

            System.out.println("Cipher suite: " + cipherSuite);

            if( mutex.tryAcquire(15, TimeUnit.SECONDS) ){
                System.out.println("Client authentification successful");
            }else{
                client.close();
                System.out.println("Client didn't authenticate in time");
                continue;
            }

            HashMap<Integer,String> clientMappings = new HashMap<>();
            clientMappings.put(new Integer(1324894399),"pc.keks.daskekshaus.de");
            clientMappings.put(new Integer(1953709898),"cedrik.keks.daskekshaus.de");
            clientMappings.put(new Integer(-1646902452),"panda.keks.daskekshaus.de");
            clientMappings.put(new Integer(-284778396),"panda2.keks.daskekshaus.de");

            String mapping = null;
            for(java.security.cert.Certificate peerCertificates : sslSession.getPeerCertificates()){
                System.out.println("Certificate Hash: " + Integer.toString(peerCertificates.hashCode()));
                mapping = clientMappings.get(new Integer(peerCertificates.hashCode()));
                if( mapping != null ){
                    break;
                }
            }

            if( mapping == null ){
                System.out.println("No client mapping found");
                client.close();
                continue;
            }else{
                System.out.println("Mapped client to: " + mapping);
            }

            String ip = sslSession.getPeerHost();
            String clock = dateFormat.format(new Date());


            LinkedList<String> commands = new LinkedList<>();
            System.out.println("Updating to: " + ip);
            commands.add("/usr/bin/nsupdate");
            commands.add("-k");
            commands.add("Kkeks.daskekshaus.de.+163+15476.private");
            commands.add("server localhost");
            commands.add("zone keks.daskekshaus.de");
            commands.add("update delete " + mapping + " A");
            commands.add("update add " + mapping + " 300 A " + ip);
            commands.add("send");

            try {
                // Execute command
                ProcessBuilder builder = new ProcessBuilder(commands.removeFirst(), commands.removeFirst(), commands.removeFirst());
                builder.redirectErrorStream(true);
                Process process = builder.start();

                // Get output stream to write from it
                BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()));
                BufferedReader br = new BufferedReader(new InputStreamReader( process.getInputStream()));

                String line = null;
                while (!commands.isEmpty()) {
                    String command = commands.removeFirst();
                    System.out.println(clock + " Writing: " + command);
                    bw.write(command);
                    bw.newLine();
                }
                bw.close();
                br.close();


                builder = null;
                builder = new ProcessBuilder("/usr/sbin/rndc", "reload");
                builder.start();

            } catch (IOException e) {
                System.out.println(e);
            }
        }
    }
}
