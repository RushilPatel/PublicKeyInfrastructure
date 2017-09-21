package org.pki;

import org.pki.dto.SocketMessage;
import org.pki.entities.CertificateOfAuthority;
import org.pki.entities.Client;
import org.pki.entities.Server;
import org.pki.x509.Certificate;
import org.pki.util.EntityUtil;
import org.pki.x509.Key;
import org.pki.x509.Keygen;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.util.HashMap;

public class StartEntity {

    /**
     * Main class where all entities are launched from
     * @param args the entitiy to launch
     * @throws Exception
     */
    public static void main(String [] args) throws Exception{
        //if no argument is given, run all roles in seperate threads
        if(args.length < 1){
            Thread caThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    try{
                        startCertificateOfAuthority();
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            });
            Thread serverThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    try{
                        startServer();
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            });
            Thread clientThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    try{
                        startClient();
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            });
            caThread.start();
            Thread.sleep(2000); //Sleeping for 2 second to let CA finish startup operations
            serverThread.start();
            Thread.sleep(4000); //Sleeping for 4 second to let CA and Server finish startup operations
            clientThread.start();
        }else{
            String role = args[0].toUpperCase();
            if(role.equals("SERVER")){
                startServer();
            }else if(role.equals("CLIENT")){
                startClient();
            }else if(role.equals("CA")){
                startCertificateOfAuthority();
            }else {
                System.out.println("Error: Invalid Role!\n Valid ROLES: 'SERVER', 'CLIENT' OR 'CA'");
            }
        }
    }

    /**
     * Server start up process of key/cert gen
     * @throws Exception
     */
    private static void startServer() throws Exception{
        System.out.println("Server: Started");

        System.out.println("Server: Generating Self signed certificate and Private Key");
        Keygen keygen = new Keygen(Keygen.generateX500Name(Server.X500Name_CommonName)); //generates keys

        //gets server private key
        Key serverKey = keygen.getKey();

        //load CA cert from directory
        System.out.println("Server: Loading CA certificate at path: " + Server.CACertificateFile_Default);
        Certificate caCertificate = new Certificate(new File(Server.CACertificateFile_Default));

        //Connects to CA, sends self signed certificate to CA, and receives signed certificate from ca
        System.out.println(String.format("Server: Opening socket to CA; Hostname: %s, Port: %s", Server.CAHost_Default, CertificateOfAuthority.Port));
        Socket caSocket = new Socket(Server.CAHost_Default, CertificateOfAuthority.Port);
        SocketMessage messageForCA = new SocketMessage(false, caCertificate.encrypt(keygen.getCertificate().getEncoded()));
        System.out.println("Server: Sending self signed certificate to CA for signing. The message is encrypted with only CA's public key");
        SocketMessage replyFromCA = EntityUtil.getCertificateSigned(caSocket, messageForCA);
        Certificate serverCertificate = new Certificate(EntityUtil.decryptMessage(caCertificate, serverKey, replyFromCA.getData()));
        System.out.println("Server: Received signed certificate from CA");

        //saves cert and key to file
        serverKey.outputKeyToFile(new File(Server.KeyFile_Default));
        serverCertificate.outputCertificateToFile(new File(Server.CertificateFile_Default));
        System.out.println("Server: Certificate saved to file: " + Server.CertificateFile_Default);
        System.out.println("Server: Key saved to file: " + Server.KeyFile_Default);

        // load trusted certs from directory
        System.out.println("Server: Loading trusted certs from directory: " + Server.TrustedCertsDir_Default);
        HashMap<Principal, Certificate> certificateStore = getCertificateStore(Server.TrustedCertsDir_Default);

        //Start server
        System.out.println("Server: Listening for connection from clients on port: " + Server.Port);
        ServerSocket serverSocket = new ServerSocket(Server.Port);
        while (true){
            Socket socket = serverSocket.accept();
            System.out.println("Server: Received connection from client. Creating new thread to handle connection");
            new Thread(new Server(socket, certificateStore, serverCertificate, serverKey)).start();
        }
    }

    /**
     * CA cert/key gen
     * Starts CA entitiy
     * @throws Exception
     */
    private static void startCertificateOfAuthority()throws Exception{
        System.out.println("CA: Started");
        System.out.println("CA: Generating Self signed certificate and Private Key");
        Keygen keygen = new Keygen(Keygen.generateX500Name(CertificateOfAuthority.X500Name_CommonName));

        Certificate caCertificate = keygen.getCertificate();
        Key caKey = keygen.getKey();

        //save key to file
        caKey.outputKeyToFile(new File(CertificateOfAuthority.KeyFile_Default));
        System.out.println("CA: Key saved to file: " + CertificateOfAuthority.KeyFile_Default);
        //save to Client and server trusted cert dir to mimic a cert that is already present on the system
        //This is similar to how OS's ship with trusted certs already on the system
        caCertificate.outputCertificateToFile(new File(CertificateOfAuthority.CertificateFile_Default));
        caCertificate.outputCertificateToFile(new File(Server.CACertificateFile_Default));
        caCertificate.outputCertificateToFile(new File(Client.CACertificateFile_Default));
        System.out.println("CA: Certificate saved to file: " + CertificateOfAuthority.CertificateFile_Default);
        System.out.println("CA: Certificate saved to file: " + Server.CACertificateFile_Default);
        System.out.println("CA: Certificate saved to file: " + Client.CACertificateFile_Default);


        //Load any trusted certs
        System.out.println("CA: Loading trusted certs from directory: " + CertificateOfAuthority.TrustedCertsDir_Default);
        HashMap<Principal, Certificate> certificateStore = getCertificateStore(CertificateOfAuthority.TrustedCertsDir_Default);

        //Start CA entity
        System.out.println("CA: Listening for connection on port: " + CertificateOfAuthority.Port);
        ServerSocket serverSocket = new ServerSocket(CertificateOfAuthority.Port);
        while (true){
            Socket socket = serverSocket.accept();
            System.out.println("CA: Received connection. Creating new thread to handle connection");
            new Thread(new CertificateOfAuthority(socket, certificateStore, caCertificate, caKey)).start();
        }
    }

    /**
     * Generates clients key/cert
     * starts client entity
     * @throws Exception
     */
    private static void startClient()throws Exception{
        System.out.println("Client: Started");

        System.out.println("Client: Generating Self signed certificate and Private Key");
        Keygen keygen = new Keygen(Keygen.generateX500Name(Client.X500Name_CommonName)); //generates keys

        //gets client private key
        Key clientKey = keygen.getKey();

        //load CA cert from directory
        System.out.println("Client: Loading CA certificate at path: " + Client.CACertificateFile_Default);
        Certificate caCertificate = new Certificate(new File(Client.CACertificateFile_Default));

        //Connects to CA, sends self signed certificate to CA, and receives signed certificate from ca
        System.out.println(String.format("Client: Opening socket to CA; Hostname: %s, Port: %s", Client.CAHost_Default, CertificateOfAuthority.Port));
        Socket caSocket = new Socket(Client.CAHost_Default, CertificateOfAuthority.Port);
        SocketMessage messageForCA = new SocketMessage(false, caCertificate.encrypt(keygen.getCertificate().getEncoded()));
        System.out.println("Client: Sending self signed certificate to CA for signing. The message is encrypted with only CA's public key");
        SocketMessage replyFromCA = EntityUtil.getCertificateSigned(caSocket, messageForCA);
        Certificate clientCertificate = new Certificate(EntityUtil.decryptMessage(caCertificate, clientKey, replyFromCA.getData()));
        System.out.println("Client: Received signed certificate from CA");

        //saves cert and key to file
        clientKey.outputKeyToFile(new File(Client.KeyFile_Default));
        clientCertificate.outputCertificateToFile(new File(Client.CertificateFile_Default));
        System.out.println("Client: Certificate saved to file: " + Client.CertificateFile_Default);
        System.out.println("Client: Key saved to file: " + Client.KeyFile_Default);

        // load trusted certs from directory
        System.out.println("Client: Loading trusted certs from directory: " + Client.TrustedCertsDir_Default);
        HashMap<Principal, Certificate> certificateStore = getCertificateStore(Client.TrustedCertsDir_Default);

        System.out.println(String.format("Client: Connecting to server at host %s, port %s", Client.ServerHost_Default, Server.Port));
        Socket socket = new Socket(Client.ServerHost_Default, Server.Port);
        new Thread(new Client(socket, certificateStore, clientCertificate, clientKey)).start();
    }

    //helper method to load trusted certs
    private static HashMap<Principal, Certificate> getCertificateStore(String trustedCertsDir){
        HashMap<Principal, Certificate> certificateStore = new HashMap<Principal, Certificate>();
        File trustedCerts = new File(trustedCertsDir);
        if(trustedCerts.listFiles() != null && trustedCerts.listFiles().length > 0){
            for(File file : new File(trustedCertsDir).listFiles()){
                try {
                    if(file.getName().contains(".crt") || file.getName().contains(".cer")) {
                        Certificate certificate = new Certificate(file);
                        certificateStore.put(certificate.getSubject(), certificate);
                    }
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (CertificateException e) {
                    e.printStackTrace();
                }
            }
        }
        return certificateStore;
    }
}
