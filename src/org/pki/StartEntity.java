package org.pki;

import org.pki.dto.SocketMessage;
import org.pki.entities.CertificateOfAuthority;
import org.pki.entities.Client;
import org.pki.entities.Server;
import org.pki.util.Certificate;
import org.pki.util.EntityUtil;
import org.pki.util.Key;
import org.pki.util.Keygen;

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
        if(args.length < 1){
            System.out.println("Error: Please !");
        }else{
            String role = args[0];
            if(role.equals("SERVER")){
                startServer();
            }else if(role.equals("CLIENT")){
                startClient();
            }else if(role.equals("CA")){
                startCertificateOfAuthority();
            }else {
                System.out.println("Error: Invalid Role!");
            }
        }
    }

    /**
     * Server start up process of key/cert gen
     * @throws Exception
     */
    private static void startServer() throws Exception{
        //create cert/key if necessary
        File certificateFile = new File(Server.CertificateFile_Default);
        File keyFile = new File(Server.KeyFile_Default);
        File caCertFile = new File(Server.CACertificateFile_Default);

        //load CA cert
        Certificate caCertificate = new Certificate(caCertFile);

        //Socket to CA
        Socket caSocket = new Socket("localhost", CertificateOfAuthority.Port);

        System.out.println("Generating Certs and Keys...");
        Keygen keygen = new Keygen(Keygen.generateX500Name(Server.X500Name_CommonName));

        //gets server private key
        Key serverKey = keygen.getKey();
        //get server cert signed
        SocketMessage messageForCA = new SocketMessage(false, caCertificate.encrypt(keygen.getCertificate().getEncoded()));
        SocketMessage replyFromCA = EntityUtil.getCertificateSigned(caSocket, messageForCA);
        Certificate serverCertificate = new Certificate(EntityUtil.decryptMessage(caCertificate, serverKey, replyFromCA.getData()));

        //saves cert and key
        serverKey.outputKeyToFile(keyFile);
        serverCertificate.outputCertificateToFile(certificateFile);

        // load trusted certs
        HashMap<Principal, Certificate> certificateStore = getCertificateStore(Server.TrustedCertsDir_Default);

        //Start server
        ServerSocket serverSocket = new ServerSocket(Server.Port);
        while (true){
            Socket socket = serverSocket.accept();
            System.out.println("Handling new Server connection");
            new Thread(new Server(socket, certificateStore, serverCertificate, serverKey)).start();
        }
    }

    /**
     * CA cert/key gen
     * starts CA entitiy
     * @throws Exception
     */
    private static void startCertificateOfAuthority()throws Exception{

        System.out.println("Generating Certs and Keys...");
        Keygen keygen = new Keygen(Keygen.generateX500Name(CertificateOfAuthority.X500Name_CommonName));
        // Load certs/keys
        Certificate caCertificate = keygen.getCertificate();
        Key caKey = keygen.getKey();

        //save to Client and server trusted cert dir to mimic a cert that is already presnet on the system
        //This is similar to how OS's ship with trusted certs already on the system
        caCertificate.outputCertificateToFile(new File(CertificateOfAuthority.CertificateFile_Default));
        caCertificate.outputCertificateToFile(new File(Server.TrustedCertsDir_Default + "/ca.crt"));
        caCertificate.outputCertificateToFile(new File(Client.TrustedCertsDir_Default + "/ca.crt"));

        //save CA private key
        caKey.outputKeyToFile(new File(CertificateOfAuthority.KeyFile_Default));

        //Load any trusted certs
        HashMap<Principal, Certificate> certificateStore = getCertificateStore(CertificateOfAuthority.TrustedCertsDir_Default);

        //Start CA entity
        ServerSocket serverSocket = new ServerSocket(CertificateOfAuthority.Port);
        while (true){
            Socket socket = serverSocket.accept();
            System.out.println("Handling new CA connection");
            new Thread(new CertificateOfAuthority(socket, certificateStore, caCertificate, caKey)).start();
        }
    }

    /**
     * Generates clients key/cert
     * starts client entity
     * @throws Exception
     */
    private static void startClient()throws Exception{

        //load CA cert
        Certificate caCertificate = new Certificate(new File(Client.CACertificateFile_Default));
        //socket to talk to CA
        Socket caSocket = new Socket("localhost", CertificateOfAuthority.Port);

        System.out.println("Generating Certs and Keys...");
        Keygen keygen = new Keygen(Keygen.generateX500Name(Client.X500Name_CommonName));

        //get new cert signed by CA
        Key clientKey = keygen.getKey();
        SocketMessage messageForCA = new SocketMessage(false, caCertificate.encrypt(keygen.getCertificate().getEncoded()));
        SocketMessage replyFromCA = EntityUtil.getCertificateSigned(caSocket, messageForCA);
        Certificate clientCertificate = new Certificate(EntityUtil.decryptMessage(caCertificate, clientKey, replyFromCA.getData()));

        //save cert and key
        clientKey.outputKeyToFile(new File(Client.KeyFile_Default));
        clientCertificate.outputCertificateToFile(new File(Client.CertificateFile_Default));

        //load trusted certs
        HashMap<Principal, Certificate> certificateStore = getCertificateStore(Client.TrustedCertsDir_Default);

        //socket to talk to server
        Socket socket = new Socket("localhost", Server.Port);
        //start client entity
        new Thread(new Client(socket, certificateStore, clientCertificate, clientKey)).start();
    }

    //helper method to load trusted certs
    private static HashMap<Principal, Certificate> getCertificateStore(String trustedCertsDir){
        HashMap<Principal, Certificate> certificateStore = new HashMap<Principal, Certificate>();
        if(new File(trustedCertsDir).listFiles().length > 0){
            for(File file : new File(trustedCertsDir).listFiles()){
                try {
                    if(file.getName().contains(".crt")) {
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
