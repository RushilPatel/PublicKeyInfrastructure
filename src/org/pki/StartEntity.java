package org.pki;

import org.pki.entities.Server;
import org.pki.util.Certificate;
import org.pki.util.Key;
import org.pki.util.Keygen;

import java.io.File;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Principal;
import java.util.HashMap;

public class StartEntity {
    public static void main(String [] args) throws Exception{
        if(args.length > 4){
            System.out.println("Error: Invalid Arguments!");
        }else{
            String role = args[0];
            if(role.equals("SERVER")){
                startServer(args[1], args[2], args[3]);
            }else if(role.equals("CLIENT")){
                startClient();
            }else if(role.equals("CA")){
                startCertificateOfAuthority();
            }else {
                System.out.println("Error: Invalid Role!");
            }
        }
    }

    private static void startServer(String trustedCertsDir, String certificatePath, String keyPath) throws Exception{
        if(certificatePath == null){
            certificatePath = Server.CertificateFile_Default;
        }
        if(keyPath == null) {
            keyPath = Server.KeyFile_Default;
        }
        File cp = new File(certificatePath);
        File kp = new File(keyPath);
        if((!cp.exists() && !kp.exists()) || Server.OverwriteKeys){
            System.out.println("Generating Certs and Keys...");
            Keygen kg = new Keygen(cp,kp,Server.getX500Name(),new Socket());
        }

        // Load certs/keys
        Certificate serverCertificate = new Certificate(cp);
        Key serverKey = new Key(kp);
        HashMap<Principal, Certificate> certificateStore = getCertificateStore(trustedCertsDir);

        ServerSocket serverSocket = new ServerSocket(Server.Port);
        while (true){
            Socket socket = serverSocket.accept();
            new Thread(new Server(socket, certificateStore, serverCertificate, serverKey)).start();
        }
    }

    private static void startCertificateOfAuthority(){
        String trustedCertsDir = "certificatestore/ca/trustedcerts";

    }

    private static void startClient(){
        String trustedCertsDir = "certificatestore/ca/trustedcerts";

    }

    private static HashMap<Principal, Certificate> getCertificateStore(String trustedCertsDir) throws Exception{
        HashMap<Principal, Certificate> certificateStore = new HashMap<Principal, Certificate>();

        for(File file : new File(trustedCertsDir).listFiles()){
            Certificate certificate = new Certificate(file);
            certificateStore.put(certificate.getSubject(), certificate);
        }
        return certificateStore;
    }
}
