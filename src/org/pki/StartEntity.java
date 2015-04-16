package org.pki;

import org.pki.entities.Server;
import org.pki.util.Certificate;
import org.pki.util.Key;

import java.io.File;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Principal;
import java.util.HashMap;

public class StartEntity {
    public static void main(String [] args) throws Exception{
        if(args.length < 4){
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
        Certificate serverCertificate = new Certificate(new File(certificatePath));
        Key serverKey = new Key(new File(keyPath));
        HashMap<Principal, Certificate> certificateStore = getCertificateStore(trustedCertsDir);

        ServerSocket serverSocket = new ServerSocket(7777);
        while (true){
            Socket socket = serverSocket.accept();
            new Thread(new Server(socket, certificateStore, serverCertificate, serverKey)).start();
        }
    }

    private static void startCertificateOfAuthority(){
        String trustedCertsDir = "certificatestore/server/trustedcerts";

    }

    private static void startClient(){
        String trustedCertsDir = "certificatestore/server/trustedcerts";

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
