package org.pki.entities;


import org.pki.dto.SocketMessage;
import org.pki.util.Certificate;
import org.pki.util.EntityUtil;
import org.pki.util.Key;
import org.pki.util.SocketIOStream;
import sun.security.x509.X500Name;
import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.HashMap;

public class Client implements Runnable{

    private Socket socket;
    private HashMap<Principal, Certificate> certificateStore;
    private Certificate certificate;
    private Key privateKey;
    private Certificate serverCertificate;

    public Client(Socket socket, HashMap<Principal, Certificate> certificateStore, Certificate certificate, Key privateKey){
        this.socket = socket;
        this.certificateStore = certificateStore;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        try{
            SocketIOStream socketIOStream = new SocketIOStream(socket.getInputStream(), socket.getOutputStream());

            //validates client certificate
            try{
                this.serverCertificate = new Certificate(socketIOStream.readMessage().getData());
                EntityUtil.validateCertificate(certificateStore, serverCertificate);
            }catch (CertificateException e){
                socketIOStream.sendMessage(new SocketMessage(true, e.getMessage().getBytes()));
                System.out.println("Problem validating clients certificate, terminating connection" + e.getMessage());
            }catch (Exception e){
                e.printStackTrace();
            }


            //if clientCertificate is null, it is invalid
            if(serverCertificate != null){
                //encrypt server's cert with client's public anad send it to client
                SocketMessage certMessage = new SocketMessage(false, EntityUtil.encryptMessage(this.serverCertificate.getEncoded(),privateKey,certificate.getB));
                socketIOStream.sendMessage(certMessage);
            }else{
                socketIOStream.close();
                socket.close();
                return;
            }

            String request = null;
            while(request != "DONE"){
                request = socketIOStream.readMessage().getData().toString();
                System.out.println(request);
            }

        }catch (IOException e){
            e.printStackTrace();
        }catch (CertificateEncodingException e) {
            e.printStackTrace();
        }catch (Exception e){
            e.printStackTrace();
        }

    }

    public static X500Name getX500Name()throws IOException{
        X500Name x500Name = new X500Name(X500Name_CommonName, X500Name_OrganizationalUnit, X500Name_Organization, X500Name_City, X500Name_State, X500Name_Country);
        return x500Name;
    }

    public static final String TrustedCertsDir_Default = "certificatestore/client/trustedcerts";
    public static final String CertificateFile_Default = "certificatestore/client/cert.crt";
    public static final String KeyFile_Default = "certificatestore/client/key.key";
    public static final boolean OverwriteKeys = true;

    private static final String X500Name_CommonName = "SecureBankClient";
    private static final String X500Name_OrganizationalUnit = "na";
    private static final String X500Name_Organization = "Personal";
    private static final String X500Name_City = "SomeCity";
    private static final String X500Name_State = "SomeState";
    private static final String X500Name_Country = "Internet";
}
