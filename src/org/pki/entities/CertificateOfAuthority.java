package org.pki.entities;

import org.pki.dto.SocketMessage;
import org.pki.util.Certificate;
import org.pki.util.EntityUtil;
import org.pki.util.Key;
import org.pki.util.SocketIOStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.util.HashMap;

public class CertificateOfAuthority implements Runnable{
    public static final String TrustedCertsDir_Default = "certificatestore/ca/trustedcerts";
    public static final String CertificateFile_Default = "certificatestore/ca/cert.crt";
    public static final String KeyFile_Default = "certificatestore/ca/key.key";
    public static final int Port = 8888;
    public static final String X500Name_CommonName = "www.CertAuth.fit.edu";


    private Socket socket = null;
    private HashMap<Principal, Certificate> certificateStore;
    private Certificate certificate = null;
    private Key privateKey = null;

    /**
     * creates a new CA obj for each validation request
     * @param socket socket to talk to entitiy trying to validate a cert
     * @param certificateStore by store of trusted certs
     * @param certificate my cert to sign stuff with
     * @param privateKey my priv key to decrypt stuff with
     */
    public CertificateOfAuthority(Socket socket, HashMap<Principal, Certificate> certificateStore, Certificate certificate, Key privateKey){
        this.socket = socket;
        this.certificateStore = certificateStore;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        try{
            SocketIOStream socketIOStream = new SocketIOStream(socket.getInputStream(), socket.getOutputStream());
            SocketMessage message = socketIOStream.readMessage();

            //the certificate signing request is encrypted with CA public key
            Certificate clientCert = new Certificate(this.privateKey.decrypt(message.getData()));
            //sign client certificate
            System.out.println("CA: Signing certificate");
            Certificate signedClientCertificate = this.certificate.sign(clientCert, this.privateKey);
            //encrypt the certificate and then send it. The receiver has CA's public key and its own private key, so it will be able to decrypt the signed cert
            byte[] encryptedCert = EntityUtil.encryptMessage(signedClientCertificate, this.privateKey, signedClientCertificate.getEncoded());
            System.out.println("CA: Sending signed certificate");
            SocketMessage socketMessage = new SocketMessage(false, encryptedCert);
            socketIOStream.sendMessage(socketMessage); //send signed certificate
            socketIOStream.close();
        }catch (IOException e){
            e.printStackTrace();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
