package org.pki.entities;

import org.pki.dto.SocketMessage;
import org.pki.util.Certificate;
import org.pki.util.Key;
import org.pki.util.SocketIOStream;
import sun.security.x509.X500Name;
import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.HashMap;

public class Server implements Runnable{

    private Socket socket;
    private HashMap<Principal, Certificate> certificateStore;
    private Certificate certificate;
    private Key privateKey;
    private Certificate clientCertificate;

    public Server(Socket socket, HashMap<Principal, Certificate> certificateStore, Certificate certificate, Key privateKey){
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
                this.clientCertificate = new Certificate(socketIOStream.readMessage().getData());
                validateCertificate(clientCertificate);
            }catch (CertificateException e){
                socketIOStream.sendMessage(new SocketMessage(true, e.getMessage().getBytes()));
            }catch (Exception e){
                e.printStackTrace();
            }

            //if clientCertificate is null, it is invalid
            if(clientCertificate != null){
                //encrypt server's cert with client's public anad send it to client
                SocketMessage certMessage = new SocketMessage(false, encryptMessage(this.certificate.getX509Certificate().getEncoded()));
                socketIOStream.sendMessage(certMessage);

            }else{
                socketIOStream.close();
                socket.close();
            }
        }catch (IOException e){
            e.printStackTrace();
        }catch (CertificateEncodingException e) {
            e.printStackTrace();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private byte[] encryptMessage(byte[] data) throws Exception{
        return this.clientCertificate.encrypt(data);
    }

    private byte [] decryptMessage(byte[] data) throws Exception{
        return this.privateKey.decrypt(data);
    }

    private void validateCertificate(Certificate certificate) throws Exception{
        if(certificate.hasExpired()){
            throw new CertificateException("Cerificate has expired!");
        }else if(certificate.isSelfSigned()){
            throw new CertificateException("Certificate is self signed!");
        }else{
            validateCertificateSignature(certificate);
        }
    }

    private void validateCertificateSignature(Certificate certificate) throws Exception{
        Certificate caCertificate = certificateStore.get(certificate.getIssuer());
        if(caCertificate == null){
            throw new CertificateException("Untrusted issuer: " + certificate.getIssuer());
        }else{
            if(!caCertificate.getIssuer().equals(caCertificate.getSubject())){
                validateCertificateSignature(caCertificate);
            }
            if(!certificate.isSignedBy(caCertificate)){
                throw new CertificateException(String.format("Certificate of Subject (%s) is not signed by its Issuer (%s)" , certificate.getSubject(), certificate.getIssuer()));
            }
        }
    }

     public static X500Name getX500Name()throws IOException{
         X500Name x500Name = new X500Name(X500Name_CommonName, X500Name_OrganizationalUnit, X500Name_Organization, X500Name_City, X500Name_State, X500Name_Country);
         return x500Name;
     }
    public static final String TrustedCertsDir_Default = "certificatestore/server/trustedcerts";
    public static final String CertificateFile_Default = "certificatestore/server/cert.crt";
    public static final String KeyFile_Default = "certificatestore/server/key.key";
    public static final boolean OverwriteKeys = true;
    public static final int Port = 7777;

    private static final String X500Name_CommonName = "www.SecureBankServer.fit.edu";
    private static final String X500Name_OrganizationalUnit = "IT";
    private static final String X500Name_Organization = "SecureBank";
    private static final String X500Name_City = "SomeCity";
    private static final String X500Name_State = "SomeState";
    private static final String X500Name_Country = "Internet";
}
