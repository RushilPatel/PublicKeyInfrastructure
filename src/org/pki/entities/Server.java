package org.pki.entities;

import org.pki.dto.SocketMessage;
import org.pki.util.Certificate;
import org.pki.util.Key;
import org.pki.util.SocketIOStream;

import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.HashMap;

public class Server implements Runnable{

    private Socket socket;

    private HashMap<Principal, Certificate> certificateStore;
    private Certificate serverCertificate;
    private Key serverKey;

    public Server(Socket socket, HashMap<Principal, Certificate> certificateStore, Certificate serverCertificate, Key serverKey){
        this.socket = socket;
        this.certificateStore = certificateStore;
        this.serverCertificate = serverCertificate;
        this.serverKey = serverKey;
    }

    @Override
    public void run() {
        try{
            SocketIOStream socketIOStream = new SocketIOStream(socket.getInputStream(), socket.getOutputStream());
            Certificate clientCertificate = null;
            try{
                clientCertificate = new Certificate(socketIOStream.readMessage().getData());
                validateCertificate(clientCertificate);

                //send cert to client
            }catch (CertificateException e){
                socketIOStream.sendMessage(new SocketMessage(true, e.getMessage().getBytes()));
            }catch (Exception e){
                e.printStackTrace();
            }

            if(clientCertificate != null){
                SocketMessage certMessage = new SocketMessage(false, this.serverCertificate.getX509Certificate().getEncoded());
                socketIOStream.sendMessage(certMessage);
            }else{
                socketIOStream.close();
                socket.close();
            }
        }catch (IOException e){
            e.printStackTrace();
        }catch (CertificateEncodingException e){
            e.printStackTrace();
        }

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
}
