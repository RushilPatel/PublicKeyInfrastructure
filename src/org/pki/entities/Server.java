package org.pki.entities;

import org.pki.dto.SocketMessage;
import org.pki.x509.Certificate;
import org.pki.util.EntityUtil;
import org.pki.x509.Key;
import org.pki.util.SocketIOStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;

public class Server implements Runnable{
    public static final String DEPOSIT = "DEPOSIT";
    public static final String WITHDRAW = "WITHDRAW";
    public static final String BALANCE = "BALANCE";
    public static final String DONE = "DONE";
    public static final String TrustedCertsDir_Default = "certificatestore/server/trustedcerts";
    public static final String CACertificateFile_Default = "certificatestore/server/trustedcerts/ca.crt";
    public static final String CAHost_Default = "localhost";
    public static final String CertificateFile_Default = "certificatestore/server/cert.crt";

    public static final String KeyFile_Default = "certificatestore/server/key.key";
    public static final int Port = 7777;
    public static final String X500Name_CommonName = "www.SecureBankServer.fit.edu";



    private Socket socket;
    private HashMap<Principal, Certificate> certificateStore;
    private Certificate certificate;
    private Key privateKey;
    private Certificate clientCertificate;
    private SocketIOStream socketIOStream = null;
    private double clientBalance = 1000;


    /**
     *
     * @param socket new client connection
     * @param certificateStore the cert store to use for authentication
     * @param certificate my cert to sign my messages with
     * @param privateKey my private key to decrypt incoming messages
     */
    public Server(Socket socket, HashMap<Principal, Certificate> certificateStore, Certificate certificate, Key privateKey){
        this.socket = socket;
        this.certificateStore = certificateStore;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }


    @Override
    public void run() {
        try{
            socketIOStream = new SocketIOStream(socket.getInputStream(), socket.getOutputStream()); // set up in and out streams from client

            //validates client certificate
            try{
                //read client certificate. This is sent in clear text
                this.clientCertificate = new Certificate(socketIOStream.readMessage().getData());
                System.out.println("Server: Client certificate received");
                System.out.println("Server: Validating client certificate");
                EntityUtil.validateCertificate(certificateStore, clientCertificate);
            }catch (Exception e){
                //inform server of an error
                socketIOStream.sendMessage(new SocketMessage(true, e.getMessage().getBytes()));
                System.out.println("Server: Could not validate client's certificate, terminating connection" + e.getMessage());
                clientCertificate = null;
                e.printStackTrace();
            }


            //if clientCertificate is null, it is invalid
            if(clientCertificate != null){
                System.out.println("Server: Client certificate was validated successfully");
                System.out.println("Server: Sending my certificate to the client");
                //encrypt server's cert with client's public key send it to client
                SocketMessage certMessage = new SocketMessage(false,this.clientCertificate.encrypt(this.certificate.getEncoded()));
                socketIOStream.sendMessage(certMessage);
                System.out.println("Server: Certificate exchange complete. All outgoing communication will now be encrypted using server's private key and client's public key");
                System.out.println("Server: Now handling banking application requests");
            }else{
                socketIOStream.close();
                socket.close();
                return;
            }

            while(!handleClientRequest().contains(DONE)); //handles client requests

        }catch (IOException e){
            e.printStackTrace();
        }catch (CertificateEncodingException e) {
            e.printStackTrace();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Handles the client while they continue to make requests
     * @return
     */
    private String handleClientRequest(){
        String req = "";
        try {
            //decrypt client request
            req = new String(EntityUtil.decryptMessage(clientCertificate, privateKey, socketIOStream.readMessage().getData()));

            if(req.contains(DEPOSIT)){
                String[] ary = req.split(":");
                clientBalance += Double.parseDouble(ary[1]);
                System.out.println("Server: Deposited $" + ary[1]);
            }else if(req.contains(WITHDRAW)){
                String[] ary = req.split(":");
                clientBalance -= Double.parseDouble(ary[1]);
                System.out.println("Server: Withdrawn $" + ary[1]);
            }else if(req.contains(BALANCE)){
                System.out.println("Server: Reporting client's balance");
                SocketMessage balMsg = new SocketMessage(false,
                        EntityUtil.encryptMessage(clientCertificate, privateKey,
                                Double.toString(clientBalance).getBytes()));
                socketIOStream.sendMessage(balMsg);
            }else if(req.contains(DONE)){
                System.out.println("Server: Client is finished. Terminating connection");
            }else{
                System.out.println("Server: Unrecognized request, ignoring");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return req;
    }
}
