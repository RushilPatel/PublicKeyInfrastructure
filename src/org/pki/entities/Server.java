package org.pki.entities;

import org.pki.dto.SocketMessage;
import org.pki.util.Certificate;
import org.pki.util.EntityUtil;
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
                this.clientCertificate = new Certificate(socketIOStream.readMessage().getData());
                EntityUtil.validateCertificate(certificateStore, clientCertificate);
            }catch (CertificateException e){
                socketIOStream.sendMessage(new SocketMessage(true, e.getMessage().getBytes()));
                System.out.println("Problem validating clients certificate, terminating connection" + e.getMessage());
            }catch (Exception e){
                e.printStackTrace();
            }


            //if clientCertificate is null, it is invalid
            if(clientCertificate != null){
                //encrypt server's cert with client's public anad send it to client
                SocketMessage certMessage = new SocketMessage(false,this.clientCertificate.encrypt(this.certificate.getEncoded()));
                socketIOStream.sendMessage(certMessage);
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
            System.out.println("\nNew Message: "+new String(req));

            if(req.contains(DEPOSIT)){
                String[] ary = req.split(":");
                System.out.println("Depositing : " + ary[1]);
                clientBalance += Double.parseDouble(ary[1]);
            }else if(req.contains(WITHDRAW)){
                String[] ary = req.split(":");
                System.out.println("Withdrawing : " + ary[1]);
                clientBalance -= Double.parseDouble(ary[1]);
            }else if(req.contains(BALANCE)){
                System.out.println("Reporting client's balance");
                SocketMessage balMsg = new SocketMessage(false,
                        EntityUtil.encryptMessage(clientCertificate, privateKey,
                                Double.toString(clientBalance).getBytes()));
                socketIOStream.sendMessage(balMsg);
            }else if(req.contains(DONE)){
                System.out.println("Client is finished. Terminating connection");
            }else{
                System.out.println("Unrecognized request, ignoring");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return req;
    }

    public static final String DEPOSIT = "DEPOSIT";
    public static final String WITHDRAW = "WITHDRAW";
    public static final String BALANCE = "BALANCE";
    public static final String DONE = "DONE";
    public static final String TrustedCertsDir_Default = "certificatestore/server/trustedcerts";
    public static final String CACertificateFile_Default = "certificatestore/server/trustedcerts/ca.crt";
    public static final String CertificateFile_Default = "certificatestore/server/cert.crt";
    public static final String KeyFile_Default = "certificatestore/server/key.key";
    public static final int Port = 7777;
    public static final String X500Name_CommonName = "www.SecureBankServer.fit.edu";
}
