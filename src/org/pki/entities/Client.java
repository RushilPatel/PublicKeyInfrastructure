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
import java.util.Scanner;

/**
 * This class acts like a client to the banking sever
 */
public class Client implements Runnable{

    private Socket socket;
    private HashMap<Principal, Certificate> certificateStore;
    private Certificate certificate;
    private Key privateKey;
    private Certificate serverCertificate;
    private Scanner num = null;
    SocketIOStream socketIOStream = null;

    /**
     * creates a new client obj to interact with the serer
     * @param socket socket to use when talking to server
     * @param certificateStore my trusted certs
     * @param certificate my cert to sign requests with
     * @param privateKey my key to decrypt incoming messages
     */
    public Client(Socket socket, HashMap<Principal, Certificate> certificateStore, Certificate certificate, Key privateKey){
        this.socket = socket;
        this.certificateStore = certificateStore;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        try{
            num = new Scanner(System.in); // allows for user input
            socketIOStream = new SocketIOStream(socket.getInputStream(), socket.getOutputStream()); //sets up in/out on the socket
            socketIOStream.sendMessage(new SocketMessage(false,this.certificate.getEncoded())); // sends my cert to server for it to verify

            //validates server certificate
            try{
                this.serverCertificate = new Certificate((privateKey.decrypt(socketIOStream.readMessage().getData())));
                EntityUtil.validateCertificate(certificateStore, serverCertificate);
                System.out.println("Server certificate validated");
            }catch (CertificateException e){
                socketIOStream.sendMessage(new SocketMessage(true, e.getMessage().getBytes()));
                System.out.println("Problem validating clients certificate, terminating connection" + e.getMessage());
            }catch (Exception e){
                e.printStackTrace();
            }

            //if servercert is null, it is invalid
            if(serverCertificate != null){
                getUserRequest();
            }else{
                socketIOStream.close();
                socket.close();
                return;
            }

        }catch (IOException e){
            e.printStackTrace();
        }catch (CertificateEncodingException e) {
            e.printStackTrace();
        }catch (Exception e){
            e.printStackTrace();
        }

    }


    /**
     * this is where the clients requests are handled.
     * executing stays in here until the client is done making requests
     * @throws Exception us being lazy
     */
    private void getUserRequest()throws Exception{
        int transaction;
        double balance = 0;
        double amount;
        boolean done = false;
        do {
            //possible requests
            System.out.println("1. Deposit");
            System.out.println("2. Withdraw");
            System.out.println("3. Check balance");
            System.out.println("4. Done!");
            System.out.print("Enter your choice:  ");

            transaction = num.nextInt();
            switch (transaction) {
                case 1:
                    System.out.print("Enter Deposit Amount: ");
                    amount = num.nextDouble();

                    // validation.
                    if (amount <= 0)
                        System.out.println("Negative amount. Try again.");
                    else {
                        //send request to server
                        SocketMessage depositMsg = new SocketMessage(false,
                                EntityUtil.encryptMessage(serverCertificate, privateKey,
                                        (Server.DEPOSIT + ":" + Double.toString(amount)).getBytes()));
                        socketIOStream.sendMessage(depositMsg);
                        System.out.println("$" + amount + " has been deposited into your account.");
                    }
                    break;
                case 2:
                    System.out.print("Enter Withdraw Amount: ");

                    amount = num.nextDouble();

                    // validation.
                    if (amount < 0)
                        System.out.println("Negative amount. Try again.");
                    else {
                        SocketMessage withdrawMsg = new SocketMessage(false,
                                EntityUtil.encryptMessage(serverCertificate, privateKey,
                                        (Server.WITHDRAW + ":" + Double.toString(amount)).getBytes()));
                        socketIOStream.sendMessage(withdrawMsg);
                        System.out.println("$" + amount + " has been withdrawn from your account.");
                    }
                    break;
                case 3:
                    SocketMessage balReqMsg = new SocketMessage(false,
                            EntityUtil.encryptMessage(serverCertificate, privateKey,
                                    Server.BALANCE.getBytes()));
                    socketIOStream.sendMessage(balReqMsg);
                    //waits for response from the server
                    String bal = new String(EntityUtil.decryptMessage(serverCertificate,privateKey,socketIOStream.readMessage().getData()));
                    System.out.println("***** Balance: "+bal.toString() + "*****");
                    break;
                case 4:
                    SocketMessage doneMsg = new SocketMessage(false,
                            EntityUtil.encryptMessage(serverCertificate, privateKey,
                                    Server.DONE.getBytes()));
                    socketIOStream.sendMessage(doneMsg);
                    done = true;
                    break;

                default:
                    System.out.println("Invalid choice. Try again.");
                    break;
            }
            System.out.println();

        } while (!done);
        System.out.println("Have a good one!");
    }

    public static final String TrustedCertsDir_Default = "certificatestore/client/trustedcerts";
    public static final String CACertificateFile_Default = "certificatestore/server/trustedcerts/ca.crt";
    public static final String CertificateFile_Default = "certificatestore/client/cert.crt";
    public static final String KeyFile_Default = "certificatestore/client/key.key";
    public static final String X500Name_CommonName = "SecureBankClient";

}
