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
import java.util.Scanner;

public class Client implements Runnable{

    private Socket socket;
    private HashMap<Principal, Certificate> certificateStore;
    private Certificate certificate;
    private Key privateKey;
    private Certificate serverCertificate;
    private Scanner num = null;
    SocketIOStream socketIOStream = null;

    public Client(Socket socket, HashMap<Principal, Certificate> certificateStore, Certificate certificate, Key privateKey){
        this.socket = socket;
        this.certificateStore = certificateStore;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        try{
            num = new Scanner(System.in);
            socketIOStream = new SocketIOStream(socket.getInputStream(), socket.getOutputStream());
            SocketMessage certMessage = new SocketMessage(false,this.certificate.getEncoded());
            socketIOStream.sendMessage(certMessage);


            //validates client certificate
            try{
                this.serverCertificate = new Certificate(socketIOStream.readMessage().getData());
                EntityUtil.validateCertificate(certificateStore, serverCertificate);
                System.out.println("Server certificate validated");
            }catch (CertificateException e){
                socketIOStream.sendMessage(new SocketMessage(true, e.getMessage().getBytes()));
                System.out.println("Problem validating clients certificate, terminating connection" + e.getMessage());
            }catch (Exception e){
                e.printStackTrace();
            }

            //if clientCertificate is null, it is invalid
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

    private String getUserRequest()throws Exception{
        int transaction;
        double balance = 0;
        double amount;
        boolean done = false;
        do {
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
                        System.out.println("$" + amount + " has been deposited into your account.");                        System.out.println("$" + amount + " has been withdrawn from your account.");
                    }
                    break;
                case 3:
                    SocketMessage withdrawMsg = new SocketMessage(false,
                            EntityUtil.encryptMessage(serverCertificate, privateKey,
                                    Server.BALANCE.getBytes()));
                    socketIOStream.sendMessage(withdrawMsg);
                    socketIOStream.readMessage();
                    byte[] myBalance = EntityUtil.decryptMessage(serverCertificate,privateKey,socketIOStream.readMessage().getData());
                    String bal = new String(myBalance);
                    System.out.println(bal);
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


        return null;
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
