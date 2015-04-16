package org.pki.entities;

import sun.security.x509.X500Name;

import java.io.IOException;
import java.net.Socket;

public class Client implements Runnable{

    @Override
    public void run() {
        try{
            Socket socket = new Socket("localhost", 7777);

        }catch (IOException e){
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
