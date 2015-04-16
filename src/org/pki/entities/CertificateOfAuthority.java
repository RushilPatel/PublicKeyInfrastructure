package org.pki.entities;

import org.pki.dto.SocketMessage;
import org.pki.util.Certificate;
import org.pki.util.Key;
import org.pki.util.SocketIOStream;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;

import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

public class CertificateOfAuthority implements Runnable{

    private Socket socket = null;
    private HashMap<Principal, Certificate> certificateStore;
    private Certificate certificate = null;
    private Key privateKey = null;

    public CertificateOfAuthority(Socket socket, HashMap<Principal, Certificate> certificateStore, Certificate certificate, Key privateKey){
        //todo add in null/validity checks
        this.socket = socket;
        this.certificateStore = certificateStore;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {

    }

    public Certificate signPublicKey(X509Certificate certificateToSign) throws Exception{
        X509CertImpl cert = X509CertImpl.toImpl(certificateToSign);
        cert.sign(privateKey.getPrivateKey(), cert.getSigAlgName());
        cert.set(X509CertImpl.ISSUER_DN, cert.getIssuerDN());
        return new Certificate(cert);
    }

    public static X500Name getX500Name()throws IOException {
        X500Name x500Name = new X500Name(X500Name_CommonName, X500Name_OrganizationalUnit, X500Name_Organization, X500Name_City, X500Name_State, X500Name_Country);
        return x500Name;
    }

    public static final String TrustedCertsDir_Default = "certificatestore/ca/trustedcerts";
    public static final String CertificateFile_Default = "certificatestore/ca/cert.crt";
    public static final String KeyFile_Default = "certificatestore/ca/key.key";
    public static final boolean OverwriteKeys = true;
    public static final int Port = 8888;

    public static final String X500Name_CommonName = "www.CertAuth.fit.edu";
    private static final String X500Name_OrganizationalUnit = "Admin";
    private static final String X500Name_Organization = "fit";
    private static final String X500Name_City = "NoWhere";
    private static final String X500Name_State = "SomeState";
    private static final String X500Name_Country = "Internet";
}
