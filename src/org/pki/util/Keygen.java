package org.pki.util;

import org.pki.entities.CertificateOfAuthority;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.File;
import java.net.Socket;
import java.security.cert.X509Certificate;

public class Keygen {
    private Certificate certificate;
    private Key key;
    public static final int KeySize = 1024;

    public Keygen(File certFile, File keyFile, X500Name x500Named,Socket caSocket) throws Exception{
        CertAndKeyGen unsignedKey = generateKeyPair();
        if(x500Named == CertificateOfAuthority.getX500Name()){
            System.out.println("I am the CA, self signing");
            certificate = new Certificate(unsignedKey.getSelfCertificate(x500Named, 1096));
        }else{
            certificate = getSignedCertificate(unsignedKey.getSelfCertificate(x500Named, 1096),key, caSocket);
        }
        key.outputKeyToDirectory(keyFile);
        certificate.outputCertificateToDirectory(certFile);
    }

    private CertAndKeyGen generateKeyPair() throws Exception{
        CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
        keypair.generate(KeySize);
        key = new Key(keypair.getPrivateKey());
        return keypair;
    }

    private Certificate getSignedCertificate(X509Certificate certificateToSign, Key key, Socket socket){

        return null; // return signed key
    }

    public Key getKey(){
        return this.key;
    }

    public Certificate getCertificate(){
        return this.certificate;
    }




}
