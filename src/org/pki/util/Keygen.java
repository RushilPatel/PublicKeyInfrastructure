package org.pki.util;

import sun.security.pkcs.PKCS10;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;

import java.io.File;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class Keygen {
    private Certificate certificate;
    private Key key;

    public Keygen(File certFile, File keyFile, X500Name x500Name,Socket caSocket) throws Exception{
        generateKeyPair(certFile, keyFile, x500Name,caSocket);
    }

    private void generateKeyPair(File certFile, File keyFile, X500Name x500Name,Socket socket) throws Exception{
        CertAndKeyGen keypair = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
        keypair.generate(1024);
        key = new Key(keypair.getPrivateKey());
        //certificate = getSignedCertificate(keypair.getSelfCertificate(x500Name, 1096), socket);
        //output certificate and key files to the directory
        key.outputKeyToDirectory(keyFile);
        certificate.outputCerticateToDirectory(certFile);

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

    //move this to CA

    public Certificate signPublicKey(X509Certificate certificateToSign) throws Exception{
        Certificate caCertificate = null; //load ca certificate
        Key caKey = null; //load ca key

        X509CertImpl cert = X509CertImpl.toImpl(certificateToSign);
        cert.sign(caKey.getPrivateKey(), cert.getSigAlgName());
        cert.set(X509CertImpl.ISSUER_DN, cert.getIssuerDN());
        return new Certificate(cert);
    }

}
