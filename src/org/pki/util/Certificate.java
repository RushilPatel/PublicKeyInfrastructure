package org.pki.util;

import sun.security.x509.X509CertImpl;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Certificate {

    private X509Certificate certificate;

    public Certificate(File file) throws FileNotFoundException, CertificateException{
        this.certificate = new X509CertImpl(new FileInputStream(file));
    }

    public Certificate (byte[] certData) throws CertificateException{
        this.certificate = new X509CertImpl(certData);
    }

    public Certificate(X509Certificate x509Certificate){
        this.certificate = x509Certificate;
    }

    public boolean hasExpired(){
        try{
            this.certificate.checkValidity();
            return false;
        }catch (Exception e){
            return true;
        }
    }


    public boolean isSelfSigned() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException{
        return isSignedBy(this);
    }

    public boolean isSignedBy(Certificate certificate) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException{
        try{
            this.certificate.verify(certificate.getX509Certificate().getPublicKey());
            return true;
        }catch (SignatureException e){
            return false;
        }catch(InvalidKeyException e){
            return false;
        }
    }

    public X509Certificate getX509Certificate(){
        return this.certificate;
    }

}
