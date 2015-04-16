package org.pki.util;

import sun.security.x509.X509CertImpl;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Certificate {

    private X509CertImpl certificate;

    public Certificate(File file) throws FileNotFoundException, CertificateException{
        this.certificate = new X509CertImpl(new FileInputStream(file));
    }

    public Certificate (byte[] certData) throws CertificateException{
        this.certificate = new X509CertImpl(certData);
    }

    public Certificate(X509Certificate x509Certificate) throws CertificateException{
        this.certificate = X509CertImpl.toImpl(x509Certificate);
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

    public Principal getIssuer(){
        return this.certificate.getIssuerDN();
    }

    public Principal getSubject(){
        return this.certificate.getSubjectDN();
    }

    public boolean outputCertificateToDirectory(File file) throws IOException{
        if(file.exists()){
            System.out.println("Overwriting existing file");
            file.delete();
        }
        return file.createNewFile();
    }

    public X509CertImpl getX509Certificate(){
        return this.certificate;
    }

    public byte[] sign(byte[] data){
        return null;
    }

}
