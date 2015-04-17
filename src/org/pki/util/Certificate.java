package org.pki.util;

import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;
import sun.security.x509.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
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
            this.certificate.verify(certificate.getPublicKey());
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

    public void outputCertificateToFile(File file) throws CertificateEncodingException, IOException{
        if(file.exists()){
            System.out.println("Overwriting existing file");
            file.delete();
        }
        file.createNewFile();
        BufferedWriter out = new BufferedWriter(new FileWriter(file));
        BASE64Encoder encoder = new BASE64Encoder();
        out.write(X509Factory.BEGIN_CERT);
        out.newLine();
        out.write(encoder.encode(this.getEncoded()));
        out.newLine();
        out.write(X509Factory.END_CERT);
        out.close();
    }

    public byte[] getEncoded() throws CertificateEncodingException{
        return this.certificate.getEncoded();
    }

    public X509CertImpl getX509Certificate(){
        return this.certificate;
    }

    public PublicKey getPublicKey(){
        return getX509Certificate().getPublicKey();
    }

//    public Certificate sign(Certificate certificateToSign, Key key) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, SignatureException, IOException{
//        X509CertImpl cert = certificateToSign.getX509Certificate();
//        cert.sign(key.getPrivateKey(), certificateToSign.getSigAlgName());
//        cert.set(X509CertImpl.ISSUER_DN, this.getSubject());
//        return new Certificate(cert);
//    }

    public Certificate sign(Certificate certificateToSign, Key key) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, SignatureException, IOException{
        X509CertImpl cert = certificateToSign.getX509Certificate();

        X509CertInfo newCertInfo = (X509CertInfo)cert.get
                (X509CertImpl.NAME + "." + X509CertImpl.INFO);

        X509CertInfo caCertInfo = (X509CertInfo)this.certificate.get
                (X509CertImpl.NAME + "." + X509CertImpl.INFO);
        X500Name issuer = (X500Name)caCertInfo.get
                (X509CertInfo.SUBJECT + "." + CertificateIssuerName.DN_NAME);


        // Set the issuer
        newCertInfo.set(X509CertInfo.ISSUER +
                "." + CertificateSubjectName.DN_NAME, issuer);

        X509CertImpl newCert = new X509CertImpl(newCertInfo);
        newCert.sign(key.getPrivateKey(), this.getSigAlgName());
        return new Certificate(newCert);
    }

    public String getSigAlgName(){
        return this.certificate.getSigAlgName();
    }

    public Principal getIssuerDN(){
        return this.certificate.getIssuerDN();
    }

    public byte[] encrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encryptOrDecrypt(data, true);
    }

    public byte[] decrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        return encryptOrDecrypt(data, false);
    }

    public boolean equals(Certificate cert){
        return this.certificate.equals(cert.getX509Certificate());
    }

    private byte[] encryptOrDecrypt(byte[] data, boolean encrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        Cipher cipher = Cipher.getInstance(this.getPublicKey().getAlgorithm());
        cipher.init(mode, this.getPublicKey());

        byte[] temp = new byte[0]; //temp result holder
        int blockLength = encrypt ? cipher.getOutputSize(1) - 20 : cipher.getOutputSize(1);

        int offset = 0;
        int totalBlocks = (int) Math.ceil((double)data.length / (double)blockLength);
        for(int i = 0; i < totalBlocks - 1; i++){
            temp = concatenateByteArrays(temp,cipher.doFinal(data, offset, blockLength));
            offset = offset + blockLength;
        }
        return concatenateByteArrays(temp, cipher.doFinal(data, offset, data.length - offset));
    }

    private byte[] concatenateByteArrays(byte[] org_array, byte[] new_array){
        byte[] output = new byte[org_array.length + new_array.length];
        System.arraycopy(org_array, 0, output, 0, org_array.length);
        System.arraycopy(new_array, 0, output, org_array.length, new_array.length);
        return output;
    }
}
