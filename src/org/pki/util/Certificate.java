package org.pki.util;

import sun.security.x509.X509CertImpl;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

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

    public boolean outputCertificateToDirectory(File file) throws Exception{
        if(file.exists()){
            System.out.println("Overwriting existing file");
            file.delete();
        }
        byte dataToWrite[] = this.certificate.getEncoded();
        FileOutputStream out = new FileOutputStream(file.getPath());
        out.write(dataToWrite);
        out.close();
        return true;
    }

    public X509CertImpl getX509Certificate(){
        return this.certificate;
    }

    public PublicKey getPublicKey(){
        return getX509Certificate().getPublicKey();
    }

    public byte[] encrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encryptOrDecrypt(data, true);
    }

    public byte[] decrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        return encryptOrDecrypt(data, false);
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
