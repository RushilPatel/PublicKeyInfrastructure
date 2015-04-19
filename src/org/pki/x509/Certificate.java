package org.pki.x509;

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

    /**
     * load certificate from file
     * @param file - certificate file
     * @throws FileNotFoundException
     * @throws CertificateException
     */
    public Certificate(File file) throws FileNotFoundException, CertificateException{
        this.certificate = new X509CertImpl(new FileInputStream(file));
    }

    /**
     * load certificate from encoded bytes
     * @param certData - encoded bytes
     * @throws CertificateException
     */
    public Certificate (byte[] certData) throws CertificateException{
        this.certificate = new X509CertImpl(certData);
    }

    /**
     * load certificate from x509Certificate object
     * @param x509Certificate
     * @throws CertificateException
     */
    public Certificate(X509Certificate x509Certificate) throws CertificateException{
        this.certificate = X509CertImpl.toImpl(x509Certificate);
    }

    /**
     * check if the cert has expired
     * @return - true is expired, false otherwise
     */
    public boolean hasExpired(){
        try{
            this.certificate.checkValidity();
            return false;
        }catch (Exception e){
            return true;
        }
    }

    /**
     * Is the cert self signed
     * @return - true if self signed, false otherwise
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    public boolean isSelfSigned() throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException{
        return isSignedBy(this);
    }

    /**
     * verify that this cert signed by the given certificate
     * @param certificate - certificate to check against
     * @return
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
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

    /**
     * @return - certificate issuer
     */
    public Principal getIssuer(){
        return this.certificate.getIssuerDN();
    }

    /**
     * @return - certificate subject
     */
    public Principal getSubject(){
        return this.certificate.getSubjectDN();
    }

    /**
     * Output certificate to file
     * @param file - file to output certificate to
     * @throws CertificateEncodingException
     * @throws IOException
     */
    public void outputCertificateToFile(File file) throws CertificateEncodingException, IOException{
        if(file.exists()){
            System.out.println("Overwriting existing certificate file");
            file.delete();
        }
        file.getParentFile().mkdirs(); //create directories
        file.createNewFile(); //create new certificate file
        BufferedWriter out = new BufferedWriter(new FileWriter(file));
        BASE64Encoder encoder = new BASE64Encoder();
        out.write(X509Factory.BEGIN_CERT); //write header to the file
        out.newLine(); //new line
        //write cert data to the file, after Base64 encoding it
        out.write(encoder.encode(this.getEncoded()));
        out.newLine(); //new line
        out.write(X509Factory.END_CERT); //write footer
        out.close();
    }

    /**
     * returns encoded cert
     * @return - encoded bytes
     * @throws CertificateEncodingException
     */
    public byte[] getEncoded() throws CertificateEncodingException{
        return this.certificate.getEncoded();
    }

    /**
     * @return - X509CertImpl object
     */
    public X509CertImpl getX509Certificate(){
        return this.certificate;
    }

    /**
     * @return - cert's public key
     */
    public PublicKey getPublicKey(){
        return getX509Certificate().getPublicKey();
    }

    /**
     * use this certificate and given private key to sign the given certificate.
     * This method is intended to use by Certificate of Authority to sign certificates
     * @param certificateToSign - certificate that needs to be signed
     * @param key - private to be used to sign the certificate
     * @return - signed certificate
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws CertificateException
     * @throws SignatureException
     * @throws IOException
     */
    public Certificate sign(Certificate certificateToSign, Key key) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, SignatureException, IOException{
        X509CertImpl cert = certificateToSign.getX509Certificate();

        //extract cert info from the old certificate.
        //This is so we can reuse attributes like public key, validity, subject, etc.
        X509CertInfo newCertInfo = (X509CertInfo)cert.get
                (X509CertImpl.NAME + "." + X509CertImpl.INFO);

        //extract cert info from this certificate that will be used to
        // set 'issuer' attribute on the signed certificate
        X509CertInfo caCertInfo = (X509CertInfo)this.certificate.get
                (X509CertImpl.NAME + "." + X509CertImpl.INFO);
        X500Name issuer = (X500Name)caCertInfo.get
                (X509CertInfo.SUBJECT + "." + CertificateIssuerName.DN_NAME);


        // Set the issuer
        newCertInfo.set(X509CertInfo.ISSUER +
                "." + CertificateSubjectName.DN_NAME, issuer);

        //create cert with new info
        X509CertImpl newCert = new X509CertImpl(newCertInfo);
        //sign the newly created cert.
        newCert.sign(key.getPrivateKey(), this.getSigAlgName());
        return new Certificate(newCert);
    }

    /**
     * @return - signature algorithm used
     */
    public String getSigAlgName(){
        return this.certificate.getSigAlgName();
    }

    /**
     * encrypt given blocks of data with the certficate's public key
     * @param data - data to encrypt
     * @return - encypted data
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encryptOrDecrypt(data, true);
    }

    /**
     * decrypt given blocks of data with the certficate's public key
     * @param data - data to decrypt
     * @return - decrypted data
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] decrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        return encryptOrDecrypt(data, false);
    }

    /**
     * check if two certs are equal
     * @param cert - cert to check against
     * @return - true if certs are equal
     */
    public boolean equals(Certificate cert){
        return this.certificate.equals(cert.getX509Certificate());
    }

    //encrypts of decrypts data. Implements Electronic Code Book (ECB) to cipher large blocks of data
    private byte[] encryptOrDecrypt(byte[] data, boolean encrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        //init cipher for encrypt or decrypt
        int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        Cipher cipher = Cipher.getInstance(this.getPublicKey().getAlgorithm());
        cipher.init(mode, this.getPublicKey());

        //length of each block. if encrypting use (expected cipher block size - 20) length blocks to compensate RSA restrictions.
        int blockLength = encrypt ? cipher.getOutputSize(1) - 20 : cipher.getOutputSize(1);

        int offset = 0; //offset to read next block data from
        int totalBlocks = (int) Math.ceil((double)data.length / (double)blockLength); //calculate total blocks to encrypt
        byte[] temp = new byte[0]; //temp result holder
        for(int i = 0; i < totalBlocks - 1; i++){
            temp = concatenateByteArrays(temp,cipher.doFinal(data, offset, blockLength));
            offset = offset + blockLength;
        }

        //compute cipher for last block, concatenate with previous result, and return result
        //last block is done seperately as its length is not known and needs to be computed by subtracting offset from total length
        return concatenateByteArrays(temp, cipher.doFinal(data, offset, data.length - offset));
    }

    //concatenates to byte arrays and returns resulting array
    private byte[] concatenateByteArrays(byte[] org_array, byte[] new_array){
        byte[] output = new byte[org_array.length + new_array.length];
        System.arraycopy(org_array, 0, output, 0, org_array.length);
        System.arraycopy(new_array, 0, output, org_array.length, new_array.length);
        return output;
    }
}
