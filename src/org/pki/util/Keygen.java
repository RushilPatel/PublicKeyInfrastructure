package org.pki.util;

import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

/**
 * Generate Self signed certificate and key
 */
public class Keygen {
    private Certificate certificate = null;
    private Key key;
    public static final int KEY_SIZE_DEFAULT = 2048;
    public static final String KEY_ALGORITHM_DEFAULT = "RSA";
    public static final String SIG_ALGORITHM_DEFAULT = "SHA1WithRSA";
    public static final int VALIDITY_DEFAULT = (60 * 60 * 24) * 365 ;

    /**
     * @param x500Name - cert owner information
     * @param keyAlgorithm - algorithm to use
     * @param signatureAlgorithm - signature algorithm to use
     * @param keySize - key size to use
     * @param validity - validity of certificate
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws SignatureException
     */
    public Keygen( X500Name x500Name,String keyAlgorithm, String signatureAlgorithm, int keySize, int validity) throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, NoSuchProviderException, SignatureException{
        generateSelfSignedCertificate(x500Name, keyAlgorithm, signatureAlgorithm, keySize, validity);
    }

    /**
     * @param x500Name - certificate owner information
     */
    public Keygen(X500Name x500Name){
        try{
            generateSelfSignedCertificate(x500Name, KEY_ALGORITHM_DEFAULT, SIG_ALGORITHM_DEFAULT, KEY_SIZE_DEFAULT, VALIDITY_DEFAULT);
        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    /**
     * @param x500Name - cert owner information
     * @param keyAlgorithm - algorithm to use
     * @param signatureAlgorithm - signature algorithm to use
     * @param keySize - key size to use
     * @param validity - validity of certificate
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws SignatureException
     */
    private void generateSelfSignedCertificate(X500Name x500Name,String keyAlgorithm, String signatureAlgorithm, int keySize, int validity) throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, NoSuchProviderException, SignatureException{
        CertAndKeyGen keypair = new CertAndKeyGen(keyAlgorithm, signatureAlgorithm);
        keypair.generate(keySize);
        key = new Key(keypair.getPrivateKey());
        certificate = new Certificate(keypair.getSelfCertificate(x500Name, validity));
    }

    /**
     * Generate a default x500Name
     * @param commonName - common name to use
     * @return - x500Name information
     * @throws IOException
     */
    public static X500Name generateX500Name(String commonName) throws IOException {
        String organizationalUnit = "CS";
        String organization = "FIT";
        String city = "Melbourne";
        String state = "FL";
        String country = "US";
        return new X500Name(commonName, organizationalUnit, organization, city, state, country);
    }

    /**
     * @return - generated key
     */
    public Key getKey(){
        return this.key;
    }

    /**
     * @return - generated certificate
     */
    public Certificate getCertificate(){
        return this.certificate;
    }

}
