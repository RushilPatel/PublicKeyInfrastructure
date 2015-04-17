package org.pki.util;

import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Keygen {
    private Certificate certificate = null;
    private Key key;
    public static final int DEFAULT_KEY_SIZE = 2048;
    public static final String DEFAULT_KEY_ALGORITHM = "RSA";
    public static final String DEFAULT_SIG_ALGORITHM = "SHA1WithRSA";
    public static final int DEFAULT_VALIDITY = (60 * 60 * 24) * 365 ;

    public Keygen( X500Name x500Name,String keyAlgorithm, String signatureAlgorithm, int keySize, int validity) throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, NoSuchProviderException, SignatureException{
        generateSelfSignedCertificate(x500Name, keyAlgorithm, signatureAlgorithm, keySize, validity);
    }


    public Keygen(X500Name x500Named){
        try{
            generateSelfSignedCertificate(x500Named, DEFAULT_KEY_ALGORITHM, DEFAULT_SIG_ALGORITHM, DEFAULT_KEY_SIZE, DEFAULT_VALIDITY);
        }catch (Exception e){
            throw new RuntimeException(e);
        }

//        CertAndKeyGen unsignedKey = generateKeyPair();
//        if(x500Named.equals(CertificateOfAuthority.getX500Name())){
//            System.out.println("I am the CA, self signing");
//            certificate = new Certificate(unsignedKey.getSelfCertificate(x500Named, 1096));
//        }else{
//            int signAttempts = 0;
//            while(certificate == null && signAttempts < 10) {
//                signAttempts++;
//                Thread.sleep(1000);
//                System.out.println("Requesting CA to sign my key. " + signAttempts);
//                certificate = getSignedCertificate(unsignedKey.getSelfCertificate(x500Named, 1096), key, caSocket);
//            }
//            if(certificate == null){
//                throw new Exception("Unable to sign Certificate");
//            }
//        }
    }

    private void generateSelfSignedCertificate(X500Name x500Name,String keyAlgorithm, String signatureAlgorithm, int keySize, int validity) throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, NoSuchProviderException, SignatureException{
        CertAndKeyGen keypair = new CertAndKeyGen(keyAlgorithm, signatureAlgorithm);
        keypair.generate(keySize);
        key = new Key(keypair.getPrivateKey());
        certificate = new Certificate(keypair.getSelfCertificate(x500Name, validity));
    }

    public static X500Name generateX500Name(String commonName) throws IOException {
        String organizationalUnit = "CS";
        String organization = "FIT";
        String city = "Melbourne";
        String state = "FL";
        String country = "US";
        return new X500Name(commonName, organizationalUnit, organization, city, state, country);
    }

    public Key getKey(){
        return this.key;
    }

    public Certificate getCertificate(){
        return this.certificate;
    }

}
