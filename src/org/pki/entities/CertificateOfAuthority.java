package org.pki.entities;

import org.pki.util.Certificate;
import org.pki.util.Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;

import java.io.IOException;
import java.security.cert.X509Certificate;

public class CertificateOfAuthority implements Runnable{

    private final Certificate certificate = null;
    @Override
    public void run() {
        if(certificate == null){

        }
    }

    public Certificate signPublicKey(X509Certificate certificateToSign) throws Exception{
        Certificate caCertificate = null; //load ca certificate
        Key caKey = null; //load ca key

        X509CertImpl cert = X509CertImpl.toImpl(certificateToSign);
        cert.sign(caKey.getPrivateKey(), cert.getSigAlgName());
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
