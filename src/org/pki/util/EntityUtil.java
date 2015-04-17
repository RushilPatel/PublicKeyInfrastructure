package org.pki.util;

import org.pki.dto.SocketMessage;

import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.util.HashMap;

/**
 * Created by ttoggweiler on 4/17/15.
 */
public class EntityUtil {

    private byte[] encryptMessage(Certificate cert, Key key,byte[] data) throws Exception{
        return cert.encrypt(key.encrypt(data));
    }

    private byte [] decryptMessage(Certificate cert, Key key, byte[] data) throws Exception{
        return cert.decrypt(key.decrypt(data));

    }

    public static void validateCertificate(HashMap<Principal, Certificate> certificateStore, Certificate certificate) throws Exception{
        if(certificate.hasExpired()){
            throw new CertificateException("Cerificate has expired!");
        }else if(certificate.isSelfSigned()){
            throw new CertificateException("Certificate is self signed!");
        }else{
            validateCertificateSignature(certificateStore, certificate);
        }
    }

    private static void validateCertificateSignature(HashMap<Principal, Certificate> certificateStore, Certificate certificate) throws Exception{
        Certificate caCertificate = certificateStore.get(certificate.getIssuer());
        if(caCertificate == null){
            throw new CertificateException("Untrusted issuer: " + certificate.getIssuer());
        }else{
            if(!caCertificate.getIssuer().equals(caCertificate.getSubject())){
                validateCertificateSignature(certificateStore, caCertificate);
            }
            if(!certificate.isSignedBy(caCertificate)){
                throw new CertificateException(String.format("Certificate of Subject (%s) is not signed by its Issuer (%s)" , certificate.getSubject(), certificate.getIssuer()));
            }
        }
    }

    public static SocketMessage getCertificateSigned(Socket socket, SocketMessage mySocketMessage){
        return null; // todo
    }
}
