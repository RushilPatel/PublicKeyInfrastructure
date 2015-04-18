package org.pki.util;

import org.pki.dto.SocketMessage;

import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.util.HashMap;

/**
 * Created by ttoggweiler on 4/17/15.
 */
public class EntityUtil {

    /**
     * static method to make encrypting messages easy
     * @param cert cert receivers cert to sign data with
     * @param key my key to prove I sent it
     * @param data data to send
     * @return encrypted bytes of data
     * @throws Exception lazyness knows no bounds
     */
    public static byte[] encryptMessage(Certificate cert, Key key,byte[] data) throws Exception{
        return cert.encrypt(key.encrypt(data));
    }

    /**
     * static method to make decrypting easy
     * @param cert cert to prove who it came from
     * @param key key to decrypt the data
     * @param data data that is to be decrypted
     * @return decrypted data
     * @throws Exception lazy
     */
    public static byte [] decryptMessage(Certificate cert, Key key, byte[] data) throws Exception{
        return cert.decrypt(key.decrypt(data));

    }

    /**
     * static method to help with validation of certs
     * @param certificateStore the cert store for cert chains
     * @param certificate the cert to verify
     * @throws Exception lazy
     */
    public static void validateCertificate(HashMap<Principal, Certificate> certificateStore, Certificate certificate) throws Exception{
        if(certificate.hasExpired()){
            throw new CertificateException("Certificate has expired!");
        }else if(certificate.isSelfSigned()){
            throw new CertificateException("Certificate is self signed!");
        }else{
            validateCertificateSignature(certificateStore, certificate);
        }
    }

    /**
     * check with CA if valid signature
     * @param certificateStore trusted certs
     * @param certificate cert to verify
     * @throws Exception lazy
     */
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

    /**
     * static method to get certs signed with a CA
     * @param socket socket to talk to CA with
     * @param mySocketMessage  message to send
     * @return the signed cert message
     * @throws IOException lazy
     */
    public static SocketMessage getCertificateSigned(Socket socket, SocketMessage mySocketMessage) throws IOException{
        SocketIOStream socketIOStream = new SocketIOStream(socket.getInputStream(), socket.getOutputStream());
        socketIOStream.sendMessage(mySocketMessage);
        return socketIOStream.readMessage();
    }
}
