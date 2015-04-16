package org.pki.util;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;

public class Key {

    private PrivateKey privateKey;

    public Key(File file) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line = reader.readLine();
        while (line != null){
            sb.append(line);
            line = reader.readLine();
        }
        reader.close();

        String key = sb.toString();
        key = key.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        key = key.replace("-----BEGIN PRIVATE KEY-----", "");
        key = key.replace("-----END RSA PRIVATE KEY-----", "");
        key = key.replace("-----END PRIVATE KEY-----", "");

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(key));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(keySpec);
    }

    private Key(String key) throws NoSuchAlgorithmException, InvalidKeySpecException{
        this(key.getBytes());
    }

    private Key(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException{
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(keySpec);
    }

    public Key(PrivateKey privateKey){
        this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey(){
        return this.privateKey;
    }

    public boolean outputKeyToDirectory(File file)throws IOException{
        //output encoded key file to the directory in .key format
        if(file.exists()){
            System.out.println("Overwriting existing file");
            file.delete();
        }
        byte dataToWrite[] = this.privateKey.getEncoded();
        FileOutputStream out = new FileOutputStream(file.getPath());
        out.write(dataToWrite);
        out.close();
        return true;
    }

    public byte[] encrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        return encryptOrDecrypt(data, true);
    }

    public byte[] decrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        return encryptOrDecrypt(data, false);
    }

    private byte[] encryptOrDecrypt(byte[] data, boolean encrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        Cipher cipher = Cipher.getInstance(this.getPrivateKey().getAlgorithm());
        cipher.init(mode, this.getPrivateKey());

        // toReturn will hold the total result
        byte[] output = new byte[0];
        int blockLength = encrypt ? cipher.getOutputSize(1) - 20 : cipher.getOutputSize(1);

        int offset = 0;
        int totalBlocks = (int) Math.ceil((double)data.length / (double)blockLength);
        for(int i = 0; i < totalBlocks - 1; i++){
            output = concatenateByteArrays(output,cipher.doFinal(data, offset, blockLength));
            offset = offset + blockLength;
        }
        return concatenateByteArrays(output, cipher.doFinal(data, offset, data.length - offset));
    }

    private byte[] concatenateByteArrays(byte[] org_array, byte[] new_array){
        byte[] output = new byte[org_array.length + new_array.length];
        System.arraycopy(org_array, 0, output, 0, org_array.length);
        System.arraycopy(new_array, 0, output, org_array.length, new_array.length);
        return output;
    }
}
