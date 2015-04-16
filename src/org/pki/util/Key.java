package org.pki.util;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

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

        System.out.println(key);

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

    public byte[] sign(byte[] data){
        return null;
    }

}
