package org.pki.util;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Key {

    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_DSA = "DSA";

    private PrivateKey privateKey;

    public Key(File file, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
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
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        this.privateKey =  kf.generatePrivate(keySpec);
    }

    private Key(byte[] key, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException{
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        this.privateKey = kf.generatePrivate(keySpec);
    }

    public byte[] getEncoded(){
        return this.privateKey.getEncoded();
    }

    public Key(PrivateKey privateKey){
        this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey(){
        return this.privateKey;
    }

    public void outputKeyToFile(File file) throws IOException{
        if(file.exists()){
            System.out.println("Overwriting existing file");
            file.delete();
        }
        file.createNewFile();
        BufferedWriter out = new BufferedWriter(new FileWriter(file));
        BASE64Encoder encoder = new BASE64Encoder();
        out.write("-----BEGIN PRIVATE KEY-----");
        out.newLine();
        out.write(encoder.encode(this.privateKey.getEncoded()));
        out.newLine();
        out.write("-----END PRIVATE KEY-----");
        out.close();
    }

    public byte[] encrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        return encryptOrDecrypt(data, true);
    }

    public byte[] decrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        return encryptOrDecrypt(data, false);
    }

    public boolean equals(Key key){
        return this.privateKey.equals(key.getPrivateKey());
    }

    private byte[] encryptOrDecrypt(byte[] data, boolean encrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        Cipher cipher = Cipher.getInstance(this.getPrivateKey().getAlgorithm());
        cipher.init(mode, this.getPrivateKey());

        byte[] temp = new byte[0]; //temp result holder
        int blockLength = encrypt ? cipher.getOutputSize(1) - 20 : cipher.getOutputSize(1);

        int offset = 0;
        int totalBlocks = (int) Math.ceil((double) data.length / (double)blockLength);
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
