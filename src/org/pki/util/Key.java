package org.pki.util;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import sun.misc.BASE64Encoder;
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

    /**
     * Read key from file
     * @param file - file to read key from
     * @param algorithm - key algorithm used
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public Key(File file, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
        StringBuilder sb = new StringBuilder();
        //read key
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line = reader.readLine();
        while (line != null){
            sb.append(line);
            line = reader.readLine();
        }
        reader.close();

        String key = sb.toString();

        //remove header and footer
        key = key.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        key = key.replace("-----BEGIN PRIVATE KEY-----", "");
        key = key.replace("-----END RSA PRIVATE KEY-----", "");
        key = key.replace("-----END PRIVATE KEY-----", "");

        //generate private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(key));
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        this.privateKey =  kf.generatePrivate(keySpec);
    }

    /**
     * Read key data from encoded byte array
     * @param key - key data
     * @param algorithm - algorithm used
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private Key(byte[] key, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException{
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        this.privateKey = kf.generatePrivate(keySpec);
    }

    /**
     * @return - encoded key data
     */
    public byte[] getEncoded(){
        return this.privateKey.getEncoded();
    }

    /**
     * Create key from PrivateKey object
     * @param privateKey - private key
     */
    public Key(PrivateKey privateKey){
        this.privateKey = privateKey;
    }

    /**
     * @return - private key
     */
    public PrivateKey getPrivateKey(){
        return this.privateKey;
    }

    /**
     * Store key to file
     * @param file - file to write key to
     * @throws IOException
     */
    public void outputKeyToFile(File file) throws IOException{
        if(file.exists()){
            System.out.println("Overwriting existing key file");
            file.delete();
        }
        //create parent directories
        file.getParentFile().mkdirs();
        file.createNewFile();
        BufferedWriter out = new BufferedWriter(new FileWriter(file));
        BASE64Encoder encoder = new BASE64Encoder(); //base 64 encode it
        out.write("-----BEGIN PRIVATE KEY-----"); //write header
        out.newLine(); //new line
        out.write(encoder.encode(this.privateKey.getEncoded())); //write key data
        out.newLine(); //new line
        out.write("-----END PRIVATE KEY-----"); // write footer
        out.close();
    }

    /**
     * Encrypts given data
     * @param data - data to encrypt
     * @return - encrypted data
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        return encryptOrDecrypt(data, true);
    }

    /**
     * Decrypts given data
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
     * compare with other key
     * @param key - key to compare with
     * @return
     */
    public boolean equals(Key key){
        return this.privateKey.equals(key.getPrivateKey());
    }

    //encrypts of decrypts data. Implements Electronic Code Book (ECB) to cipher large blocks of data
    private byte[] encryptOrDecrypt(byte[] data, boolean encrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException{
        //init cipher for encrypt or decrypt
        int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        Cipher cipher = Cipher.getInstance(this.getPrivateKey().getAlgorithm());
        cipher.init(mode, this.getPrivateKey());

        byte[] temp = new byte[0]; //temp result holder
        //length of each block. if encrypting use (expected cipher block size - 20) length blocks to compensate RSA restrictions.
        int blockLength = encrypt ? cipher.getOutputSize(1) - 20 : cipher.getOutputSize(1);

        int offset = 0; //offset to read next block data from
        int totalBlocks = (int) Math.ceil((double) data.length / (double)blockLength); //calculate total blocks to encrypt
        for(int i = 0; i < totalBlocks - 1; i++){
            temp = concatenateByteArrays(temp,cipher.doFinal(data, offset, blockLength));
            offset = offset + blockLength;
        }

        //compute cipher for last block, concatenate with previous result, and return result
        //last block is done seperately as its length is not known and needs to be computed by subtracting offset from total length
        return concatenateByteArrays(temp, cipher.doFinal(data, offset, data.length - offset));
    }

    private byte[] concatenateByteArrays(byte[] org_array, byte[] new_array){
        byte[] output = new byte[org_array.length + new_array.length];
        System.arraycopy(org_array, 0, output, 0, org_array.length);
        System.arraycopy(new_array, 0, output, org_array.length, new_array.length);
        return output;
    }
}
