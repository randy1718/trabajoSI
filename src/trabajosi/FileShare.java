/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trabajosi;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Randy
 * @author Alvaro de León
 * @url https://www.alvarodeleon.net/encriptar-y-desencriptar-con-rsa-en-java/
 * La mayoria del codigo es proveniente de este url, y nosotros le hicimos modificaciones para adecuarlo a los criterios previstos.
 */
public class FileShare {

    public PrivateKey PrivateKey = null;
    public PublicKey PublicKey = null;

    public FileShare() {

    }

    /**
     *Metodo que convierte recibe la clave privada para convertirlo en formato bytes y asi mismo codificarla al formato X.509 Standard
     * @author Alvaro de León
     * @param key
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */

    public void setPrivateKeyString(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encodedPrivateKey = stringToBytes(key);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        this.PrivateKey = privateKey;
    }
    
    /**
     * Method que convierte recibe la clave publica para convertirlo en formato bytes y asi mismo codificarla al formato X.509 Standard
     * @author Alvaro de León
     * @param key
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */

    public void setPublicKeyString(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] encodedPublicKey = stringToBytes(key);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        this.PublicKey = publicKey;
    }
    
    /**
     * Method convierte el formato de llave privada a String
     * @author Alvaro de León
     * @return 
     */

    public String getPrivateKeyString() {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(this.PrivateKey.getEncoded());
        return bytesToString(pkcs8EncodedKeySpec.getEncoded());
    }

    /**
     * Method convierte el formato de llave publica a String
     * @author Alvaro de León
     * @return 
     */
    public String getPublicKeyString() {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(this.PublicKey.getEncoded());
        return bytesToString(x509EncodedKeySpec.getEncoded());
    }

    /**
     * Method que genera tanto la llave privada como la publica teniendo el cuenta el tamaño que recibe
     * @author Alvaro de León
     * @param size
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public void crearClaves(int size) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        KeyPair kp = kpg.genKeyPair();

        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        this.PrivateKey = privateKey;
        this.PublicKey = publicKey;
    }
  
    /**
     * Method que recibe la ruta del archivo que despues lee para convertirlo en string y asi cifrarlo con la llave publica
     * 
     * @param archivo
     * @return el cifrado
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws java.io.UnsupportedEncodingException
     * @throws java.security.NoSuchProviderException
     */
    public String cifrarArchivo(String archivo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, UnsupportedEncodingException, NoSuchProviderException, IOException {

        String plain=readFileAsString(archivo);
        
        byte[] encryptedBytes;

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.PublicKey);
        encryptedBytes = cipher.doFinal(plain.getBytes());

        return bytesToString(encryptedBytes);

    }

    /**
     * Method que descifra el archivo cifrado con la llave publica usnado la llave privada
     * 
     * @param archivo
     * @return el texto descifrado
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     * @throws java.io.IOException
     */
    public String descifrarArchivo(String archivo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {

        String result=readFileAsString(archivo);
        byte[] decryptedBytes;

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, this.PrivateKey);
        decryptedBytes = cipher.doFinal(stringToBytes(result));
        return new String(decryptedBytes);
    }

    /**
     * Method de conversion de bytes a String
     * @author Alvaro de León
     * @param b
     * @return 
     */
    public String bytesToString(byte[] b) {
        byte[] b2 = new byte[b.length + 1];
        b2[0] = 1;
        System.arraycopy(b, 0, b2, 1, b.length);
        return new BigInteger(b2).toString(36);
    }

    /**
     * Method de conversion de String a bytes
     * @author Alvaro de León
     * @param s
     * @return 
     */
    public byte[] stringToBytes(String s) {
        byte[] b2 = new BigInteger(s, 36).toByteArray();
        return Arrays.copyOfRange(b2, 1, b2.length);
    }
    
    /**
     * Method que guarda la clave privada generadas en el computador
     * @author Alvaro de León
     * @param path
     * @throws java.io.IOException
     */
    public void saveToDiskPrivateKey(String path) throws IOException {
        try {
            try (Writer out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(path), "UTF-8"))) {
                out.write(this.getPrivateKeyString());
            }
        } catch (IOException e) {
            // TODO: handle exception
        }
    }

    /**
     * Method que guarda la clave publica generadas en el computador
     * @author Alvaro de León
     * @param path
     */
    public void saveToDiskPublicKey(String path) {
        try {
            try (Writer out = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(path), "UTF-8"))) {
                out.write(this.getPublicKeyString());
            }
        } catch (IOException e) {
            // TODO: handle exception
        }
    }
    /**
     * Method que guarda el archivo cifrado con la clave publica en el disco
     * 
     * @param text
     * @param ruta
     * @throws java.io.IOException
     */
    public void saveCipherText(String text, String ruta) throws IOException {
     
            File file = new File(ruta);
            // Si el archivo no existe es creado
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter fw = new FileWriter(file);
        try (BufferedWriter bw = new BufferedWriter(fw)) {
            bw.write(text);
        }
    }
    
    /** 
     * Method que guarda el archivo descifrado con la clave privada en el disco
     * 
     * @param text
     * @param ruta
     * @throws java.io.IOException
     */
    public void saveDecipherText(String text, String ruta) throws IOException {
     
            
            File file = new File(ruta);
            // Si el archivo no existe es creado
            if (!file.exists()) {
                file.createNewFile();
            }
            FileWriter fw = new FileWriter(file);
        try (BufferedWriter bw = new BufferedWriter(fw)) {
            bw.write(text);
        }
    }
    
    /**
     * Method que busca la clave publica en el disco para ser usada
     * @author Alvaro de León
     * @param path
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public void openFromDiskPublicKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String content = this.readFileAsString(path);
        this.setPublicKeyString(content);
    }

    /**
     * Method que busca la clave privada en el disco para ser usada
     * @author Alvaro de León
     * @param path
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public void openFromDiskPrivateKey(String path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String content = this.readFileAsString(path);
        this.setPrivateKeyString(content);
    }
    
    /**
     * Method que lee los archivos para convertirlos en String
     * @author Alvaro de León
     */
    private String readFileAsString(String filePath) throws IOException {
        StringBuilder fileData = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new FileReader(filePath))) {
            char[] buf = new char[1024];
            int numRead = 0;
            while ((numRead = reader.read(buf)) != -1) {
                String readData = String.valueOf(buf, 0, numRead);
                fileData.append(readData);
            }
        }
        return fileData.toString();
    }

}
