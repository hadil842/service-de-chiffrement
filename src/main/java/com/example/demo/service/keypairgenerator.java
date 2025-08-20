package com.example.demo.service;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
@Service
public class keypairgenerator {
       private  PrivateKey privatekey;
       private  PublicKey publickey;
       private SecretKey secretkey;
       @Value("${cl.public-key}")
       private String clpubkey;
       private keypairgenerator(){};
       @PostConstruct
       void keyinit() throws NoSuchAlgorithmException { 
          KeyPairGenerator keyGen;
          keyGen = KeyPairGenerator.getInstance("RSA");
          keyGen.initialize(2048);
          KeyPair keypair = keyGen.generateKeyPair();
          this.publickey=keypair.getPublic();
          this.privatekey=keypair.getPrivate();
          KeyGenerator keygen;
          keygen = KeyGenerator.getInstance("AES");
          keygen.init(128);
          SecretKey cle = keygen.generateKey();
          this.secretkey=cle;
  }
   public  PublicKey getpublic(){
        return publickey;
    }
    //prepare server public key 
    public String getpublicbase64(){
          byte[] code = this.publickey.getEncoded();
          String encodedKey= Base64.getEncoder().encodeToString(code);
          return encodedKey;
    }
    //prepare server secret key 
    public String getsecretbase64()throws NoSuchAlgorithmException,InvalidKeySpecException,NoSuchPaddingException,InvalidKeyException,BadPaddingException,IllegalBlockSizeException{
        byte[] keyBytes = Base64.getDecoder().decode(clpubkey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(secretkey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }
    //decryption client msg
    public void decryptdata(String data) throws  NoSuchAlgorithmException,InvalidKeySpecException,NoSuchPaddingException,InvalidKeyException,BadPaddingException,IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException{
        JSONObject jdata=new JSONObject(data);
        try{
        byte[]iv=Base64.getDecoder().decode(jdata.getString("iv"));
        byte[]encrypteddata=Base64.getDecoder().decode(jdata.getString("ciphertext"));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretkey, spec);
        byte[] decryptdata= cipher.doFinal(encrypteddata);
        System.out.println(new String(decryptdata));
    }catch(Exception e){
        System.out.println("An error ");
        e.printStackTrace();
        }
}}
