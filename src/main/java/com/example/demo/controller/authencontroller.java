package com.example.demo.controller;




import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.authenticationRequest;
import com.example.demo.model.authenticationreponse;
import com.example.demo.model.jwt;
import com.example.demo.service.keypairgenerator;
import com.example.demo.service.userlogin;

import jakarta.servlet.http.HttpServletResponse;
@RestController
@CrossOrigin(origins = {"http://localhost:5500", "null", "http://localhost:8080"})
public class authencontroller {
     private userlogin user;
     private final jwt jwtutil;
     private final keypairgenerator keypair;
     public authencontroller(jwt jwtutil,keypairgenerator keypair,userlogin user){
        this.jwtutil=jwtutil;
        this.keypair=keypair;
        this.user=user;
     }
    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody authenticationRequest authenticationRequest,HttpServletResponse response) throws Exception {
        if(user.authenticate(authenticationRequest.getUsername(),authenticationRequest.getPassword())){
        final String jwt = jwtutil.createToken(authenticationRequest.getUsername());
        String pubkey=keypair.getpublicbase64();
        String secrekey=keypair.getsecretbase64();
        return ResponseEntity.ok(new authenticationreponse(pubkey,secrekey,jwt));
        }else {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");}
}
   @PostMapping("/send-data")
   public void senddata(@RequestBody String object) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
      keypair.decryptdata(object);
   }
   
    
    
}


