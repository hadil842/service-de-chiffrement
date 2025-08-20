package com.example.demo.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@ConfigurationProperties(prefix ="us")
public class userlogin {
    @Value("${us.name}")
    private String name;
    @Value("${us.password}")
    private String password;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public boolean authenticate(String username, String rawPassword){
        if (name.equals(username) && passwordEncoder.matches(rawPassword, password)) {
            return true;
        } else {
            if (!name.equals(username)) {
                System.out.println("error: username does not match.");
            }
            if (!passwordEncoder.matches(rawPassword, password)) {
                System.out.println("error: password does not match.");
            }
            return false;
        }
    }
}