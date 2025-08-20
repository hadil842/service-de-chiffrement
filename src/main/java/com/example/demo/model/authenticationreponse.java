package com.example.demo.model;

public class authenticationreponse {
    private String publickey;
    private String secretkey;
    private String jwt;
    public authenticationreponse(String p,String s,String j){this.publickey=p;this.secretkey=s;this.jwt=j;}
    public String getpubkey() { return publickey; }
    public void setpubkey(String ch) { this.publickey=ch; }
    public String getjwt() { return jwt; }
    public void setjwt(String ch) { this.jwt=ch; }
     public String getstmkey() { return secretkey; }
    public void setsymkey(String ch) { this.secretkey=ch; }
}
