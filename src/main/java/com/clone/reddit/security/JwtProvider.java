package com.clone.reddit.security;

import com.clone.reddit.exception.SpringRedditException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import static io.jsonwebtoken.Jwts.parser;
import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.IOException;
import java.security.*;
import java.security.KeyStore;
import java.security.cert.CertificateException;


@Service
public class JwtProvider {

   // private KeyStore keyStore;
   private Key key;

    @PostConstruct
    public void init() {

        try {
            key= Keys.secretKeyFor(SignatureAlgorithm.HS512);
        } catch (Exception e) {
            throw new SpringRedditException("Exception occurred while loading keystore");
        }
    }
   /* @PostConstruct
    public void init() {
        try {
            keyStore = KeyStore.getInstance("JKS");
            InputStream resourceAsStream = getClass().getResourceAsStream("/springblog.jks");
            keyStore.load(resourceAsStream, "secret".toCharArray());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new SpringRedditException("Exception occurred while loading keystore");
        }

    } */

    public String generateToken(Authentication authentication) {
        User principal = (User) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject(principal.getUsername())
               // .setIssuedAt(from(Instant.now()))
                .signWith(key)
               // .setExpiration(Date.from(Instant.now().plusMillis(jwtExpirationInMillis)))
                .compact();
    }
  /*  private PrivateKey getPrivateKey() {
        try {
            return (PrivateKey) keyStore.getKey("springblog", "secret".toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new SpringRedditException("Exception occured while retrieving public key from keystore");
        }
    } */
      public boolean validateToken(String jwt){
          parser().setSigningKey(key).parseClaimsJws(jwt);
          return true;
      }
/*
    public boolean validateToken(String jwt) {
        parser().setSigningKey(getPublickey()).parseClaimsJws(jwt);
        return true;
    }

    private PublicKey getPublickey() {
        try {
            return keyStore.getCertificate("springblog").getPublicKey();
        } catch (KeyStoreException e) {
            throw new SpringRedditException("Exception occured while retrieving public key from keystore");
        }
    }

    public String getUsernameFromJWT(String token) {
        Claims claims = parser()
                .setSigningKey(getPublickey())
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }*/
    public String getUsernameFromJWT(String token) {

        Claims claims = Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();

    }
}
