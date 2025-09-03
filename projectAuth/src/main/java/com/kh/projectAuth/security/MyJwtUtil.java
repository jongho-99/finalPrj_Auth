package com.kh.projectAuth.security;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;

@Component
public class MyJwtUtil {

    @Value("${kh.jwt.secretKey}") private String str;

    private final SecretKey secretKey;

    public MyJwtUtil(@Value("${kh.jwt.secretKey}") String str) {

        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        String algo = Jwts.SIG.HS256.key().build().getAlgorithm();
        this.secretKey = new SecretKeySpec(bytes, algo);
    }

    //JWT 생성
    public String createJwt(String userId, String userNick, String userRole) {

        return Jwts.builder()
                .subject(userId)
                .claim("userNick", userNick)
                .claim("userRole", userRole)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000*60*15))
                .signWith(secretKey)
                .compact();
    }

    public String getUserId(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getSubject();
    }
    public String getUserNick(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("userNick", String.class);
    }
    public String getUserRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("userRole", String.class);
    }
    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }
}
