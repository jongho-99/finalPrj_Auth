package com.kh.projectAuth.security;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;

@Component
public class MyJwtUtil {

    @Value("${kh.jwt.secretKey}") private String secretKey;

    //JWT 생성
    public String createJwt(String userId, String userNick, String userRoleName, String userDepartmentName, LocalDateTime userCreatedAt) {
        byte[] bytes = secretKey.getBytes(StandardCharsets.UTF_8);
        String algo = Jwts.SIG.HS256.key().build().getAlgorithm();
        Key key = new SecretKeySpec(bytes, algo);

        return Jwts.builder()
                .subject(userId)
                .claim("userNick", userNick)
                .claim("userRoleName", userRoleName)
                .claim("userDepartmentName", userDepartmentName)
                .claim("userCreatedAt", userCreatedAt)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000*60*15))
                .signWith(key)
                .compact();
    }
}
