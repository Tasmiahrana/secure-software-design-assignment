package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    // FIXED CODE
    @Value("${app.jwt.ttl_ms}")
    private long ttl;

    // VULNERABILITY(API8): HS256 with trivial key, long TTL, missing issuer/audience
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setIssuedAt(new Date(now))
                // FIXED CODE
                .setExpiration(new Date(now + ttl))
                .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                .compact();
    }
}
