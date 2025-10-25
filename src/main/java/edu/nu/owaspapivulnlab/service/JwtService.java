package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {
    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    // vvv These properties are loaded from application.properties vvv
    private final SecretKey secretKey;
    private final String issuer;
    private final String audience;
    private final long ttlMillis;

    public JwtService(
            @Value("${jwt.secret.key}") String secretString,
            @Value("${jwt.issuer}") String issuer,
            @Value("${jwt.audience}") String audience,
            @Value("${jwt.ttl.ms}") long ttlMillis) {

        // FIX: Decode the strong Base64 key into a secure key object
        byte[] decodedKey = Base64.getDecoder().decode(secretString);
        this.secretKey = Keys.hmacShaKeyFor(decodedKey); // Use HMAC-SHA
        
        this.issuer = issuer;
        this.audience = audience;
        this.ttlMillis = ttlMillis;
    }

    /**
     * Issues a new, secure JWT.
     */
    public String issue(String subject, Map<String, Object> claims) {
        log.info("Issuing token for {}", subject);
        
        // vvv FIX: Use the modern builder with .set* methods vvv
        return Jwts.builder()
                .setSubject(subject)
                .setClaims(claims)
                .setIssuer(this.issuer)
                .setAudience(this.audience)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + this.ttlMillis))
                .signWith(this.secretKey)
                .compact();
    }

    /**
     * Parses and strictly validates a JWT.
     */
    public Claims parse(String token) {
        log.info("Parsing token");
        
        // vvv FIX: Use the modern parserBuilder() vvv
        return Jwts.parserBuilder()
                .setSigningKey(this.secretKey)      // 1. Set the strong key
                .requireIssuer(this.issuer)         // 2. VALIDATE the issuer
                .requireAudience(this.audience)     // 3. VALIDATE the audience
                .build()
                .parseClaimsJws(token)              // 4. This validates signature AND expiry
                .getBody();
    }
}