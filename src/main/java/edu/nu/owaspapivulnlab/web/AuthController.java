package edu.nu.owaspapivulnlab.web;

import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;

// vvv ADD THIS IMPORT vvv
import org.springframework.security.crypto.password.PasswordEncoder;
// ^^^ ADD THIS IMPORT ^^^

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordEncoder passwordEncoder; // <-- 1. ADD THIS FIELD

    // 2. UPDATE THIS CONSTRUCTOR
    public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.jwt = jwt;
        this.passwordEncoder = passwordEncoder; // <-- ADD THIS LINE
    }

    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }
    
    // vvv 3. ADD THIS ENTIRE /signup METHOD vvv
    // This method was missing but is required for the assignment
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody LoginReq request) {
        if (users.findByUsername(request.username()).isPresent()) {
            return ResponseEntity.status(400).body("{\"error\": \"username already taken\"}");
        }

        // VULNERABILITY (Plaintext Password) - FIXED
        AppUser newUser = AppUser.builder()
                .username(request.username())
                // FIX: Hash the password using the encoder
                .password(passwordEncoder.encode(request.password()))
                .role("USER")
                .build();
        
        users.save(newUser);
        
        return ResponseEntity.status(201).body("{\"message\": \"user created\"}");
    }
    // ^^^ END OF NEW /signup METHOD ^^^

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        // VULNERABILITY(API2: Broken Authentication): plaintext password check
        AppUser user = users.findByUsername(req.username()).orElse(null);

        // vvv 4. UPDATE THIS IF-STATEMENT vvv
        
        // VULNERABLE CODE:
        // if (user != null && user.getPassword().equals(req.password())) {
        
        // FIXED CODE:
        // Use passwordEncoder.matches() to securely compare the hashes
        if (user != null && passwordEncoder.matches(req.password(), user.getPassword())) {
            // ^^^ END OF CHANGE ^^^
            
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin()); 
            String token = jwt.issue(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }
        Map<String, String> error = new HashMap<>();
        error.put("error", "invalid credentials");
        return ResponseEntity.status(401).body(error);
    }
}