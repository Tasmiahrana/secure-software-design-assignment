package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.dto.UserDTO; // This import is correct

import jakarta.validation.Valid; // <-- ADD THIS IMPORT
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus; // <-- ADD THIS IMPORT
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordEncoder passwordEncoder;

    // This constructor is correct
    public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.jwt = jwt;
        this.passwordEncoder = passwordEncoder;
    }

    // Renamed LoginReq to SignupRequest for clarity, added @Valid
    public static class SignupRequest {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        // Constructor, getters, setters are the same...
        public SignupRequest() {}
        public SignupRequest(String username, String password) { this.username = username; this.password = password; }
        public String username() { return username; }
        public String password() { return password; }
        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    // Login Request class (same as before)
    public static class LoginReq {
        @NotBlank private String username;
        @NotBlank private String password;
        public LoginReq() {}
        public LoginReq(String u, String p) { username = u; password = p; }
        public String username() { return username; }
        public String password() { return password; }
        public void setUsername(String u) { username = u; }
        public void setPassword(String p) { password = p; }
    }


    public static class TokenRes {
        private String token;
        public TokenRes() {}
        public TokenRes(String token) { this.token = token; }
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    // vvv FIX: Changed return type to ResponseEntity<UserDTO> vvv
    // vvv FIX: Added @Valid to enable validation vvv
    @PostMapping("/signup")
    public ResponseEntity<UserDTO> signup(@Valid @RequestBody SignupRequest request) { // <-- Changed parameter type
        if (users.findByUsername(request.username()).isPresent()) {
            // Consider returning a more structured error DTO later
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null); // Return null body or error DTO
        }

        AppUser newUser = AppUser.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .role("USER")
                .isAdmin(false) // Explicitly set isAdmin to false
                .build();

        AppUser saved = users.save(newUser);

        // vvv FIX (API3): Return the safe DTO, not the full entity vvv
        return new ResponseEntity<>(UserDTO.fromEntity(saved), HttpStatus.CREATED);
    }


    // Login method remains the same for Task 4
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        AppUser user = users.findByUsername(req.username()).orElse(null);

        if (user != null && passwordEncoder.matches(req.password(), user.getPassword())) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin());
            String token = jwt.issue(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }
        // Consider returning a structured error DTO here too
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null); // Return null body or error DTO
    }
}