package edu.nu.owaspapivulnlab.dto; // <-- 1. SET THE PACKAGE

import jakarta.validation.constraints.NotBlank; // <-- 2. ADD THIS IMPORT

public class SignupRequest { // <-- 3. REMOVE "static"
    @NotBlank
    private String username;
    @NotBlank
    private String password;

    // ... the rest of the class is the same ...
    public SignupRequest() {}
    public SignupRequest(String username, String password) { this.username = username; this.password = password; }
    public String username() { return username; }
    public String password() { return password; }
    public void setUsername(String username) { this.username = username; }
    public void setPassword(String password) { this.password = password; }
}