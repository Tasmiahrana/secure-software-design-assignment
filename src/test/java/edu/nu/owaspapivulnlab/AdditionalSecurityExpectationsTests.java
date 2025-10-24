package edu.nu.owaspapivulnlab; // Make sure this package name matches your other files

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional // This annotation rolls back database changes after each test
public class AdditionalSecurityExpectationsTests {

    @Autowired
    private MockMvc mockMvc; // Lets us send fake HTTP requests

    @Autowired
    private AppUserRepository appUserRepository; // Lets us check the database

    @Autowired
    private PasswordEncoder passwordEncoder; // Lets us check the hash

    @Autowired
    private ObjectMapper objectMapper; // Lets us create JSON strings

    /**
     * Test for Task 1: Password Security
     * This test verifies that:
     * 1. A new user's password is NOT stored in plaintext.
     * 2. The stored hash is a valid BCrypt hash.
     * 3. A user can log in with the correct password.
     * 4. A user cannot log in with an incorrect password.
     */
    @Test
    public void testTask1_PasswordSecurity_BCryptImplementation() throws Exception {
        // 1. ARRANGE: Create a new user login request
        Map<String, String> signupRequest = Map.of(
                "username", "testuser",
                "password", "MyS3cur3P@ss!"
        );
        String jsonRequest = objectMapper.writeValueAsString(signupRequest);

        // 2. ACT: Call the /signup endpoint
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isCreated()); // Expect 201 Created

        // 3. ASSERT (Database Check): Verify the password is hashed in the DB
        AppUser savedUser = appUserRepository.findByUsername("testuser")
                .orElseThrow(() -> new AssertionError("User 'testuser' not found in database"));

        String storedPasswordHash = savedUser.getPassword();

        // Check 1: The password in the DB is NOT the plaintext password
        assertNotEquals("MyS3cur3P@ss!", storedPasswordHash);

        // Check 2: The password in the DB IS a valid BCrypt hash
        assertTrue(storedPasswordHash.startsWith("$2a$"), "Password does not appear to be a BCrypt hash");
        
        // Check 3: The plaintext password MATCHES the hash
        assertTrue(passwordEncoder.matches("MyS3cur3P@ss!", storedPasswordHash), "Password encoder could not match password");

        // 4. ACT & ASSERT (Login Success): Try to log in with the CORRECT password
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isOk()) // Expect 200 OK
                .andExpect(jsonPath("$.token").exists()); // Expect a token to be returned

        // 5. ACT & ASSERT (Login Failure): Try to log in with the WRONG password
        Map<String, String> badLoginRequest = Map.of(
                "username", "testuser",
                "password", "WRONG_PASSWORD"
        );
        String badJsonRequest = objectMapper.writeValueAsString(badLoginRequest);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(badJsonRequest))
                .andExpect(status().isUnauthorized()); // Expect 401 Unauthorized
    }

    // You will add your other tests for other fixes below this line
    // @Test
    // public void testTask2_AccessControl_...() throws Exception { ... }
}