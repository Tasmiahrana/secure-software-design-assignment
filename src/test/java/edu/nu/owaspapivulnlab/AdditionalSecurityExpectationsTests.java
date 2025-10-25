package edu.nu.owaspapivulnlab; // Make sure this package name matches your other files

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
    private AccountRepository accountRepository; // Lets us check accounts

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

        /**
         * Test for Task 2: Access Control
         * This test verifies that:
         * 1. Unauthenticated users can NO LONGER access /api/** endpoints.
         * 2. It specifically checks that /api/users is now protected.
         */
        @Test
        public void testTask2_AccessControl_BlocksUnauthenticatedAccess() throws Exception {
        // ACT & ASSERT
        // Try to access a protected API endpoint (GET /api/users)
        // without providing an Authorization token.
        mockMvc.perform(get("/api/users"))
                // FIXED TEST CODE
                // CORRECT CODE
                .andExpect(status().isForbidden()); // Expect 403 Forbidden
        }

                /**
         * Test for Task 3: BOLA/IDOR
         * This test verifies that a non-admin user ("alice"):
         * 1. CAN access her own user data.
         * 2. CANNOT access another user's ("bob") data.
         * 3. CAN access her own account balance.
         * 4. CANNOT access another user's ("bob") account balance.
         */
        @Test
        public void testTask3_BOLA_PreventsAccessToOtherUserData() throws Exception {
        // ARRANGE: Create a mock authenticated user "alice" (ID 1, Role USER)
        SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor alice =
                user("alice").password("alice123").roles("USER");

        // Ensure alice and bob exist in the database
        AppUser aliceUser = appUserRepository.findByUsername("alice")
                .orElseThrow(() -> new AssertionError("Alice not found"));
        AppUser bobUser = appUserRepository.findByUsername("bob")
                .orElseThrow(() -> new AssertionError("Bob not found"));

        // Ensure accounts exist
        Account aliceAccount = accountRepository.findByOwnerUserId(aliceUser.getId())
                .stream().findFirst()
                .orElseThrow(() -> new AssertionError("Alice's account not found"));
        Account bobAccount = accountRepository.findByOwnerUserId(bobUser.getId())
                .stream().findFirst()
                .orElseThrow(() -> new AssertionError("Bob's account not found"));

        // TEST 1: Alice CAN get her own user info (User ID 1)
        mockMvc.perform(get("/api/users/" + aliceUser.getId()).with(alice))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));

        // TEST 2: Alice CANNOT get Bob's user info (User ID 2)
        mockMvc.perform(get("/api/users/" + bobUser.getId()).with(alice))
                .andExpect(status().isForbidden()); // Expect 403 Forbidden

        // TEST 3: Alice CAN get her own account balance (Account ID 1)
        mockMvc.perform(get("/api/accounts/" + aliceAccount.getId() + "/balance").with(alice))
                .andExpect(status().isOk());

        // TEST 4: Alice CANNOT get Bob's account balance (Account ID 2)
        mockMvc.perform(get("/api/accounts/" + bobAccount.getId() + "/balance").with(alice))
                .andExpect(status().isForbidden()); // Expect 403 Forbidden
        }

                /**
         * Test for Task 4: Excessive Data Exposure
         * This test verifies that:
         * 1. The /api/users/{id} endpoint ONLY returns the UserDTO (no password/role).
         * 2. The /api/auth/signup endpoint ONLY returns the UserDTO (no password/role).
         * 3. The /api/accounts/{id}/balance endpoint ONLY returns the AccountDTO (no ownerUserId).
         */
        @Test
        public void testTask4_DataExposure_DTOsPreventSensitiveDataLeak() throws Exception {
        // ARRANGE: Create a mock authenticated user "alice"
        SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor alice =
                user("alice").password("alice123").roles("USER");

        // TEST 1: Check the /api/users/{id} endpoint
        mockMvc.perform(get("/api/users/1").with(alice))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"))
                // --- ASSERT SENSITIVE FIELDS DO NOT EXIST ---
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.role").doesNotExist())
                .andExpect(jsonPath("$.admin").doesNotExist());

        // TEST 2: Check the /api/auth/signup endpoint
        Map<String, String> signupRequest = Map.of(
                "username", "dto_test_user",
                "password", "MyS3cur3P@ss!"
        );
        String jsonRequest = objectMapper.writeValueAsString(signupRequest);

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("dto_test_user"))
                // --- ASSERT SENSITIVE FIELDS DO NOT EXIST ---
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.role").doesNotExist())
                .andExpect(jsonPath("$.admin").doesNotExist());

        // TEST 3: Check the /api/accounts/{id}/balance endpoint
        mockMvc.perform(get("/api/accounts/1/balance").with(alice))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.balance").value(100.0))
                // --- ASSERT SENSITIVE FIELD DOES NOT EXIST ---
                .andExpect(jsonPath("$.ownerUserId").doesNotExist());
        }

        /**
         * Test for Task 5: Rate Limiting (API4)
         * This test verifies that:
         * 1. A user can make a few login attempts.
         * 2. After 5 attempts, the 6th attempt is blocked with an HTTP 429 "Too Many Requests".
         * This test MUST run last, so we give it a lower priority.
         */
        @Test
        public void testTask5_RateLimiting_BlocksExcessiveLoginAttempts() throws Exception {
        // ARRANGE: Create a bad login request
        Map<String, String> badLoginRequest = Map.of(
                "username", "testuser",
                "password", "WRONG_PASSWORD"
        );
        String jsonRequest = objectMapper.writeValueAsString(badLoginRequest);

        // ACT: Attempt to log in 5 times (these should be allowed but fail auth)
        for (int i = 0; i < 5; i++) {
                mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(jsonRequest))
                        .andExpect(status().isUnauthorized()); // Expect 401 Unauthorized
        }

        // ASSERT: The 6th attempt should be blocked by the rate limiter
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isTooManyRequests()); // Expect 429 Too Many Requests
        }

        /**
         * Test for Task 6: Mass Assignment (API6)
         * This test verifies that:
         * 1. A hacker sends a JSON request with "isAdmin": true.
         * 2. The /api/users endpoint (the 'create' method) IGNORES this field.
         * 3. The new user is created as a regular "USER" and NOT an "ADMIN".
         */
        @Test
        public void testTask6_MassAssignment_PreventsAdminCreation() throws Exception {
        // ARRANGE: Create a malicious JSON request trying to set "isAdmin"
        String maliciousJson = """
                {
                        "username": "hacker",
                        "password": "hackerpassword123",
                        "isAdmin": true,
                        "role": "ADMIN"
                }
                """;

        // We also need an authenticated user to perform this action (e.g., alice)
        SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor alice =
                user("alice").password("alice123").roles("USER");

        // ACT: Call the 'create' endpoint (/api/users POST)
        mockMvc.perform(post("/api/users")
                        .with(alice) // <-- Need to be authenticated to create a user
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(maliciousJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("hacker"))
                .andExpect(jsonPath("$.password").doesNotExist()); // DTO check (Task 4)

        // ASSERT: Check the database to ensure the user is NOT an admin
        AppUser savedUser = appUserRepository.findByUsername("hacker")
                .orElseThrow(() -> new AssertionError("User 'hacker' not found in database"));

        assertFalse(savedUser.isAdmin(), "User was created as an ADMIN!");
        assertEquals("USER", savedUser.getRole(), "User role was not set to USER!");
        }

// You will add your test for Task 7 below this line...

     

    // You will add your other tests for other fixes below this line
    // @Test
    // public void testTask2_AccessControl_...() throws Exception { ... }
}