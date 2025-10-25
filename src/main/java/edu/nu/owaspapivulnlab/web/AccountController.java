package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

// vvv ADD THESE IMPORTS vvv
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import java.security.Principal;
// ^^^ END OF IMPORTS ^^^

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    // This constructor is already correct.
    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // vvv THIS METHOD IS NOW FIXED vvv
    @GetMapping("/{id}/balance")
    public Double balance(@PathVariable Long id, Principal principal) {
        // Find who is logged in
        AppUser loggedInUser = users.findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        
        // Find the account they want to see
        Account a = accounts.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"));

        // FIX (API1: BOLA): Enforce ownership or admin role
        if (a.getAppUser().getId().equals(loggedInUser.getId()) || loggedInUser.isAdmin()) {
            return a.getBalance(); // OK
        }
        
        // If not the owner or admin, deny access
        throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }
    // ^^^ END OF FIXED METHOD ^^^


    // vvv THIS METHOD IS NOW FIXED vvv
    // VULNERABILITY(API4: Unrestricted Resource Consumption) - still vulnerable, fixed in a later task
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Principal principal) {
        
        // Find who is logged in
        AppUser loggedInUser = users.findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        // Find the account they want to use
        Account a = accounts.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"));

        // FIX (API1/API5: BOLA): Enforce ownership or admin role
        if (!a.getAppUser().getId().equals(loggedInUser.getId()) && !loggedInUser.isAdmin()) {
            // Deny access if NOT the owner and NOT an admin
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }

        // --- Ownership check passed, proceed with transfer ---
        
        // (This is still vulnerable to API4/API9, but the BOLA/IDOR is fixed)
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", a.getBalance());
        return ResponseEntity.ok(response);
    }
    // ^^^ END OF FIXED METHOD ^^^


    // Safe-ish helper to view my accounts (still leaks more than needed - Task 4)
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}