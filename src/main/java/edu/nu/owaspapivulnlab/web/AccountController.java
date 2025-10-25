package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

// vvv ADD THESE IMPORTS FOR TASK 4 vvv
import edu.nu.owaspapivulnlab.dto.AccountDTO;
import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;
// ^^^ END OF IMPORTS ^^^

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    // This constructor is correct.
    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // vvv FIX (API3): Changed return type from Double to AccountDTO vvv
    @GetMapping("/{id}/balance")
    public AccountDTO balance(@PathVariable("id") Long id, Principal principal) { // <-- Changed return type
        // Find who is logged in
        AppUser loggedInUser = users.findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        // Find the account they want to see
        Account a = accounts.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"));

        // FIX (API1: BOLA): Enforce ownership or admin role
        if (a.getOwnerUserId().equals(loggedInUser.getId()) || loggedInUser.isAdmin())
        {
            // vvv FIX (API3): Return the safe DTO, not just the balance vvv
            return AccountDTO.fromEntity(a); // OK
        }

        // If not the owner or admin, deny access
        throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }
    // ^^^ END OF FIXED METHOD ^^^


    // vvv FIX (API3): Changed return type to ResponseEntity<AccountDTO> vvv
    @PostMapping("/{id}/transfer")
    public ResponseEntity<AccountDTO> transfer(@PathVariable("id") Long id, @RequestParam Double amount, Principal principal) { // <-- Changed return type

        // Find who is logged in
        AppUser loggedInUser = users.findByUsername(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        // Find the account they want to use
        Account a = accounts.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"));

        // FIX (API1/API5: BOLA): Enforce ownership or admin role
        if (!a.getOwnerUserId().equals(loggedInUser.getId()) && !loggedInUser.isAdmin())
        {
            // Deny access if NOT the owner and NOT an admin
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }

        // --- Ownership check passed, proceed with transfer ---
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);

        // vvv FIX (API3): Return the safe DTO, not the old Map vvv
        return ResponseEntity.ok(AccountDTO.fromEntity(a));
    }
    // ^^^ END OF FIXED METHOD ^^^


    // vvv FIX (API3): Changed return type from Object to List<AccountDTO> vvv
    @GetMapping("/mine")
    public List<AccountDTO> mine(Authentication auth) { // <-- Changed return type
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        
        if (me == null) {
            return Collections.emptyList();
        }

        // vvv FIX (API3): Map all accounts to the safe DTO vvv
        return accounts.findByOwnerUserId(me.getId()).stream()
                .map(AccountDTO::fromEntity)
                .collect(Collectors.toList());
    }
}