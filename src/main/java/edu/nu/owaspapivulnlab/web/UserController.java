package edu.nu.owaspapivulnlab.web;

import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.security.core.Authentication;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    // FIXED CODE
    @GetMapping("/{userId}")
    public ResponseEntity<AppUser> getUserById(@PathVariable("userId") Long userId, Authentication auth) {

        // Find the user who is logged in
        AppUser loggedInUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        // Find the user they are trying to access
        AppUser requestedUser = users.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        // FIX (API1: BOLA): Enforce ownership or admin role
        if (loggedInUser.getId().equals(requestedUser.getId()) || loggedInUser.isAdmin()) {
            return ResponseEntity.ok(requestedUser); // OK: User is admin OR is requesting their own info
        }

        // If not, deny access explicitly with a 403 response
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    // VULNERABILITY(API6: Mass Assignment) - binds role/isAdmin from client
    @PostMapping
    public AppUser create(@Valid @RequestBody AppUser body) {
        return users.save(body);
    }

    // VULNERABILITY(API9: Improper Inventory + API8 Injection style): naive 'search' that can be abused for enumeration
    @GetMapping("/search")
    public List<AppUser> search(@RequestParam String q) {
        return users.search(q);
    }

    // VULNERABILITY(API3: Excessive Data Exposure) - returns all users including sensitive fields
    @GetMapping
    public List<AppUser> list() {
        return users.findAll();
    }

    // VULNERABILITY(API5: Broken Function Level Authorization) - allows regular users to delete anyone
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable("id") Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
