package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.dto.UserDTO; // This import is correct

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
import java.util.stream.Collectors; // <-- ADD THIS IMPORT

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    // vvv FIX (API3): Changed return type to ResponseEntity<UserDTO> vvv
    @GetMapping("/{userId}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable("userId") Long userId, Authentication auth) {

        // Find the user who is logged in
        AppUser loggedInUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        // Find the user they are trying to access
        AppUser requestedUser = users.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        // FIX (API1: BOLA): Enforce ownership or admin role
        if (loggedInUser.getId().equals(requestedUser.getId()) || loggedInUser.isAdmin()) {
            
            // vvv FIX (API3): Return the safe DTO, not the full entity vvv
            return ResponseEntity.ok(UserDTO.fromEntity(requestedUser)); // OK: User is admin OR is requesting their own info
        }

        // If not, deny access explicitly with a 403 response
        return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }

    // vvv FIX (API3): Changed return type to UserDTO vvv
    // VULNERABILITY(API6: Mass Assignment) - still vulnerable, but exposure is fixed
    @PostMapping
    public UserDTO create(@Valid @RequestBody AppUser body) {
        AppUser savedUser = users.save(body);
        // vvv FIX (API3): Return the safe DTO, not the full entity vvv
        return UserDTO.fromEntity(savedUser);
    }

    // vvv FIX (API3): Changed return type to List<UserDTO> vvv
    // VULNERABILITY(API9: Improper Inventory + API8 Injection style): still vulnerable
    @GetMapping("/search")
    public List<UserDTO> search(@RequestParam String q) {
        // vvv FIX (API3): Map results to the safe DTO vvv
        return users.search(q).stream()
                .map(UserDTO::fromEntity)
                .collect(Collectors.toList());
    }

    // vvv FIX (API3): Changed return type to List<UserDTO> vvv
    @GetMapping
    public List<UserDTO> list() {
        // vvv FIX (API3): Map results to the safe DTO vvv
        return users.findAll().stream()
                .map(UserDTO::fromEntity)
                .collect(Collectors.toList());
    }

    // This endpoint is fine, no changes needed for Task 4
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable("id") Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}