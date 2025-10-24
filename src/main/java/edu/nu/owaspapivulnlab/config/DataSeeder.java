package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

// vvv ADD THIS IMPORT vvv
import org.springframework.security.crypto.password.PasswordEncoder;
// ^^^ ADD THIS IMPORT ^^^

@Configuration
public class DataSeeder {
    @Bean
    // vvv 1. ADD PasswordEncoder HERE vvv
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts, PasswordEncoder passwordEncoder) {
        return args -> {
            if (users.count() == 0) {
                
                // vvv 2. FIX THE PASSWORD FOR "alice" vvv
                AppUser u1 = users.save(AppUser.builder()
                        .username("alice")
                        .password(passwordEncoder.encode("alice123")) // <-- FIX
                        .email("alice@cydea.tech")
                        .role("USER")
                        .isAdmin(false)
                        .build());

                // vvv 3. FIX THE PASSWORD FOR "bob" vvv
                AppUser u2 = users.save(AppUser.builder()
                        .username("bob")
                        .password(passwordEncoder.encode("bob123")) // <-- FIX
                        .email("bob@cydea.tech")
                        .role("ADMIN")
                        .isAdmin(true)
                        .build());
                
                accounts.save(Account.builder().ownerUserId(u1.getId()).iban("PK00-ALICE").balance(1000.0).build());
                accounts.save(Account.builder().ownerUserId(u2.getId()).iban("PK00-BOB").balance(5000.0).build());
            }
        };
    }
}