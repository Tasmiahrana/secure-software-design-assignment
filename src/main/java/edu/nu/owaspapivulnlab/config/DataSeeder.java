package edu.nu.owaspapivulnlab.config;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataSeeder implements CommandLineRunner {
    private final AppUserRepository userRepository;
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;

    public DataSeeder(AppUserRepository userRepository, AccountRepository accountRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.accountRepository = accountRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        // FIX: Check if users already exist to prevent UNIQUE constraint errors during tests
        if (userRepository.count() == 0) {
            // FIX: HASH passwords for seeded users
        // Create basic seeded users. Alice is a normal USER (not admin) to
        // match tests which expect alice to be a non-admin account.
        AppUser u1 = AppUser.builder()
            .username("alice")
            .password(passwordEncoder.encode("alice123"))
            .role("USER")
            .isAdmin(false)
            .build();
            AppUser u2 = AppUser.builder()
                    .username("bob")
                    .password(passwordEncoder.encode("bob234")) // <-- HASHED
                    .role("USER")
                    .isAdmin(false)
                    .build();
        userRepository.save(u1);
        userRepository.save(u2);

        // Create simple accounts for seeded users so tests can exercise ownership checks
        Account a1 = Account.builder()
            .ownerUserId(u1.getId())
            .iban("IBANALICE1")
            .balance(100.0)
            .build();

        Account a2 = Account.builder()
            .ownerUserId(u2.getId())
            .iban("IBANBOB2")
            .balance(200.0)
            .build();

        accountRepository.save(a1);
        accountRepository.save(a2);
        }
    }
}