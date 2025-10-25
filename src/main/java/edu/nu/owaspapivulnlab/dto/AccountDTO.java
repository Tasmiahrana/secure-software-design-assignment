package edu.nu.owaspapivulnlab.dto;

import edu.nu.owaspapivulnlab.model.Account;
import lombok.Data;

/**
 * DTO for Account (Task 4)
 * This "filters" the Account object to only show safe fields.
 */
@Data
public class AccountDTO {

    // SAFE FIELDS TO INCLUDE
    private Long id;
    private String iban;
    private Double balance;
    // (We are hiding the internal ownerUserId)

    // CONSTRUCTOR
    public AccountDTO(Long id, String iban, Double balance) {
        this.id = id;
        this.iban = iban;
        this.balance = balance;
    }

    // "MAPPER" METHOD
    // Converts a full Account into our safe DTO
    public static AccountDTO fromEntity(Account account) {
        return new AccountDTO(account.getId(), account.getIban(), account.getBalance());
    }
}