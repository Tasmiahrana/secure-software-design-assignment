package edu.nu.owaspapivulnlab.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * A generic, safe DTO for returning error messages to the client.
 */
@Data
@AllArgsConstructor // This creates a constructor for us
public class ErrorDTO {
    private String error;
}