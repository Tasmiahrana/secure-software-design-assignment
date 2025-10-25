package edu.nu.owaspapivulnlab.dto;

import edu.nu.owaspapivulnlab.model.AppUser;
import lombok.Data;

/**
 * DTO for AppUser (Task 4)
 * This "filters" the AppUser object, so we only send
 * safe fields to the client.
 */
@Data // Creates getters/setters
public class UserDTO {

    // 1. SAFE FIELDS TO INCLUDE
    private Long id;
    private String username;

    // We are hiding password, role, and isAdmin

    // 2. CONSTRUCTOR
    public UserDTO(Long id, String username) {
        this.id = id;
        this.username = username;
    }

    // 3. STATIC "MAPPER" METHOD
    // This easily converts a full AppUser into our safe DTO
    public static UserDTO fromEntity(AppUser user) {
        return new UserDTO(user.getId(), user.getUsername());
    }
}