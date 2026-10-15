package example.toolshed.store;

import com.fasterxml.jackson.annotation.JsonIgnore;

public record Member(long id, String email, String fullName,
                     @JsonIgnore String password, String role) {
}
