package com.example.apiBook.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RegisterResponse {
    private Long id;
    private String email;
    private String username;
    private String fullName;
    private String firstName;
    private String lastName;
    private String role;
    private String avatarUrl;
    private Boolean status;
}
