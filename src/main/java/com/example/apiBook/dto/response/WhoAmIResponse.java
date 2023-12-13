package com.example.apiBook.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class WhoAmIResponse {
    private Long id;
    private String fullName;
    private String firstName;
    private String lastName;
    private String email;
    private String address;
    private String username;
    private String role;
    private String avatarUrl;
    private Boolean status;

}
