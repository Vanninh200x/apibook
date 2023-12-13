package com.example.apiBook.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginResponse {
//    private Long id;
    private String accessToken;
    private String refreshToken;
//    private String fullName;
//    private String email;
//    private String address;
//    private String username;
//    private  String username;
//    private String role;
//    private String  avatarUrl;
    private Long refreshExpiresIn;
    private Long expiresIn;
}
