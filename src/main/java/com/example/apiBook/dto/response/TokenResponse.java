package com.example.apiBook.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenResponse {
private String refreshToken;
private String accessToken;
    private Long refreshExpiresIn;
    private Long expiresIn;
}
