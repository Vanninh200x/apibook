package com.example.apiBook.dto.request;

import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Builder
@Data
public class LoginRequest {
    @NotBlank(message = "abc")
    private  String account;
    @NotBlank
    private String password;
}
