package com.example.apiBook.exceptions;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class   ErrorResponse {
    private final boolean success = false;
    private HttpStatus status;
    private String message;
    @JsonProperty("status_code")
    private int statusCode;
}