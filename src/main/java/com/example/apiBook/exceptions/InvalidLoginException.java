package com.example.apiBook.exceptions;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;
@Getter
@AllArgsConstructor
public class InvalidLoginException extends RuntimeException{
    private HttpStatus status;
    private String message;
}
