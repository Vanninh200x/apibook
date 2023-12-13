package com.example.apiBook.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class HandleException {
    @ExceptionHandler(DuplicateException.class)
    @ResponseStatus(value = HttpStatus.CONFLICT)
    public ResponseEntity handleDuplicateException(DuplicateException ex) {
        ex.printStackTrace();

        return ResponseEntity.status(ex.getStatus()).body(new ErrorResponse(ex.getStatus(), ex.getMessage(), ex.getStatus().value()));
    }

    //    @ExceptionHandler(Exception.class)
//    @ResponseStatus(value = HttpStatus.CONFLICT)
//    public ResponseEntity handleException(Exception ex) {
//        ex.printStackTrace();
//        return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(new ErrorResponse(HttpStatus.EXPECTATION_FAILED, ex.getMessage(), HttpStatus.EXPECTATION_FAILED.value()));
//    }
    @ExceptionHandler(InvalidRefreshToken.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public ResponseEntity handleInvalidRefreshException(InvalidRefreshToken ex) {
        ex.printStackTrace();
        return ResponseEntity.status(ex.getStatus()).body(new ErrorResponse(ex.getStatus(), ex.getMessage(), ex.getStatus().value()));

    }

    @ExceptionHandler(NotFoundException.class)
    @ResponseStatus(value = HttpStatus.NOT_FOUND)
    public ResponseEntity handleNotFoundException(NotFoundException ex) {
        ex.printStackTrace();

        return ResponseEntity.status(ex.getStatus()).body(new ErrorResponse(ex.getStatus(), ex.getMessage(), ex.getStatus().value()));
    }

    @ExceptionHandler(InvalidFilenameException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public ResponseEntity handleInvalidFilenameException(InvalidFilenameException ex) {
        ex.printStackTrace();

        return ResponseEntity.status(ex.getStatus()).body(new ErrorResponse(ex.getStatus(), ex.getMessage(), ex.getStatus().value()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public ResponseEntity handleValidateException(MethodArgumentNotValidException ex) {
        ex.printStackTrace();
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> {
                    if (errors.containsKey(error.getField())) {
                        errors.put(error.getField(), String.format("%s, %s", errors.get(error.getField()), error.getDefaultMessage()));
                    } else {
                        errors.put(error.getField(), error.getDefaultMessage());
                    }
                }
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse(HttpStatus.BAD_REQUEST, errors.toString(), HttpStatus.BAD_REQUEST.value()));

    }

    @ExceptionHandler(BindException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public ResponseEntity handleBindingException(BindException ex) {
        ex.printStackTrace();
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> {
                    if (errors.containsKey(error.getField())) {
                        errors.put(error.getField(), String.format("%s, %s", errors.get(error.getField()), error.getDefaultMessage()));
                    } else {
                        errors.put(error.getField(), error.getDefaultMessage());
                    }
                }
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errors);

    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public ResponseEntity handleBindingException(MaxUploadSizeExceededException ex) {
        ex.printStackTrace();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse(HttpStatus.BAD_REQUEST, "file must less than 10MB", HttpStatus.BAD_REQUEST.value()));
    }
    @ExceptionHandler(InvalidLoginException.class)
    @ResponseStatus(value = HttpStatus.BAD_REQUEST)
    public ResponseEntity handleInvalidLoginException(InvalidLoginException ex) {
        ex.printStackTrace();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse(ex.getStatus(), ex.getMessage(), ex.getStatus().value()));
    }
}
