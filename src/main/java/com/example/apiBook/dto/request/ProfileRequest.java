package com.example.apiBook.dto.request;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class ProfileRequest {
    private String firstName;
    private String lastName;
    private MultipartFile image;
}
