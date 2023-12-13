package com.example.apiBook.dto.request;

import org.springframework.web.multipart.MultipartFile;

public class BookRequest {
    private MultipartFile[] avatar;
    private String description;
    private String title;
    private Boolean isDone;
}
