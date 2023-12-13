package com.example.apiBook.dto.request;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class ProductRequest {
    private String name;
    private MultipartFile[] image;
    private MultipartFile thumbnail;
    private String categoryName;
    private Float price;
    private Float priceSale;
    private String description;
}
