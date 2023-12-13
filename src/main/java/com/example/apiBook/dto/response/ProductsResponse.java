package com.example.apiBook.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder

public class ProductsResponse {
    private String categoryName;
    private List<ProductResponse> products;
    private long totalPage;
    private long currentPage;

}
