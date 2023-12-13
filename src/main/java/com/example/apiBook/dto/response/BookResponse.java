package com.example.apiBook.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BookResponse {
    private Long id;
    private String avatarUrl;
    private Boolean status;
    private String description;
    private String title;
    private Boolean isDone;
    private double star;
    private String category;
    private Long chapter;
}
