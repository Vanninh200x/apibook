package com.example.apiBook.dto.request;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RatingRequest {
    private Long bookId;
    private Long star;
}
