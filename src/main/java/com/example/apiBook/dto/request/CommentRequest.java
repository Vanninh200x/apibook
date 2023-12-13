package com.example.apiBook.dto.request;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class CommentRequest {
    private Long bookId;
    private String content;
}
