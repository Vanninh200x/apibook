package com.example.apiBook.dto.request;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class ChapterRequest {
    private Long bookId;
    private Long number;
    private String chapterTitle;
    private String content;
}
