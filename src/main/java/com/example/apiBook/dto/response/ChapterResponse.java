package com.example.apiBook.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ChapterResponse {
    private Long bookId;
    private String name;
    private Long number;
    private String chapterTitle;
    private String content;
}
