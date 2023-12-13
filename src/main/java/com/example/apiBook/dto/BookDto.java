package com.example.apiBook.dto;

import com.example.apiBook.entity.Book;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BookDto {
    private Long id;
    private String avatarUrl;
    private Boolean status;
    private String description;
    private String title;
    private Boolean isDone;
    private String categoryName;

    public BookDto(Book book, String categoryName) {
        this.id = book.getId();
        this.categoryName = categoryName;
        this.isDone = book.getIsDone();
        this.avatarUrl = book.getAvatarUrl();
        this.description = book.getDescription();
        this.status = book.getStatus();
        this.title = book.getTitle();
    }
}
