package com.example.apiBook.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class RatingDto {
    Long  bookId;
    Double star;
}
