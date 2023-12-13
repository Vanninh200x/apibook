package com.example.apiBook.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class CommentResponse {
    Long userId;
    String userName;
    String avatar_url;
    String content;
    String firstName;
    String lastName;

}
