package com.example.apiBook.dto;

import com.example.apiBook.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class UserDto {
    private Long id;
    private String fullName;
    private String email;
    private String username;
    private String role;
    private String avatarUrl;
    private Boolean status;
    public UserDto(User user, String role){
        this.id = user.getId();
        this.fullName = user.getFirstName() + user.getLastName();
        this.email = user.getEmail();
        this.username = user.getUsername();
        this. avatarUrl = user.getAvatarUrl();
        this.status = user.getStatus();
        this.role =role;

    }
}
