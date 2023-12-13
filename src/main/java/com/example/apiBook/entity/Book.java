package com.example.apiBook.entity;

import lombok.*;

import javax.persistence.*;

@Entity
@Getter
@Setter
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "Books")
public class Book {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "avatar_url",columnDefinition = "TEXT", length = 5000)
    private String avatarUrl;
    @Column(name = "status", nullable = false)
    private Boolean status;
    @Column(name = "description",columnDefinition = "TEXT", length = 5000)
    private String description;
    @Column(name = "title",columnDefinition = "TEXT", length = 5000)
    private String title;
    @Column(name = "is_done")
        private Boolean isDone;
}
