package com.example.apiBook.entity;

import lombok.*;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "Chapter")
public class Chapter {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Long bookId;
    private Long number;
    private String chapterTitle;
    @Column(columnDefinition = "TEXT")
    private String content;
    @Column(name = "created_at")
    private LocalDateTime createdAt;

}
