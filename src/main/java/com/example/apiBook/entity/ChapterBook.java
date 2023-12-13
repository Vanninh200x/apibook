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
@Table(name = "Chapter_Books")
public class ChapterBook {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name ="book_id")
    private Long bookId;
    @Column(name = "chapter_id")
    private Long chapterId;
}
