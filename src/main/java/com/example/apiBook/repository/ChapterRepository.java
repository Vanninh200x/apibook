package com.example.apiBook.repository;

import com.example.apiBook.entity.Chapter;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ChapterRepository extends JpaRepository<Chapter, Long> {

    @Query("SELECT c FROM Chapter c WHERE c.bookId = :bookId  ORDER BY c.createdAt")
    List<Chapter> getChapterByBookId(@Param("bookId") Long id);

    @Query(value = "SELECT c.*\n" +
            "FROM Chapter c\n" +
            "         JOIN (\n" +
            "    SELECT book_id, MAX(number) AS max_number\n" +
            "    FROM Chapter\n" +
            "    GROUP BY book_id\n" +
            ") subquery ON c.book_id = subquery.book_id AND c.number = subquery.max_number\n" +
            "WHERE c.book_id IN ?1", nativeQuery = true)
    List<Chapter> getChapterMax(List<Long> bookIds);
}