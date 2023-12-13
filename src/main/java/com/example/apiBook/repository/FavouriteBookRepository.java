package com.example.apiBook.repository;

import com.example.apiBook.entity.FavouriteBook;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FavouriteBookRepository extends JpaRepository<FavouriteBook, Long> {
    FavouriteBook findByBookIdAndUserId(Long bookId, Long userId);
}
