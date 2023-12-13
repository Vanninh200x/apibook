package com.example.apiBook.repository;

import com.example.apiBook.dto.RatingDto;
import com.example.apiBook.dto.response.CommentResponse;
import com.example.apiBook.entity.Comment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CommentRepository extends JpaRepository<Comment, Long> {
    @Query(value = "SELECT new com.example.apiBook.dto.response.CommentResponse( u.id, u.username, u.avatarUrl, c.content, u.firstName, u.lastName)  FROM Comment c, User  u where c.bookId = ?1  and u.id = c.userId")
    List<CommentResponse> findCommentByBookId(Long id);
}
