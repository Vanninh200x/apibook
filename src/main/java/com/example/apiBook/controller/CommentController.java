package com.example.apiBook.controller;

import com.example.apiBook.dto.request.CommentRequest;
import com.example.apiBook.entity.Book;
import com.example.apiBook.entity.Comment;
import com.example.apiBook.exceptions.NotFoundException;
import com.example.apiBook.helper.ResponseObj;
import com.example.apiBook.repository.BookRepository;
import com.example.apiBook.repository.CommentRepository;
import com.example.apiBook.repository.UserRepository;
import com.example.apiBook.util.UserUtil;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequestMapping("/api/comment")
@RestController
public class CommentController {
    @Autowired
    BookRepository bookRepository;
    @Autowired
    UserRepository userRepository;
    @Autowired
    CommentRepository commentRepository;

    @PostMapping("")
    @ApiOperation(value = "add comment")
    @CrossOrigin
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_AUTHOR', 'ROLE_USER')")
    public ResponseEntity postComment(@Valid @RequestBody CommentRequest commentRequest) {
        if (!bookRepository.existsById(commentRequest.getBookId())) {
            throw new NotFoundException(HttpStatus.NOT_FOUND, "book  not exist");
        }
        Long userId = UserUtil.getUserId();
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", commentRepository.save(Comment.builder().content(commentRequest.getContent()).bookId(commentRequest.getBookId()).userId(userId).build())));
    }

    @ApiOperation(value = "get comment")
    @GetMapping("/{bookId}")
    @Query()
    @CrossOrigin
    public ResponseEntity getComment(@PathVariable Long bookId) {
        Book book = bookRepository.findById(bookId).orElseThrow(
                () -> new NotFoundException(HttpStatus.NOT_FOUND, "book id not found"));
        commentRepository.findCommentByBookId(bookId);
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", commentRepository.findCommentByBookId(bookId)));
    }
}
