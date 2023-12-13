package com.example.apiBook.controller;

import com.example.apiBook.dto.RatingDto;
import com.example.apiBook.dto.request.RatingRequest;
import com.example.apiBook.dto.response.BookResponse;
import com.example.apiBook.entity.*;
import com.example.apiBook.exceptions.NotFoundException;
import com.example.apiBook.helper.ResponseObj;
import com.example.apiBook.repository.BookRepository;
import com.example.apiBook.repository.RatingRepository;
import com.example.apiBook.util.UserUtil;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@RequestMapping("/api/rating")
@RestController
public class RatingController {
    @Autowired
    RatingRepository ratingRepository;
    @Autowired
    BookRepository bookRepository;

    @PostMapping("")
    @ApiOperation(value = "add rating")
    @CrossOrigin
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_AUTHOR', 'ROLE_USER')")
    public ResponseEntity postRating(@Valid @RequestBody RatingRequest ratingRequest) {
        if (!bookRepository.existsById(ratingRequest.getBookId())) {
            throw new NotFoundException(HttpStatus.NOT_FOUND, "book  not exist");
        }
        Long userId = UserUtil.getUserId();
        Optional<Rating> rating = ratingRepository.findByUserId(userId, ratingRequest.getBookId());
        if (rating.isPresent()) {
            rating.get().setStar(ratingRequest.getStar());
            ratingRepository.save(rating.get());
            return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", ratingRepository.save(rating.get())));


        }
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", ratingRepository.save(Rating.builder().star(ratingRequest.getStar()).bookId(ratingRequest.getBookId()).userId(userId).build())));

    }

    @ApiOperation(value = "get ratting by id")
    @GetMapping("/{userId}/{bookId}")
    @Query()
    @CrossOrigin
    public ResponseEntity getRattingByUserId(@PathVariable Long userId,@PathVariable Long bookId) {
        Book book = bookRepository.findById(bookId).orElseThrow(
                () -> new NotFoundException(HttpStatus.NOT_FOUND, "book id not found"));
        ratingRepository.findByUserId(userId, bookId);
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", ratingRepository.findByUserId(userId,bookId)));
    }


//    @ApiOperation(value = "get comment")
//    @GetMapping("/{bookId}")
//    @Query()
//    @CrossOrigin
//    public ResponseEntity getComment(@PathVariable Long bookId) {
//        Book book = bookRepository.findById(bookId).orElseThrow(
//                () -> new NotFoundException(HttpStatus.NOT_FOUND, "book id not found"));
//        commentRepository.findCommentByBookId(bookId);
//        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", commentRepository.findCommentByBookId(bookId)));
//    }

}
