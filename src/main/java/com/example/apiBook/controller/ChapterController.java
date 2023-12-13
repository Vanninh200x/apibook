package com.example.apiBook.controller;

import com.example.apiBook.dto.request.ChapterRequest;
import com.example.apiBook.dto.response.ChapterResponse;
import com.example.apiBook.entity.Book;
import com.example.apiBook.entity.Chapter;
import com.example.apiBook.exceptions.NotFoundException;
import com.example.apiBook.helper.ResponseObj;
import com.example.apiBook.repository.BookRepository;
import com.example.apiBook.repository.ChapterRepository;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.transaction.Transactional;
import javax.validation.Valid;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@RequestMapping("/api/chapters")
@RestController
@CrossOrigin
public class ChapterController {
    @Autowired
    ChapterRepository chapterRepository;
    @Autowired
    BookRepository bookRepository;


//    @Transactional(rollbackOn = Exception.class)
//    @ApiOperation(value = "add book")
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_AUTHOR')")
//    @RequestMapping(path = "", method = POST, consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
//    @CrossOrigin

    @Transactional(rollbackOn = Exception.class)
    @ApiOperation(value = "add chapter")
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_AUTHOR')")
    @PostMapping(path = "")
    @CrossOrigin
    public ResponseEntity addChapters(@Valid @RequestBody ChapterRequest chapter) {
        Book book = bookRepository.findById(chapter.getBookId()).orElseThrow(
                () -> new NotFoundException(HttpStatus.NOT_FOUND, "book id not found"));
        Chapter chapterSave = chapterRepository.save(Chapter.builder()
                .bookId(chapter.getBookId())
                .chapterTitle(chapter.getChapterTitle())
                .content(chapter.getContent())
                .createdAt(LocalDateTime.now())
                .number(chapter.getNumber())
                .build());
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "add chapter successfully", ChapterResponse.builder().bookId(book.getId()).name(book.getTitle()).number(chapterSave.getNumber()).content(chapterSave.getContent()).build()));
    }

    @ApiOperation(value = "get chapter")
    @GetMapping("/{bookId}")
    @Query()
    @CrossOrigin
    public ResponseEntity getChapter(@PathVariable Long bookId) {
        Book book = bookRepository.findById(bookId).orElseThrow(
                () -> new NotFoundException(HttpStatus.NOT_FOUND, "book id not found"));
        List<Chapter> chapter = chapterRepository.getChapterByBookId(bookId);
        List<ChapterResponse> chapterResponses = new ArrayList<>();
        AtomicInteger i = new AtomicInteger(1);
        chapter.stream().forEach(item -> {
            ChapterResponse chapterResponse = ChapterResponse.builder()
                    .number((long) i.getAndIncrement())
                    .content(item.getContent())
                    .chapterTitle(item.getChapterTitle())
                    .name(book.getTitle())
                    .bookId(item.getBookId())
                    .build();
            chapterResponses.add(chapterResponse);
        });
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get chapter successfully", chapterResponses));
    }
}
