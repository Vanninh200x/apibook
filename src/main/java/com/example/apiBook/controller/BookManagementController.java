package com.example.apiBook.controller;

import com.example.apiBook.dto.BookDto;
import com.example.apiBook.dto.Post;
import com.example.apiBook.entity.Book;
import com.example.apiBook.entity.Category;
import com.example.apiBook.entity.CategoryBook;
import com.example.apiBook.entity.Chapter;
import com.example.apiBook.exceptions.NotFoundException;
import com.example.apiBook.repository.BookRepository;
import com.example.apiBook.repository.CategoryBookRepository;
import com.example.apiBook.repository.CategoryRepository;
import com.example.apiBook.service.BookService;
import com.example.apiBook.service.ChapterService;
import com.example.apiBook.service.FtpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@RequestMapping("/book")
@Controller
@CrossOrigin
public class BookManagementController {
    @Autowired
    BookRepository bookRepository;
    @Autowired
    CategoryRepository categoryRepository;
    @Autowired
    private CategoryBookRepository categoryBookRepository;
    @Autowired
    BookService bookService;
    @Autowired
    ChapterService chapterService;
    @Autowired
    private FtpService ftpService;

    @GetMapping("")
    @CrossOrigin
    public String getProduct2(HttpServletRequest request, Model model, @RequestParam(required = false) Optional<Integer> page,
                             @RequestParam(required = false) Optional<Integer> size) throws IOException, ServletException {
        int currentPage = page.orElse(1);
        int pageSize = size.orElse(10);
        String baseUrl = ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(null)
                .build()
                .toUriString();
        Page<Book> bookPage = bookService.findPaginated(PageRequest.of(currentPage - 1, pageSize));
        bookPage.getContent().stream().forEach(item -> {
            item.setAvatarUrl(baseUrl + "/api/books/thumbnail/" + item.getAvatarUrl());
        });
        model.addAttribute("bookPage", bookPage);
        int totalPages = bookPage.getTotalPages();
        if (totalPages > 0) {
            List<Integer> pageNumbers = IntStream.rangeClosed(1, totalPages)
                    .boxed()
                    .collect(Collectors.toList());
            model.addAttribute("pageNumbers", pageNumbers);
        }

        return "book-list.html";
    }

    @GetMapping("/edit")
    @CrossOrigin
    public String categoryFrom1(HttpServletRequest request,
                               @RequestParam("bookId")
                               Optional<Long> bookId, Model model,
                               @RequestParam(required = false) Optional<Integer> page,
                               @RequestParam(required = false) Optional<Integer> size,
                               @RequestParam(required = false) Optional<Integer> page1,
                               @RequestParam(required = false) Optional<Integer> size1,
                               @RequestParam("chapterId") Optional<Long> chapterId) throws IOException, ServletException {
        Optional<BookDto> bookOptional = Optional.empty();
        int currentPage = page.orElse(1);
        int pageSize = size.orElse(10);
        int currentPage1 = page1.orElse(1);
        int pageSize1 = size1.orElse(10);

        model.addAttribute("post", new Post());
        String baseUrl = ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(null)
                .build()
                .toUriString();
        List<Category> categories = categoryRepository.findAll();

        if (bookId.isPresent()) {
            bookOptional = bookRepository.getDto(bookId.get());
            Page<Chapter> chapterPage = chapterService.findPaginated(PageRequest.of(currentPage1 - 1, pageSize1), bookId.get());
            if (!chapterPage.isEmpty()) {

                model.addAttribute("chapterPage", chapterPage);
                int totalChapterPages = chapterPage.getTotalPages();
                if (totalChapterPages > 0) {
                    List<Integer> pageNumbers = IntStream.rangeClosed(1, totalChapterPages)
                            .boxed()
                            .collect(Collectors.toList());
                    model.addAttribute("chapterPageNumbers", pageNumbers);
                }
            } else {
                model.addAttribute("chapterPage", null);
                model.addAttribute("chapterPageNumbers", null);
            }
        } else {
            model.addAttribute("chapterPage", null);
            model.addAttribute("chapterPageNumbers", null);
        }
        BookDto book;

        if (bookOptional.isPresent()) {
            book = bookOptional.get();
            book.setAvatarUrl(baseUrl + "/api/books/thumbnail/" + book.getAvatarUrl());

        } else {
            book = new BookDto();
        }
        model.addAttribute("book", book);
        model.addAttribute("bookId", book.getId());
        model.addAttribute("categories", categories);
        return "book-edit";
    }


    @PostMapping("/edit")
    public String processForm1(@ModelAttribute("book") BookDto book,
                              @RequestParam("file") MultipartFile file) throws IOException {
        String fileName = System.currentTimeMillis() + file.getOriginalFilename();
        Category category = categoryRepository.findByName(book.getCategoryName()).orElseThrow(
                () -> new NotFoundException(HttpStatus.NOT_FOUND, "category  not exist")
        );
        ftpService.uploadFile(file, fileName);
        Book bookSave = bookRepository.save(Book.builder().avatarUrl(fileName)
                .isDone(book.getIsDone()).description(book.getDescription()).status(book.getStatus()).title(book.getTitle()).build());
        CategoryBook categoryBookSave = categoryBookRepository.save(CategoryBook.builder().bookId(bookSave.getId()).categoryId(category.getId()).build());
        return "redirect:/book";
    }
    @PostMapping("/delete")
    @CrossOrigin
    public String deleteUser2(@RequestParam("userId") Long userId) throws IOException, ServletException {
        bookRepository.deleteById(userId);
        return "redirect:/book";
    }
}
