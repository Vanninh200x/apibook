package com.example.apiBook.controller;

import com.example.apiBook.dto.RatingDto;
import com.example.apiBook.dto.request.YourBookRequest;
import com.example.apiBook.dto.response.BookResponse;
import com.example.apiBook.entity.*;
import com.example.apiBook.exceptions.NotFoundException;
import com.example.apiBook.helper.ResponseObj;
import com.example.apiBook.repository.*;
import com.example.apiBook.service.FtpService;
import io.swagger.annotations.ApiOperation;
import lombok.Synchronized;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;
import java.io.IOException;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RequestMapping("/api/books")
@RestController
@CrossOrigin
public class BookController {
    @Autowired
    private CategoryRepository categoryRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private FtpService ftpService;
    private static final Logger logger = LoggerFactory.getLogger(BookController.class);
    @Autowired
    private BookRepository bookRepository;
    @Autowired
    private CategoryBookRepository categoryBookRepository;
    @Autowired
    private ChapterRepository chapterRepository;
    @Autowired
    private FavouriteBookRepository favouriteBookRepository;
    @Autowired
    private RatingRepository ratingRepository;

    @Transactional(rollbackOn = Exception.class)
    @ApiOperation(value = "add book")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_AUTHOR')")
    @RequestMapping(path = "", method = POST, consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    @CrossOrigin
    public ResponseEntity addBook(@RequestParam("title")
                                  String title,
                                  @RequestParam("categoryName")
                                  String categoryName,
                                  @RequestParam("description")
                                  String description,
                                  @RequestParam("image")
                                  MultipartFile image,
                                  @RequestParam("isDone")
                                  Boolean isDone) throws IOException {
        Category category = categoryRepository.findByName(categoryName).orElseThrow(
                () -> new NotFoundException(HttpStatus.NOT_FOUND, "category  not exist")
        );
        String fileName = System.currentTimeMillis() + image.getOriginalFilename();
        ftpService.uploadFile(image, fileName);
        Book bookSave = bookRepository.save(Book.builder().avatarUrl(fileName)
                .isDone(isDone).description(description).status(true).title(title).build());
        CategoryBook categoryBookSave = categoryBookRepository.save(CategoryBook.builder().bookId(bookSave.getId()).categoryId(category.getId()).build());
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "save user successfully", bookSave));
    }

    @ApiOperation(value = "get book")
    @GetMapping("")
    @CrossOrigin
    public ResponseEntity getBook(HttpServletRequest request) throws IOException {
        String baseUrl = ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(null)
                .build()
                .toUriString();
//      Lấy sách tất cả truyện
        List<Book> books = bookRepository.findAll();
        List<Long> bookIds = books.stream().map(item -> item.getId()).collect(Collectors.toList());
//      Tạo một List CategoryBooks lấy từ database tìm theo bookIds
        List<CategoryBook> categoryBooks = categoryBookRepository.findByBookIds(bookIds);
        List<Chapter> chapters = chapterRepository.getChapterMax(bookIds);
        List<RatingDto> ratingDtos = ratingRepository.findRating(bookIds);
//      Tạo ra một List categoryIds dựa trên categoryBooks.id
        List<Long> categoryIds = categoryBooks.stream().map(item -> item.getCategoryId()).collect(Collectors.toList());
//      Tạo ra môt List Categories theo như CategoryId trả về
        List<Category> categories = categoryRepository.findBydIs(categoryIds);
        Map<Long, Category> categoryMap = new HashMap<>();
        Map<Long, CategoryBook> categoryBookMap = new HashMap<>();
        Map<Long, Chapter> chapterMap = new HashMap<>();
        Map<Long, RatingDto> ratingDtoHashMap = new HashMap<>();
        ratingDtos.stream().forEach(item-> ratingDtoHashMap.put(item.getBookId(),item));
        chapters.stream().forEach(item -> chapterMap.put(item.getBookId(), item));
        categories.stream().forEach(
                item -> {
                    categoryMap.put(item.getId(), item);
                });
        categoryBooks.stream().forEach(item ->
        {
            categoryBookMap.put(item.getBookId(), item);
        });
        List<BookResponse> bookResponses = new ArrayList<>();
        books.stream().forEach((item) -> {
            BookResponse bookResponse = new BookResponse();
            bookResponse.setId(item.getId());
            if (chapterMap.get(item.getId()) != null) {
                bookResponse.setChapter(chapterMap.get(item.getId()).getNumber());
            } else {
                bookResponse.setChapter(null);
            }
            if(ratingDtoHashMap.get(item.getId())!= null){
                bookResponse.setStar(ratingDtoHashMap.get(item.getId()).getStar());
            }
            else {
                bookResponse.setStar(5);
            }
            bookResponse.setDescription(item.getDescription());
            bookResponse.setStatus(item.getStatus());
            bookResponse.setTitle(item.getTitle());
            bookResponse.setAvatarUrl(baseUrl + "/api/books/thumbnail/" + item.getAvatarUrl());
            bookResponse.setIsDone(item.getIsDone());
            String name = categoryMap.get(categoryBookMap.get(item.getId()).getCategoryId()).getName();
            bookResponse.setCategory(name);
            bookResponses.add(bookResponse);
        });
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", bookResponses));
    }

    @ApiOperation(value = "get your book")
    @GetMapping("yourbook/{bookId}")
    @CrossOrigin
    public ResponseEntity getYourBook(HttpServletRequest request, @PathVariable String bookId) throws IOException {
        String baseUrl = ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(null)
                .build()
                .toUriString();
//      Lấy sách tất cả truyện
        List<Book> books = bookRepository.findByYourBook(Long.valueOf(bookId));
        List<Long> bookIds = books.stream().map(item -> item.getId()).collect(Collectors.toList());
//      Tạo một List CategoryBooks lấy từ database tìm theo bookIds
        List<CategoryBook> categoryBooks = categoryBookRepository.findByBookIds(bookIds);
        List<Chapter> chapters = chapterRepository.getChapterMax(bookIds);
        List<RatingDto> ratingDtos = ratingRepository.findRating(bookIds);
//      Tạo ra một List categoryIds dựa trên categoryBooks.id
        List<Long> categoryIds = categoryBooks.stream().map(item -> item.getCategoryId()).collect(Collectors.toList());
//      Tạo ra môt List Categories theo như CategoryId trả về
        List<Category> categories = categoryRepository.findBydIs(categoryIds);
        Map<Long, Category> categoryMap = new HashMap<>();
        Map<Long, CategoryBook> categoryBookMap = new HashMap<>();
        Map<Long, Chapter> chapterMap = new HashMap<>();
        Map<Long, RatingDto> ratingDtoHashMap = new HashMap<>();
        ratingDtos.stream().forEach(item-> ratingDtoHashMap.put(item.getBookId(),item));
        chapters.stream().forEach(item -> chapterMap.put(item.getBookId(), item));
        categories.stream().forEach(
                item -> {
                    categoryMap.put(item.getId(), item);
                });
        categoryBooks.stream().forEach(item ->
        {
            categoryBookMap.put(item.getBookId(), item);
        });
        List<BookResponse> bookResponses = new ArrayList<>();
        books.stream().forEach((item) -> {
            BookResponse bookResponse = new BookResponse();
            bookResponse.setId(item.getId());
            if (chapterMap.get(item.getId()) != null) {
                bookResponse.setChapter(chapterMap.get(item.getId()).getNumber());
            } else {
                bookResponse.setChapter(null);
            }
            if(ratingDtoHashMap.get(item.getId())!= null){
                bookResponse.setStar(ratingDtoHashMap.get(item.getId()).getStar());
            }
            else {
                bookResponse.setStar(5);
            }
            bookResponse.setDescription(item.getDescription());
            bookResponse.setStatus(item.getStatus());
            bookResponse.setTitle(item.getTitle());
            bookResponse.setAvatarUrl(baseUrl + "/api/books/thumbnail/" + item.getAvatarUrl());
            bookResponse.setIsDone(item.getIsDone());
            String name = categoryMap.get(categoryBookMap.get(item.getId()).getCategoryId()).getName();
            bookResponse.setCategory(name);
            bookResponses.add(bookResponse);
        });
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", bookResponses));
    }

    @ApiOperation(value = "add your book")
    @PostMapping("yourbook")
    @CrossOrigin
    public ResponseEntity addYourBook(@RequestBody YourBookRequest yourBookRequest) throws Exception {
        Book book = bookRepository.findById(yourBookRequest.getBookId()).orElseThrow(() -> new NotFoundException(HttpStatus.NOT_FOUND, "book id is invalid"));
        User user = userRepository.findById(yourBookRequest.getUserId()).orElseThrow(() -> new NotFoundException(HttpStatus.NOT_FOUND, "user id is invalid"));
        FavouriteBook favouriteBook1 = favouriteBookRepository.findByBookIdAndUserId(yourBookRequest.getBookId(), yourBookRequest.getUserId());
        if (favouriteBook1 != null) {
            return null;
        }
        FavouriteBook favouriteBook = favouriteBookRepository.save(FavouriteBook.builder().bookId(yourBookRequest.getBookId()).userId(yourBookRequest.getUserId()).build());
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "add your book successfully", favouriteBook));

    }

    @ApiOperation(value = "get book")
    @GetMapping("/search/{title}")
    @CrossOrigin
    public ResponseEntity getBookBySearch(HttpServletRequest request, @PathVariable String title) throws IOException {
        String baseUrl = ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(null)
                .build()
                .toUriString();

        List<Book> books = bookRepository.findBookBySearch(title);
        List<Long> bookIds = books.stream().map(item -> item.getId()).collect(Collectors.toList());
        List<CategoryBook> categoryBooks = categoryBookRepository.findByBookIds(bookIds);
        List<Chapter> chapters = chapterRepository.getChapterMax(bookIds);
        List<RatingDto> ratingDtos = ratingRepository.findRating(bookIds);
//      Tạo ra một List categoryIds dựa trên categoryBooks.id
        List<Long> categoryIds = categoryBooks.stream().map(item -> item.getCategoryId()).collect(Collectors.toList());
//      Tạo ra môt List Categories theo như CategoryId trả về
        List<Category> categories = categoryRepository.findBydIs(categoryIds);
        Map<Long, Category> categoryMap = new HashMap<>();
        Map<Long, CategoryBook> categoryBookMap = new HashMap<>();
        Map<Long, Chapter> chapterMap = new HashMap<>();
        Map<Long, RatingDto> ratingDtoHashMap = new HashMap<>();
        ratingDtos.stream().forEach(item-> ratingDtoHashMap.put(item.getBookId(),item));
        chapters.stream().forEach(item -> chapterMap.put(item.getBookId(), item));
        categories.stream().forEach(
                item -> {
                    categoryMap.put(item.getId(), item);
                });
        categoryBooks.stream().forEach(item ->
        {
            categoryBookMap.put(item.getBookId(), item);
        });
        List<BookResponse> bookResponses = new ArrayList<>();
        books.stream().forEach((item) -> {
            BookResponse bookResponse = new BookResponse();
            bookResponse.setId(item.getId());
            if (chapterMap.get(item.getId()) != null) {
                bookResponse.setChapter(chapterMap.get(item.getId()).getNumber());
            } else {
                bookResponse.setChapter(null);
            }
            if(ratingDtoHashMap.get(item.getId())!= null){
                bookResponse.setStar(ratingDtoHashMap.get(item.getId()).getStar());
            }
            else {
                bookResponse.setStar(5);
            }
            bookResponse.setDescription(item.getDescription());
            bookResponse.setStatus(item.getStatus());
            bookResponse.setTitle(item.getTitle());
            bookResponse.setAvatarUrl(baseUrl + "/api/books/thumbnail/" + item.getAvatarUrl());
            bookResponse.setIsDone(item.getIsDone());
            String name = categoryMap.get(categoryBookMap.get(item.getId()).getCategoryId()).getName();
            bookResponse.setCategory(name);
            bookResponses.add(bookResponse);
        });
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", bookResponses));
    }


    @ApiOperation(value = "get book")
    @GetMapping("/done")
    @CrossOrigin
    public ResponseEntity getBookDone(HttpServletRequest request) throws IOException {
        String baseUrl = ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(null)
                .build()
                .toUriString();

        List<Book> books = bookRepository.findBookDone();
        List<Long> bookIds = books.stream().map(item -> item.getId()).collect(Collectors.toList());
        List<CategoryBook> categoryBooks = categoryBookRepository.findByBookIds(bookIds);
        List<Chapter> chapters = chapterRepository.getChapterMax(bookIds);
        List<RatingDto> ratingDtos = ratingRepository.findRating(bookIds);
//      Tạo ra một List categoryIds dựa trên categoryBooks.id
        List<Long> categoryIds = categoryBooks.stream().map(item -> item.getCategoryId()).collect(Collectors.toList());
//      Tạo ra môt List Categories theo như CategoryId trả về
        List<Category> categories = categoryRepository.findBydIs(categoryIds);
        Map<Long, Category> categoryMap = new HashMap<>();
        Map<Long, CategoryBook> categoryBookMap = new HashMap<>();
        Map<Long, Chapter> chapterMap = new HashMap<>();
        Map<Long, RatingDto> ratingDtoHashMap = new HashMap<>();
        ratingDtos.stream().forEach(item-> ratingDtoHashMap.put(item.getBookId(),item));
        chapters.stream().forEach(item -> chapterMap.put(item.getBookId(), item));
        categories.stream().forEach(
                item -> {
                    categoryMap.put(item.getId(), item);
                });
        categoryBooks.stream().forEach(item ->
        {
            categoryBookMap.put(item.getBookId(), item);
        });
        List<BookResponse> bookResponses = new ArrayList<>();
        books.stream().forEach((item) -> {
            BookResponse bookResponse = new BookResponse();
            bookResponse.setId(item.getId());
            if (chapterMap.get(item.getId()) != null) {
                bookResponse.setChapter(chapterMap.get(item.getId()).getNumber());
            } else {
                bookResponse.setChapter(null);
            }
            if(ratingDtoHashMap.get(item.getId())!= null){
                bookResponse.setStar(ratingDtoHashMap.get(item.getId()).getStar());
            }
            else {
                bookResponse.setStar(5);
            }
            bookResponse.setDescription(item.getDescription());
            bookResponse.setStatus(item.getStatus());
            bookResponse.setTitle(item.getTitle());
            bookResponse.setAvatarUrl(baseUrl + "/api/books/thumbnail/" + item.getAvatarUrl());
            bookResponse.setIsDone(item.getIsDone());
            String name = categoryMap.get(categoryBookMap.get(item.getId()).getCategoryId()).getName();
            bookResponse.setCategory(name);
            bookResponses.add(bookResponse);
        });
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", bookResponses));
    }

    @GetMapping("/thumbnail/{fileName}")
    @CrossOrigin
    @Synchronized
    public ResponseEntity<byte[]> handleFileUpload(@PathVariable String fileName) throws IOException {
        byte[] fileContent = ftpService.retrieveFile(fileName);
        String contentType = URLConnection.guessContentTypeFromName(fileName);
        if (contentType == null) {
            contentType = "application/octet-stream";
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setCacheControl("no-cache");
        headers.setContentType(MediaType.parseMediaType(contentType));
        headers.setContentDisposition(ContentDisposition.inline().filename(fileName).build());
        return new ResponseEntity<>(fileContent, headers, HttpStatus.OK);

    }


    @ApiOperation(value = "get book category")
    @GetMapping("/{category}")
    @CrossOrigin
    public ResponseEntity getBookByCategory(HttpServletRequest request, @PathVariable String category) throws IOException {
        String baseUrl = ServletUriComponentsBuilder.fromRequestUri(request)
                .replacePath(null)
                .build()
                .toUriString();

        List<Book> books = bookRepository.findBookByCategory(category);
        List<Long> bookIds = books.stream().map(item -> item.getId()).collect(Collectors.toList());
        List<CategoryBook> categoryBooks = categoryBookRepository.findByBookIds(bookIds);
        List<Chapter> chapters = chapterRepository.getChapterMax(bookIds);
        List<RatingDto> ratingDtos = ratingRepository.findRating(bookIds);
//      Tạo ra một List categoryIds dựa trên categoryBooks.id
        List<Long> categoryIds = categoryBooks.stream().map(item -> item.getCategoryId()).collect(Collectors.toList());
//      Tạo ra môt List Categories theo như CategoryId trả về
        List<Category> categories = categoryRepository.findBydIs(categoryIds);
        Map<Long, Category> categoryMap = new HashMap<>();
        Map<Long, CategoryBook> categoryBookMap = new HashMap<>();
        Map<Long, Chapter> chapterMap = new HashMap<>();
        Map<Long, RatingDto> ratingDtoHashMap = new HashMap<>();
        ratingDtos.stream().forEach(item-> ratingDtoHashMap.put(item.getBookId(),item));
        chapters.stream().forEach(item -> chapterMap.put(item.getBookId(), item));
        categories.stream().forEach(
                item -> {
                    categoryMap.put(item.getId(), item);
                });
        categoryBooks.stream().forEach(item ->
        {
            categoryBookMap.put(item.getBookId(), item);
        });
        List<BookResponse> bookResponses = new ArrayList<>();
        books.stream().forEach((item) -> {
            BookResponse bookResponse = new BookResponse();
            bookResponse.setId(item.getId());
            if (chapterMap.get(item.getId()) != null) {
                bookResponse.setChapter(chapterMap.get(item.getId()).getNumber());
            } else {
                bookResponse.setChapter(null);
            }
            if(ratingDtoHashMap.get(item.getId())!= null){
                bookResponse.setStar(ratingDtoHashMap.get(item.getId()).getStar());
            }
            else {
                bookResponse.setStar(5);
            }
            bookResponse.setDescription(item.getDescription());
            bookResponse.setStatus(item.getStatus());
            bookResponse.setTitle(item.getTitle());
            bookResponse.setAvatarUrl(baseUrl + "/api/books/thumbnail/" + item.getAvatarUrl());
            bookResponse.setIsDone(item.getIsDone());
            String name = categoryMap.get(categoryBookMap.get(item.getId()).getCategoryId()).getName();
            bookResponse.setCategory(name);
            bookResponses.add(bookResponse);
        });
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get books successfully", bookResponses));
    }


}
