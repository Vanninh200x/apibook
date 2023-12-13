package com.example.apiBook.controller;

import com.example.apiBook.dto.request.CategoryRequest;
import com.example.apiBook.entity.Category;
import com.example.apiBook.exceptions.DuplicateException;
import com.example.apiBook.helper.ResponseObj;
import com.example.apiBook.repository.CategoryRepository;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@RequestMapping("/api/categories")
@RestController
public class CategoryController {
    @Autowired
    private CategoryRepository categoryRepository;

    @PostMapping("")
    @ApiOperation(value = "add category")
    @CrossOrigin

    public ResponseEntity postCategory(@Valid @RequestBody CategoryRequest category) {
        if (!categoryRepository.existsByName(category.getName())) {
            Category categorySaved = categoryRepository.save(Category.builder().name(category.getName()).status(true)
                    .build());
            return ResponseEntity.status(HttpStatus.CREATED).body(new ResponseObj(HttpStatus.CREATED.value(),
                    true, "create category successfully ", categorySaved));
        }
        throw new DuplicateException(HttpStatus.CONFLICT, "duplicate record");
    }

    @ApiOperation(value = "get category")
    @CrossOrigin
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseEntity getCategories() {
        List<Category> categories = categoryRepository.findAll();
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.FOUND.value(), true, "get categories successfully ", categories));
    }
}
