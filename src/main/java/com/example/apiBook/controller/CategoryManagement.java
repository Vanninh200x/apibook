package com.example.apiBook.controller;

import com.example.apiBook.entity.Category;
import com.example.apiBook.repository.CategoryRepository;
import com.example.apiBook.service.CategoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@RequestMapping("/category")
@Controller
@CrossOrigin
public class CategoryManagement {
    @Autowired
    CategoryService categoryService;
    @Autowired
    CategoryRepository categoryRepository;

    @GetMapping("")
    @CrossOrigin
    public String getProduct(Model model, @RequestParam(required = false) Optional<Integer> page,
                             @RequestParam(required = false) Optional<Integer> size) throws IOException, ServletException {
        int currentPage = page.orElse(1);
        int pageSize = size.orElse(10);

        Page<Category> categoryPage = categoryService.findPaginated(PageRequest.of(currentPage - 1, pageSize));

        model.addAttribute("categories", categoryPage);

        int totalPages = categoryPage.getTotalPages();
        if (totalPages > 0) {
            List<Integer> pageNumbers = IntStream.rangeClosed(1, totalPages)
                    .boxed()
                    .collect(Collectors.toList());
            model.addAttribute("pageNumbers", pageNumbers);
        }
        return "categoryPage";
    }

    @GetMapping("/edit")
    @CrossOrigin
    public String categoryFrom(@RequestParam("categoryId") Optional<Long> categoryId, Model model) throws IOException, ServletException {
        Optional<Category> categoryOptional =   Optional.empty();

        if (categoryId.isPresent()) {
            categoryOptional = categoryRepository.findById(categoryId.get());
        }
        Category category;
        if(categoryOptional.isPresent()){
            category = categoryOptional.get();
        }
        else {
            category = new Category();
        }
        model.addAttribute("category", category);

        return "category-edit";
    }

    @PostMapping("/edit")
    @CrossOrigin
    public String categoryEdit(@ModelAttribute("category") Category category) throws IOException, ServletException {
        categoryRepository.save(category);
        return "redirect:/category";
    }
    @PostMapping("/delete")
    @CrossOrigin
    public String deleteUser3(@RequestParam("userId") Long userId) throws IOException, ServletException {
        categoryRepository.deleteById(userId);
        return "redirect:/category";
    }
}
