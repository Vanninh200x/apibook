package com.example.apiBook.controller;

import com.example.apiBook.repository.BookRepository;
import com.example.apiBook.repository.CategoryRepository;
import com.example.apiBook.repository.UserRepository;
import io.netty.handler.codec.serialization.ObjectEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpSession;
import java.util.List;

@RequestMapping("")
@Controller
@CrossOrigin
public class DashboardController {

    @Autowired
    BookRepository bookRepository;
    @Autowired
    UserRepository userRepository;
    @Autowired
    CategoryRepository categoryRepository;
    @GetMapping("/dashboard")
    @CrossOrigin
    public String index(Model model) {
        List<Object[]> result = categoryRepository.getQuantity();
        model.addAttribute("books", result.get(0)[0].toString());
        model.addAttribute("categories", result.get(0)[2].toString());
        model.addAttribute("users", result.get(0)[1].toString());

        return "dashboardPage";
    }
}
