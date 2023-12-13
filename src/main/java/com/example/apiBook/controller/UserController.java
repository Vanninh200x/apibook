package com.example.apiBook.controller;

import com.example.apiBook.commons.RoleEnum;
import com.example.apiBook.entity.User;
import com.example.apiBook.entity.UserRole;
import com.example.apiBook.repository.UserRepository;
import com.example.apiBook.repository.UserRoleRepository;
import com.example.apiBook.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Controller
@RequiredArgsConstructor
@CrossOrigin
@RequestMapping("/user")
public class UserController {
    @Autowired
    UserService userService;
    @Autowired
    UserRoleRepository userRoleRepository;
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    UserRepository userRepository;

    @GetMapping("")
    @CrossOrigin
    public String getProduct1(Model model, @RequestParam(required = false) Optional<Integer> page,
                              @RequestParam(required = false) Optional<Integer> size) throws IOException, ServletException {
        int currentPage = page.orElse(1);
        int pageSize = size.orElse(10);

        Page<User> userPage = userService.findPaginated(PageRequest.of(currentPage - 1, pageSize));

        model.addAttribute("users", userPage);

        int totalPages = userPage.getTotalPages();
        if (totalPages > 0) {
            List<Integer> pageNumbers = IntStream.rangeClosed(1, totalPages)
                    .boxed()
                    .collect(Collectors.toList());
            model.addAttribute("pageNumbers", pageNumbers);
        }
        return "userPage";
    }

    @GetMapping("/edit")
    @CrossOrigin
    public String userFrom(@RequestParam("userId") Optional<Long> userId, Model model) throws IOException, ServletException {
        Optional<User> userOptional = Optional.empty();

        if (userId.isPresent()) {
            userOptional = userRepository.findById(userId.get());
        }
        User user;
        if (userOptional.isPresent()) {
            user = userOptional.get();
        } else {
            user = new User();
        }
        model.addAttribute("user", user);

        return "userEdit";
    }

    @PostMapping("/edit")
    @CrossOrigin
    public String userEdit(@ModelAttribute("user") User user) throws IOException, ServletException {
        user.setPassword(encoder.encode(user.getPassword()));
        user.setStatus(true);
        if (user.getId() == null) {
            User user1 = userRepository.save(user);
            userRoleRepository.save(UserRole.builder().role(RoleEnum.USER.getRole()).userId(user1.getId()).build());
        }
        return "redirect:/user";
    }

    @PostMapping("/delete")
    @CrossOrigin
    public String deleteUser1(@RequestParam("userId") Long userId) throws IOException, ServletException {
        userRepository.deleteById(userId);
        return "redirect:/user";
    }
}
