package com.example.apiBook.controller;

import com.example.apiBook.repository.TokenRepository;
import com.example.apiBook.repository.UserRepository;
import com.example.apiBook.security.jwt.JwtUtils;
import com.example.apiBook.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@RequestMapping("")
@Controller
@CrossOrigin
public class LoginController {
    @Autowired
    AuthService authService;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TokenRepository tokenRepository;
    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/login")
    @CrossOrigin
    public String login(Model model, HttpServletRequest request, HttpServletResponse response, Object handler) throws IOException, ServletException {
        if (request.getUserPrincipal() != null && request.getUserPrincipal().getName() != null) {
            // User is already logged in, redirect to index page
            return "redirect:/dashboard";
        }
        if (model.containsAttribute("error")) {
            model.addAttribute("errorMessage", "Tên đăng nhập hoặc mật khẩu không chính xác");
        }

        return "loginPage";
    }

    @GetMapping("/resetSuccess")
    @CrossOrigin
    public String resetSuccess(Model model) {
        if (model.containsAttribute("error"))
            return "success";
        return "404";
    }

    @PostMapping("/login")
    @CrossOrigin
    public String login(@RequestParam("username") String username, @RequestParam("password") String password, RedirectAttributes redirectAttributes, HttpSession session) {
        Authentication authentication = null;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", true);
            return "redirect:/login";
        }
        session.setAttribute("username", username);
        return "redirect:/dashboard";

    }


}
