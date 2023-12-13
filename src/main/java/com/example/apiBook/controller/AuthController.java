package com.example.apiBook.controller;

import com.example.apiBook.dto.request.*;
import com.example.apiBook.entity.User;
import com.example.apiBook.helper.ResponseObj;
import com.example.apiBook.repository.UserRepository;
import com.example.apiBook.security.jwt.JwtUtils;
import com.example.apiBook.service.AuthService;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Optional;

@RequestMapping("/api/auth")
@RestController
@CrossOrigin
public class AuthController {
    @Autowired
    AuthService authService;

    @PostMapping("/register")
    @ApiOperation(value = "Đăng ký")
    @CrossOrigin
    public ResponseEntity register(@Valid @RequestBody RegisterRequest user) {
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "save user successfully", authService.register(user)));
    }

    @ApiOperation(value = "verify code")
    @PostMapping("/verify")
    @CrossOrigin
    public ResponseEntity verify(@RequestBody VerifyRequest verifyRequest, HttpServletRequest httpServletRequest) {
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "verify successfully", authService.verify(verifyRequest.getCode(), httpServletRequest)));
    }

    @ApiOperation(value = "Đăng nhập")
    @PostMapping("/login")
    @CrossOrigin
    public ResponseEntity signIn(@Valid @RequestBody LoginRequest user) {
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "login successfully", authService.signIn(user)));

    }

    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_USER', 'ROLE_AUTHOR')")
    @ApiOperation(value = "đăng xuất")
    @PostMapping("/logout")
    @CrossOrigin

    public ResponseEntity logout(@RequestBody LogoutRequest logoutRequest) {
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "log out successfully", authService.logout(logoutRequest.getToken())));
    }

    @ApiOperation(value = "gửi lại mã code")
    @GetMapping("/resendCode")
    @CrossOrigin

    public ResponseEntity resendCode(HttpServletRequest httpServletRequest) {
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "resend code successfully", authService.reSendCode(httpServletRequest)));
    }

    @PostMapping("/findEmail")
    @CrossOrigin

    public ResponseEntity findEmail(@RequestBody FindEmailRequest findEmailRequest) {
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "Please check your email for password reset code", authService.findEmail(findEmailRequest.getEmail())));
    }

    @ApiOperation(value = "Đặt lại mật khẩu")
    @PostMapping("/resetPassword")
    @CrossOrigin
    public ResponseEntity resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest, HttpServletRequest httpServletRequest) {
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "reset password successfully", authService.resetPassword(resetPasswordRequest.getPassword(), httpServletRequest)));

    }


    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_USER')")
    @GetMapping("/whoami")
    @CrossOrigin
    public ResponseEntity whoAmI(HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.OK).body(new ResponseObj(HttpStatus.OK.value(), true, "get infor successfully", authService.whoAmI(request)));
    }


}
