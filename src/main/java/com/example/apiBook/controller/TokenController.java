package com.example.apiBook.controller;

import com.example.apiBook.dto.request.TokenRequest;
import com.example.apiBook.service.TokenService;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RequestMapping("/api/token")
@RestController
@CrossOrigin
public class TokenController {
    @Autowired
    private TokenService tokenService;
   // @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_USER', 'ROLE_AUTHOR')")
    @ApiOperation(value ="refresh token")
    @PostMapping("/refreshToken")
    @CrossOrigin

    public ResponseEntity refreshToken(@RequestBody TokenRequest token)  {
        return ResponseEntity.status(HttpStatus.OK).body(tokenService.refreshToken(token.getRfToken()));
    }

}
