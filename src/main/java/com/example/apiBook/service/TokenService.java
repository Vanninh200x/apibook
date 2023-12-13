package com.example.apiBook.service;


import com.example.apiBook.dto.response.TokenResponse;
import com.example.apiBook.exceptions.InvalidRefreshToken;
import com.example.apiBook.repository.TokenRepository;
import com.example.apiBook.security.jwt.JwtUtils;
import com.example.apiBook.security.jwt.TokenType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenService {
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private TokenRepository tokenRepository;

    public TokenResponse refreshToken(String rfToken) {

        if (!jwtUtils.validateJwtToken(rfToken, false)) {
          throw new InvalidRefreshToken(HttpStatus.BAD_REQUEST,"invalid refresh token");
        }
        if(!tokenRepository.existsByToken(rfToken)){
            throw new InvalidRefreshToken(HttpStatus.BAD_REQUEST,"token not exits");
        }
        Long id = Long.valueOf(jwtUtils.getIdFromJwtToken(rfToken, false));
        TokenType accessToken = jwtUtils.generateJwtToken(id, true);
        TokenType refreshToken = jwtUtils.generateJwtToken(id,false);
        tokenRepository.updateToken(refreshToken.getToken(),rfToken);
        return  TokenResponse.builder()
                .accessToken(accessToken.getToken()).
                expiresIn(accessToken.getExpiresIn() - (new Date()).getTime())
                .refreshToken(refreshToken.getToken()).
                refreshExpiresIn(refreshToken.getExpiresIn()-  (new Date()).getTime())
                .build();
    }
}
