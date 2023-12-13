package com.example.apiBook.security.jwt;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    @Value("${csApi.jwtSecret}")
    private String jwtSecret;
    private String jwtRF = "refreshToken";
    @Value("${csApi.aJwtExpirationMs}")
    private int aJwtExpirationMs;
    @Value("${csApi.rJwtExpirationMs}")
    private int rJwtExpirationMs;

    public TokenType generateJwtToken(Long id, boolean accessToken) {

        if (accessToken) {
            return TokenType.builder().token(Jwts.builder().setSubject((id.toString())).setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + rJwtExpirationMs)).signWith(SignatureAlgorithm.HS512, jwtSecret)
                    .compact()).expiresIn(new Date((new Date()).getTime() + aJwtExpirationMs).getTime()).build();
        }
        //              .setExpiration(new Date((new Date()).getTime() + 60000)).signWith(SignatureAlgorithm.HS512, jwtSecret)
        //            .compact()).expiresIn(new Date((new Date()).getTime() + 60000).getTime()).build();}

        Calendar c = Calendar.getInstance();
        c.add(Calendar.DATE, 30);
        return TokenType.builder().token(Jwts.builder().setSubject(id.toString()).setIssuedAt(new Date())
                .setExpiration(c.getTime()).signWith(SignatureAlgorithm.HS512, jwtRF)
                .compact()).expiresIn(c.getTime().getTime()).build();
        //    .setExpiration(new Date((new Date()).getTime() + 120000)).signWith(SignatureAlgorithm.HS512, jwtRF)
        // .compact()).expiresIn(new Date((new Date()).getTime() + 120000).getTime()).build();

    }

//    public TokenType generateJwtToken(Long id) {
//        return TokenType.builder().token(Jwts.builder().setSubject((id.toString())).setIssuedAt(new Date())
//                .setExpiration(new Date((new Date()).getTime() + 864000000)).signWith(SignatureAlgorithm.HS512, jwtSecret)
//                .compact()).expiresIn(new Date((new Date()).getTime() + 864000000).getTime()).build();
//        //              .setExpiration(new Date((new Date()).getTime() + 60000)).signWith(SignatureAlgorithm.HS512, jwtSecret)
//        //            .compact()).expiresIn(new Date((new Date()).getTime() + 60000).getTime()).build();}
//
//
//    }

    public String getIdFromJwtToken(String token, boolean access) {
        return Jwts.parser().setSigningKey(access ? jwtSecret : jwtRF).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken, boolean access) {
        try {
            Jwts.parser().setSigningKey(access ? jwtSecret : jwtRF).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }

}