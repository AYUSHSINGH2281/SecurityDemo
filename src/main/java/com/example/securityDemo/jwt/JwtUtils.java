package com.example.securityDemo.jwt;

import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private int jwtExpirationMs;

    @Value("${spring.app.jwtExpirationMs}")
    private String jwtSecret;

    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7); // Remove Bearer Prefix
        }

        return null;
    }

    // Generating token from Username
    public String generateTokenFromUserName(UserDetails userDetails){
        String userName = userDetails.getUsername();
        return Jwts.builder()
            .subject(userName)
            .issuedAt(new Date())
            .expiration(new Date(new Date().getTime() + jwtExpirationMs))
            .signWith(key())
            .compact();
    }
    // Generating Username from JWT Token
    public String getuserNameFromJWTToken(String token){
        return Jwts.parser()
            .verifyWith((SecretKey) key())
            .build().parseSignedClaims(token)
            .getPayload().getSubject();

    }

    // Generate Signing Key
    public Key key(){
        return Keys.hmacShaKeyFor(
            Decoders.BASE64.decode(jwtSecret)
        );
    }

    // Validate JWT Token
    public boolean validateJwtToken(String authToken){
        try{
            System.out.println("Validate");
            Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(authToken);
            return true;
        }catch(MalformedJwtException exception){
            logger.error("Invalid JWT token: {}", exception.getMessage());
        }
        catch(ExpiredJwtException exception){
            logger.error("JWT token is expired: {}", exception.getMessage());
        }
        catch(UnsupportedJwtException exception){
            logger.error("JWT token is expired: {}", exception.getMessage());
        }
        catch(IllegalArgumentException exception){
            logger.error("JWT claims string is empty: {}", exception.getMessage());
        }
        return false;
    }

}
