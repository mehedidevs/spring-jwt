package com.mehedi.jwtfull;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtService {

    public static final String SECRET_KEY = "4528482B4D6251655468576D597133743677397A24432646294A404E63526655";

    public String extractUserName(String jwt) {


        return extractClaims(jwt, Claims::getSubject);
    }


    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {

        final Claims claims = extractAllClaims(token);


        return claimsResolver.apply(claims);

    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJwt(token)
                .getBody();

    }

    private Key getSigningKey() {

        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails) {

        return generateToken(new HashMap<>(), userDetails);

    }

    public boolean isTokenValid(String token, UserDetails userDetails) {

        final String username = extractUserName(token);

        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));

    }

    private boolean isTokenExpired(String token) {

        return extractTokenExpiration(token).before(new Date());

    }

    private Date extractTokenExpiration(String token) {

        return extractClaims(token, Claims::getExpiration);

    }

    public String generateToken(
            Map<String, Object> claims,
            UserDetails userDetails
    ) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 10000 * 60 * 24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();

    }
}
