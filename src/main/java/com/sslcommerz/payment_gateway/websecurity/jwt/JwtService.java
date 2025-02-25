package com.sslcommerz.payment_gateway.websecurity.jwt;

import com.sslcommerz.payment_gateway.entity.User;
import com.sslcommerz.payment_gateway.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;


@Service
@RequiredArgsConstructor
public class JwtService {

    private final TokenRepository tokenRepository;

    public JwtService(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    private final String SECREAT_KEY = "d169552a202ace4ed9b31a326df08a2aa723e197a10213030f7c4be596ba99b6";
    private static long VALIDITY = TimeUnit.MINUTES.toMinutes(20000000);

    //Get All Part from token
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getBody();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECREAT_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Create new Token
    public String generateToken(User user) {
        return Jwts.builder()
                .subject(user.getEmail()) //Set Email as Subject
                .claim("role", user.getRole()) //Add user ROle to Payload
                .issuedAt(Date.from(Instant.now())) //set Token Issue Ime
                .expiration(Date.from(Instant.now().plusMillis(VALIDITY))) // Set Token Expire time
                .signWith(getSigningKey()) //Sign the token with secreat key
                .compact(); //Build and compacts the token into String
    }

    // GET User from Token
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private boolean isTokenExprired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean isValid(String token, UserDetails user) {

        String username = extractUserName(token);

        boolean validToken = tokenRepository
                .findByToken(token)
                .map(t -> !t.isLogout()) //Check user is in login mode
                .orElse(false);
        return (username.equals(user.getUsername()) && !isTokenExprired(token) && validToken);
    }


    //Extract a apecifice claim from the token clims
    public <T> T extractClaim(String token, Function<Claims, T> resover) {
        Claims claims = extractAllClaims(token);
        return resover.apply(claims);
    }

    public String extractUserRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }
}
