package com.example.auth_service.service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;
@Service
public class JWTService {

    private final String constantSecret = "MyConstantSecretKey1234567890123456";

    @Value("${jwt.expiration}")
    private long expiration;

    public String generateToken(String username, String role) {
        SecretKey key = Keys.hmacShaKeyFor(constantSecret.getBytes());
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role.replace("ROLE_", ""))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        SecretKey key = Keys.hmacShaKeyFor(constantSecret.getBytes());
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        final String tokenRole = extractRole(token);
        final String userRole = userDetails.getAuthorities().iterator().next().getAuthority().replace("ROLE_", "");
        return username.equals(userDetails.getUsername()) &&
                tokenRole.equals(userRole) &&
                !isTokenExpired(token);
    }
    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }
}

