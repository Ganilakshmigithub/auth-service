package com.example.auth_service.controller;
import com.example.auth_service.Request.LoginRequest;
import com.example.auth_service.service.JWTService;
import com.example.library.entity.Applicant;
import com.example.library.repository.ApplicantRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private JWTService jwtService;

    @Autowired
    private ApplicantRepo applicantRepo;



    @PostMapping("/validate")
    public ResponseEntity<Map<String, String>> validateToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(null);
        }
        String token = authHeader.substring(7);
        String username = jwtService.extractUserName(token);
        String role = jwtService.extractRole(token);
        Map<String, String> response = new HashMap<>();
        response.put("username", username);
        response.put("role", role);
        return ResponseEntity.ok(response);
    }

}
