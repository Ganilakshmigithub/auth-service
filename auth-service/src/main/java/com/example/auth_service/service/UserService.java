package com.example.auth_service.service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.library.entity.Userinfo;
import com.example.library.repository.UserRepo;
@Service
public class UserService {
    @Autowired
    private JWTService jwtService;
    @Autowired
    private AuthenticationManager authManager;
    @Autowired
    private UserRepo userRepo;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    public Userinfo registerUser(Userinfo user) {
        user.setPassword(encoder.encode(user.getPassword()));
        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("ROLE_USER"); // Default role
        }
        return userRepo.save(user);
    }
    public String verify(Userinfo user) {    //we can give only username and password also
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );
        if (auth.isAuthenticated()) {
            Userinfo foundUser = userRepo.findByUsername(user.getUsername());
            if (foundUser != null) {
                // Generate JWT token with a single role
                return jwtService.generateToken(foundUser.getUsername(), foundUser.getRole());
            }
        }
        return "Authentication Failed";
    }
}

