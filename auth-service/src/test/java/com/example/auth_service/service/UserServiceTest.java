package com.example.auth_service.service;
import com.example.library.entity.Userinfo;
import com.example.library.repository.UserRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
@ExtendWith(MockitoExtension.class)

class UserServiceTest {
    @InjectMocks
    private UserService userService;
    @Mock
    private UserRepo userRepo;
    @Mock
    private JWTService jwtService;
    @Mock
    private AuthenticationManager authManager;
    private Userinfo user;
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        user = new Userinfo();
        user.setUsername("testuser");
        user.setPassword("password");
        user.setRole("ROLE_HR");
    }
    @Test
    void testRegisterUser() {
        when(userRepo.save(any(Userinfo.class))).thenReturn(user);
        Userinfo registeredUser = userService.registerUser(user);
        assertNotNull(registeredUser);
        assertEquals("testuser", registeredUser.getUsername());
        assertNotEquals("password", registeredUser.getPassword()); // Should be encrypted
        assertEquals("ROLE_HR", registeredUser.getRole());
        verify(userRepo, times(1)).save(any(Userinfo.class));
    }
    @Test
    void testRegisterUserWithNoRole() {
        user.setRole(null);
        when(userRepo.save(any(Userinfo.class))).thenReturn(user);
        Userinfo registeredUser = userService.registerUser(user);
        assertEquals("ROLE_USER", registeredUser.getRole()); // Default role
        verify(userRepo, times(1)).save(any(Userinfo.class));
    }
    @Test
    void testVerifySuccess() {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(auth);
        when(userRepo.findByUsername("testuser")).thenReturn(user);
        when(jwtService.generateToken(anyString(), anyString())).thenReturn("mocked-jwt-token");
        String result = userService.verify(user);
        assertEquals("mocked-jwt-token", result);
        verify(authManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtService, times(1)).generateToken("testuser", "ROLE_HR");
    }
    @Test
    void testVerifyFailure() {
        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(false);
        when(authManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(auth);
        String result = userService.verify(user);
        assertEquals("Authentication Failed", result);
        verify(authManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtService, never()).generateToken(anyString(), anyString());
    }
}






