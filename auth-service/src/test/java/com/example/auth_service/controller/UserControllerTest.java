package com.example.auth_service.controller;
import com.example.auth_service.service.UserService;
import com.example.library.entity.Userinfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    private MockMvc mockMvc;

    @InjectMocks
    private UserController userController;

    @Mock
    private UserService userService;

    private Userinfo user;


    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        mockMvc = MockMvcBuilders.standaloneSetup(userController).build();
        user = new Userinfo();
        user.setUsername("testuser");
        user.setPassword("password");
        user.setRole("ROLE_HR");
    }
    @Test
    void testRegister() throws Exception {
        when(userService.registerUser(any(Userinfo.class))).thenReturn(user);
        mockMvc.perform(post("/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(user))) //converts object to string
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.password").value("password"))
                .andExpect(jsonPath("$.role").value("ROLE_HR"));
        verify(userService, times(1)).registerUser(any(Userinfo.class));
    }

    @Test
    void testLoginSuccess() throws Exception {
        when(userService.verify(any(Userinfo.class))).thenReturn("mocked-jwt-token");
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(user)))
                .andExpect(status().isOk())
                .andExpect(content().string("mocked-jwt-token"));
        verify(userService, times(1)).verify(any(Userinfo.class));
    }
    @Test
    void testLoginFailure() throws Exception {
        when(userService.verify(any(Userinfo.class))).thenReturn("Authentication Failed");
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(user)))
                .andExpect(status().isOk())
                .andExpect(content().string("Authentication Failed"));
        verify(userService, times(1)).verify(any(Userinfo.class));
    }
    @Test
    @WithMockUser(roles = "HR")
    void testHRAccess() throws Exception {
        mockMvc.perform(get("/hr"))
                .andExpect(status().isOk())
                .andExpect(content().string("hr dashboard"));
    }
    @Test
    @WithMockUser(roles = "INTERVIEWER")
    void testInterviewerAccess() throws Exception {
        mockMvc.perform(get("/interviewer"))
                .andExpect(status().isOk())
                .andExpect(content().string("interviewer dashboard"));
    }
    @Test
    @WithMockUser(authorities = "APPLICANT")
    void testApplicantAccess() throws Exception {
        mockMvc.perform(get("/applicant"))
                .andExpect(status().isOk())
                .andExpect(content().string("applicant dashboard"));
    }

}

