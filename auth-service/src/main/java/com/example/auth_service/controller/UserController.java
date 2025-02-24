package com.example.auth_service.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.auth_service.service.UserService;
import com.example.library.entity.Userinfo;
@RestController
public class UserController {
    @Autowired
    private UserService service;

    @PostMapping("/register")
    public Userinfo register(@RequestBody Userinfo user) {
        return service.registerUser(user);
    }

    @PostMapping("/login")
    public String login(@RequestBody Userinfo user) {
        return service.verify(user);
    }

    @PreAuthorize("hasRole('HR')")
    @GetMapping("/hr")
    public String hr(){
        return "hr dashboard";
    }

    @PreAuthorize("hasRole('INTERVIEWER')")
    @GetMapping("/interviewer")
    public String interviewer(){
        return "interviewer dashboard";
    }

    @PreAuthorize("hasAuthority('APPLICANT')")
    @GetMapping("/applicant")
    public String applicant(){
        return "applicant dashboard";
    }
}



