package com.example.jwt.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Optional;

@Controller
@RequestMapping("/test")
public class TestController {

    @GetMapping("/all")
    public String allAccess(@CookieValue("token") String token, Model model, HttpServletRequest request) {

        model.addAttribute("test", false);
        model.addAttribute("user",   request.getRemoteUser()+" you and everyone else can access public Content ");
        model.addAttribute("cookie", token + "\n Host " + request.getRemoteHost());

        return "test";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess(Model model, @CookieValue("token") String token, HttpServletRequest request) {

        model.addAttribute("test", false);
        model.addAttribute("user", request.getRemoteUser()+" as User you can also access to this content ");
        model.addAttribute("cookie", token);
        model.addAttribute("cookie", token + "\n Host " + request.getRemoteHost());

        return "test";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess(@CookieValue("token") String token, Model model, HttpServletResponse res, HttpServletRequest request) {

        model.addAttribute("test", false);
        model.addAttribute("user", request.getRemoteUser()+" as a moderator you can access this content ");
        model.addAttribute("cookie", token);
        model.addAttribute("cookie", token + "\n Host " + request.getRemoteHost());

        return "test";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")

    public String adminAccess(@CookieValue("token") String token, Model model, HttpServletRequest request) {

        model.addAttribute("test", false);
        model.addAttribute("user", request.getRemoteUser()+" as a Admin you can access this content ");
        model.addAttribute("cookie", token);
        model.addAttribute("cookie", token + "\n Host " + request.getRemoteHost());

        return "test";
    }

    public Optional<String> readCookie(String key, Cookie[] cookies) {

        return Arrays.stream(cookies)
                .filter(c -> key.equals(c.getName()))
                .map(Cookie::getValue)
                .findAny();
    }
}
