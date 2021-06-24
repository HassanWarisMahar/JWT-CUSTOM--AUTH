package com.example.jwt.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Optional;

@CrossOrigin(origins = "*", maxAge = 3600)
@Controller
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/all")
    public String allAccess(@CookieValue("token")String token, Model model, HttpServletRequest request) {
        //	return "Public Content.";
        request.getRemoteUser();
        model.addAttribute("user", "All"+request.getRemoteUser());
        model.addAttribute("cookie", token+"\n"+request.getRemoteHost());

        return "test";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess(Model model, @CookieValue("token") String token, HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");
        model.addAttribute("user", "User");
        model.addAttribute("header", authorization);
        model.addAttribute("cookie", token);
        //  model.addAttribute("cookie", cookie.getValue()/* readCookie("token", cookie.getValue())*/);

        return "test";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess(Model model, HttpServletResponse res, HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");

        model.addAttribute("user", "Moderator");
        model.addAttribute("header", authorization);
        model.addAttribute("cookie", request.getCookies());

        return "test";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")

    public String adminAccess(Model model, HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");

        model.addAttribute("user", "Admin");
        model.addAttribute("header", authorization);
        model.addAttribute("cookie", request.getCookies());

        return "test";
    }

    public Optional<String> readCookie(String key, Cookie[] cookies) {

        return Arrays.stream(cookies)
                .filter(c -> key.equals(c.getName()))
                .map(Cookie::getValue)
                .findAny();
    }
}
