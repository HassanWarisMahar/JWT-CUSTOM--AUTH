package com.example.jwt.utils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class HttpCookiesUtil {

    public void setCookies(HttpServletResponse res, String jwt) {
        // Create authorization header
        String authorizationHeader = "Bearer " + jwt;
        Cookie cookie = new Cookie("token", jwt);
        cookie.setMaxAge(7 * 24 * 60 * 60); // expires in 7 days
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
//        res.setHeader("Access-Control-Allow-Credentials", "true");
//        res.setHeader("Authorization",authorizationHeader);
//        res.setHeader("Accept", "application/json");
        // res.setHeader("Connection", "close");
        res.addCookie(cookie);
        res.setHeader("Access-Control-Allow-Origin", "*");
//
    }

    public void removeCookie() {

    }
}
