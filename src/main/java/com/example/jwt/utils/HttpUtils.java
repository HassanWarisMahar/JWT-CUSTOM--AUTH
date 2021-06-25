package com.example.jwt.utils;

import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class HttpUtils {

    //setting Jwt-Token Cookie To Client Side
    public void setCookies(HttpServletResponse res, String jwt) {
        // i have to use  authorization header but now I am using Cookies

        Cookie cookie = new Cookie("token", jwt);
        cookie.setMaxAge(7 * 24 * 60 * 60); // expires in 7 days
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        res.addCookie(cookie);
//        res.setHeader("Access-Control-Allow-Origin", "*");

    }

    //Getting User Jwt- from Cookie
    public String getTokenFromCookie(HttpServletRequest request) {

        Cookie cookie = WebUtils.getCookie(request, "token");
        return cookie.getValue();

    }
    //Removing Cookie from Client
    public void removeCookie(HttpServletResponse response) {

        Cookie cookie = new Cookie("token", "");
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);

    }

}
