package com.example.jwt.controllers;

import com.example.jwt.models.ERole;
import com.example.jwt.models.Role;
import com.example.jwt.models.User;
import com.example.jwt.payload.request.LoginRequest;
import com.example.jwt.payload.request.SignupRequest;
import com.example.jwt.payload.response.JwtResponse;
import com.example.jwt.payload.response.MessageResponse;
import com.example.jwt.repository.RoleRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.security.jwt.JwtUtils;
import com.example.jwt.security.services.UserDetailsImpl;
import com.example.jwt.utils.HttpCookiesUtil;
import com.sun.deploy.net.HttpResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


//@CrossOrigin(origins = "*", maxAge = 3600)
@Controller
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @GetMapping("/signing")
    public String auth(Model model) {

        model.addAttribute("user_param", new LoginRequest());
        return "login";
    }

    @PostMapping("/signing_process")
    public String authenticateUser(LoginRequest loginRequest, HttpServletResponse res, HttpServletRequest request, Model model) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        /******************Working with Cookies to handle the jwt ******************/

        HttpCookiesUtil httpCookiesUtil = new HttpCookiesUtil();
        httpCookiesUtil.setCookies(res, jwt);

        //sending jwt response against the request to thyme template
        model.addAttribute("jwt_response",
                new JwtResponse(
                        jwt,
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles
                )
        );
        model.addAttribute("header", request.getHeader("Authorization"));
        model.addAttribute("Auth", request.getAuthType());
        model.addAttribute("Cookie", WebUtils.getCookie(request, "token"));

        return "register_success";
    }

    @PostMapping("/signup")
    public String registerUser( SignupRequest signUpRequest, Model model) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            model.addAttribute("error", new MessageResponse("Username is already is use "));

//            return ResponseEntity
//                    .badRequest()
//                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {

            model.addAttribute("error","Email is already in use ! ");
//            return ResponseEntity
//                    .badRequest()
//                    .body(new MessageResponse("Error: Email is already in use!"));

        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return  "signup_form";
       //return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

}
