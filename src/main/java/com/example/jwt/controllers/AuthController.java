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
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpCookie;
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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@CrossOrigin(origins = "*", maxAge = 3600)
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
    public String authenticateUser(LoginRequest loginRequest, HttpServletResponse res, Model model) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        Cookie cookie = new Cookie("token", jwt);
        cookie.setMaxAge(7 * 24 * 60 * 60); // expires in 7 days
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        res.setHeader("Access-Control-Allow-Credentials", "true");
        res.addCookie(cookie);
        model.addAttribute("jwt",jwt);

//        ResponseEntity
//                .ok()
//                .header(HttpHeaders.AUTHORIZATION, springCookie.toString())
//                .build();

//        return ResponseEntity.ok(new JwtResponse(jwt,
//                userDetails.getId(),
//                userDetails.getUsername(),
//                userDetails.getEmail(),
//                roles));

        return "register_success";
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
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

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

}
