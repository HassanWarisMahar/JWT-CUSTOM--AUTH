package com.example.jwt.controllers;

import com.example.jwt.exceptions.TokenRefreshException;
import com.example.jwt.models.ERole;
import com.example.jwt.models.RefreshToken;
import com.example.jwt.models.Role;
import com.example.jwt.models.User;
import com.example.jwt.payload.request.LoginRequest;
import com.example.jwt.payload.request.RefreshTokenRequest;
import com.example.jwt.payload.request.SignupRequest;
import com.example.jwt.payload.response.JwtResponse;
import com.example.jwt.payload.response.MessageResponse;
import com.example.jwt.payload.response.TokenRefreshResponse;
import com.example.jwt.repository.RoleRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.security.jwt.JwtUtils;
import com.example.jwt.security.services.RefreshTokeService;
import com.example.jwt.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.expression.ExpressionException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

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

    @Autowired
    RefreshTokeService refreshTokeService;

    @GetMapping({"", "/login"})
    public String viewLoginPage(LoginRequest loginRequest, Model model) {
        // custom logic before showing login page...
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword())
        );
        if (authentication == null ) {

            return "login";

        } else {

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            RefreshToken refreshToken = refreshTokeService.createRefreshToken(userDetails.getId());

            JwtResponse jwtResponse =   new JwtResponse(

                    jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles,
                    refreshToken.toString()

            );
            model.addAttribute("JwtResponse",jwtResponse);
            return "redirect:/contacts";
        }





    }

//    @GetMapping("/register")
//    public String showRegistrationForm(Model model) {
//
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        model.addAttribute("user", new User());
//        model.addAttribute("success", true);
//        if (authentication == null || authentication instanceof AnonymousAuthenticationToken) {
//            model.addAttribute("authorized", false);
//        } else {
//            model.addAttribute("authorized", true);
//        }
//        return "signup_form";
//    }
//
//    @PostMapping("/process_register")
//    public String processRegister(User user, Model model) {
//
//        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
//        String encodedPassword = passwordEncoder.encode(user.getPassword());
//        user.setPassword(encodedPassword);
//        User userFromDb = null;
//
//        userFromDb = userRepo.findByEmail(user.getEmail());
//        String response = null;
//
//        if (userFromDb != null) {
//
//            logger.info(" User Email changing " + userFromDb.getEmail());
//            model.addAttribute("user-already-exists", user);
//            model.addAttribute("isExistsUser", true);
//            model.addAttribute("emailAlreadyExists", "This Email is already registered ! " + userFromDb.getEmail());
//            response = "signup_form";
//
//        } else {
//
//            userRepo.save(user);
//            //  model.addAttribute("User","");
//            response = "register_success";
//        }
//        return response;
//    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokeService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(
                new JwtResponse(
                        jwt, userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles, refreshToken.toString()));


//        return ResponseEntity.ok(new JwtResponse(jwt,
//                userDetails.getId(),
//                userDetails.getUsername(),
//                userDetails.getEmail(),
//                roles));

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

        // making account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));


        Set<String> strRoles = signUpRequest.getRole();
        System.out.print("User Details : " + strRoles);
        Set<Role> roles = new HashSet<>();


        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));

            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        System.out.println("User as Admin " + role);
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new ExpressionException("Error: Admin Role is not found."));

                        roles.add(adminRole);

                        break;
                    case "mod":
                        System.out.println("User as Moderator " + role);
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Moderator Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        System.out.println("User as User " + role);
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: User Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse((roles.toString()) + "User registered successfully!"));
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody RefreshTokenRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokeService.findByToken(requestRefreshToken)
                .map(refreshTokeService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }

}
