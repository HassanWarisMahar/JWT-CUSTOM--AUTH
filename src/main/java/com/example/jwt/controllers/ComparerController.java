//package com.example.jwt.controllers;
//
//import com.example.jwt.exceptions.TokenRefreshException;
//
//import com.example.jwt.models.RefreshToken;
//
//import com.example.jwt.payload.request.LoginRequest;
//import com.example.jwt.payload.request.RefreshTokenRequest;
//
//import com.example.jwt.payload.response.JwtResponse;
//import com.example.jwt.payload.response.TokenRefreshResponse;
//import com.example.jwt.security.jwt.JwtUtils;
//import com.example.jwt.security.services.RefreshTokeService;
//import com.example.jwt.security.services.UserDetailsImpl;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.bind.annotation.*;
//
//import javax.validation.Valid;
//import java.util.HashSet;
//import java.util.List;
//import java.util.Set;
//import java.util.stream.Collectors;
//
//
//@RestController
//@RequestMapping("/api/auth")
//public class ComparerController {
//    @Autowired
//    AuthenticationManager authenticationManager;
//
//    @Autowired
//    JwtUtils jwtUtils;
//
//    @Autowired
//    RefreshTokeService refreshTokenService;
//
//
//    @PostMapping("/signin")
//    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
//
//        Authentication authentication = authenticationManager
//                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//
//        String jwt = jwtUtils.generateJwtToken(authentication);
//
//        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
//                .collect(Collectors.toList());
//
//        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
//
//        return ResponseEntity.ok(new JwtResponse(jwt, refreshToken.getToken(), userDetails.getId(),
//                userDetails.getUsername(), userDetails.getEmail(), roles));
//    }
//
//    @PostMapping("/refreshtoken")
//    public ResponseEntity<?> refreshtoken(@Valid @RequestBody RefreshTokenRequest request) {
//        String requestRefreshToken = request.getRefreshToken();
//
//        return refreshTokenService.findByToken(requestRefreshToken)
//                .map(refreshTokenService::verifyExpiration)
//                .map(RefreshToken::getUser)
//                .map(user -> {
//                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
//                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
//                })
//                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
//                        "Refresh token is not in database!"));
//    }
//}