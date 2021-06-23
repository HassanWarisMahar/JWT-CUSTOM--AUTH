//package com.example.jwt.security.jwt;
//
//import com.example.jwt.security.services.UserDetailsServiceImpl;
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.ExpiredJwtException;
//import io.jsonwebtoken.JwtException;
//import io.jsonwebtoken.Jwts;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.web.filter.OncePerRequestFilter;
//import org.springframework.web.util.WebUtils;
//
//import javax.servlet.FilterChain;
//import javax.servlet.ServletException;
//import javax.servlet.http.Cookie;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//import java.util.Arrays;
//import java.util.Collection;
//import java.util.stream.Collectors;
//
//public class JwtAuthFilter extends OncePerRequestFilter {
//    @Autowired
//    private JwtUtils jwtUtils;
//    @Autowired
//    private UserDetailsServiceImpl userDetailsService;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//        Cookie cookie = WebUtils.getCookie(request, "token");
//        try {
//
//            String jwt = cookie.getValue();
//            System.out.print("JWT" + jwt);
//            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
//
//                String username = jwtUtils.getUserNameFromJwtToken(jwt);
//
//                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
//                        userDetails, null, userDetails.getAuthorities());
//                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                SecurityContextHolder.getContext().setAuthentication(authentication);
//            }
//        } catch (Exception e) {
//            logger.error("Cannot set user authentication: {}", e);
//        }
//        filterChain.doFilter(request, response);
//    }
//
//    private UsernamePasswordAuthenticationToken getAuthentication(String token) {
//        if (token != null) {
//            // parse the token
//            Claims claims = Jwts.parser()
//                    .setSigningKey(System.getenv("SECRET_KEY"))
//                    .parseClaimsJws(token)
//                    .getBody();
//            String user = claims.getSubject();
//
//            // authorities are transmitted as a comma-delimited string like "USER,ADMIN,SUPERUSER"
//            String authorityString = (String) claims.get("authorities");
//            Collection<? extends GrantedAuthority> authorities;
//            if (!authorityString.isEmpty()) {
//                authorities = Arrays.asList(authorityString.split(",")).stream()
//                        .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
//            } else {
//                authorities = null;
//            }
//
//            if (user != null) {
//                return new UsernamePasswordAuthenticationToken(user, null, authorities);
//            }
//            return null;
//        }
//        return null;
//    }
//}