package com.example.jwt.security.services;

import com.example.jwt.models.RefreshToken;
import com.example.jwt.repository.RefreshTokenRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.exceptions.TokenRefreshException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.transaction.Transactional;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;


@RestControllerAdvice
public class RefreshTokeService {

    @Value("${jwtRefreshExpirationMs}")
    private Long jwtRefreshExpirationMS;

    @Autowired
     private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token){

            return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(Long id){

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUser(userRepository.findById(id).get());
        refreshToken.setExpiryDate(Instant.now().plusMillis(jwtRefreshExpirationMS));
        refreshToken.setToken(UUID.randomUUID().toString());

        refreshToken = refreshTokenRepository.save(refreshToken);


        return  refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }

        return token;
    }
    @Transactional
    public int deleteByUserId(Long userId) {
        return refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
    }
}

