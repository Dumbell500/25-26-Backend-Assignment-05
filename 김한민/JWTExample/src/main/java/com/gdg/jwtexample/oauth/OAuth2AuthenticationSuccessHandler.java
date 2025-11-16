package com.gdg.jwtexample.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gdg.jwtexample.domain.RefreshToken;
import com.gdg.jwtexample.domain.User;
import com.gdg.jwtexample.jwt.JwtTokenProvider;
import com.gdg.jwtexample.repository.RefreshTokenRepository;
import com.gdg.jwtexample.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.NoSuchElementException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = (String) oAuth2User.getAttributes().get("email");

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new NoSuchElementException("사용자를 찾을 수 없습니다."));

        // JWT 발급
        String access = tokenProvider.createAccessToken(user.getEmail(), user.getRole());
        String refresh = tokenProvider.createRefreshToken(user.getEmail());

        long refreshExpireMillis = tokenProvider.getRefreshValidityMs();
        Instant refreshExpireAt = Instant.now().plusMillis(refreshExpireMillis);

        refreshTokenRepository.findByUser(user)
                .ifPresent(refreshTokenRepository::delete);

        refreshTokenRepository.save(
                new RefreshToken(user, refresh, refreshExpireAt)
        );

        // JSON 응답으로 토큰 반환
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json;charset=UTF-8");

        Map<String, String> body = Map.of(
                "accessToken", access,
                "refreshToken", refresh
        );

        objectMapper.writeValue(response.getWriter(), body);
    }
}
