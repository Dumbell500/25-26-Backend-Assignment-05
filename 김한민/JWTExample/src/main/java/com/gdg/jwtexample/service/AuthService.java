package com.gdg.jwtexample.service;

import com.gdg.jwtexample.domain.AuthProvider;
import com.gdg.jwtexample.domain.RefreshToken;
import com.gdg.jwtexample.domain.User;
import com.gdg.jwtexample.domain.UserRole;
import com.gdg.jwtexample.dto.auto.LoginRequest;
import com.gdg.jwtexample.dto.auto.SignupRequest;
import com.gdg.jwtexample.dto.auto.TokenResponse;
import com.gdg.jwtexample.jwt.JwtTokenProvider;
import com.gdg.jwtexample.repository.RefreshTokenRepository;
import com.gdg.jwtexample.repository.UserRepository;
import java.time.Instant;
import java.util.NoSuchElementException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider tokenProvider;
    private final BCryptPasswordEncoder encoder;

    public AuthService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       JwtTokenProvider tokenProvider,
                       BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenProvider = tokenProvider;
        this.encoder = encoder;
    }

    // 회원가입 - LOCAL 전용 (쓰기 트랜잭션)
    @Transactional
    public void signup(SignupRequest req) {
        if (userRepository.existsByEmail(req.email())) {
            throw new IllegalArgumentException("이미 가입된 이메일입니다.");
        }

        User user = User.builder()
                .email(req.email())
                .password(encoder.encode(req.password()))
                .role(UserRole.ROLE_USER)
                .provider(AuthProvider.LOCAL)
                .providerId(null)          // 로컬 계정은 providerId 없음
                .name(req.email())         // 일단 이메일 기반으로 이름 세팅(원하면 별도 필드 추가)
                .build();

        userRepository.save(user);
    }

    // 로그인 + 토큰 발급 - LOCAL 전용 (쓰기 트랜잭션)
    @Transactional
    public TokenResponse login(LoginRequest req) {
        User user = userRepository.findByEmail(req.email())
                .orElseThrow(() -> new NoSuchElementException("사용자를 찾을 수 없습니다."));

        // 1) 소셜 계정은 여기서 로그인 막기
        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new IllegalArgumentException("소셜 로그인 계정입니다. 구글 로그인을 이용해주세요.");
        }

        // 2) 비밀번호 검증
        if (!encoder.matches(req.password(), user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // Access / Refresh 토큰 발급
        String access = tokenProvider.createAccessToken(user.getEmail(), user.getRole());
        String refresh = tokenProvider.createRefreshToken(user.getEmail());

        long refreshExpireMillis = tokenProvider.getRefreshValidityMs();
        Instant refreshExpireAt = Instant.now().plusMillis(refreshExpireMillis);

        // 기존 리프레시 토큰 있으면 삭제 후 새 토큰 저장
        refreshTokenRepository.findByUser(user)
                .ifPresent(refreshTokenRepository::delete);

        refreshTokenRepository.save(
                new RefreshToken(user, refresh, refreshExpireAt)
        );

        return new TokenResponse(access, refresh);
    }

    // 리프레시 토큰 재발급 - 공통 (쓰기 트랜잭션)
    @Transactional
    public TokenResponse reissue(String refreshToken) {
        if (!tokenProvider.isValid(refreshToken)) {
            throw new IllegalArgumentException("리프레시 토큰이 유효하지 않습니다.");
        }

        String email = tokenProvider.parseClaims(refreshToken).getSubject();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new NoSuchElementException("사용자를 찾을 수 없습니다."));

        RefreshToken saved = refreshTokenRepository.findByUser(user)
                .orElseThrow(() -> new NoSuchElementException("저장된 리프레시 토큰이 없습니다."));

        if (!saved.getToken().equals(refreshToken)) {
            throw new IllegalArgumentException("리프레시 토큰이 일치하지 않습니다.");
        }

        // 새 토큰 발급
        String newAccess = tokenProvider.createAccessToken(user.getEmail(), user.getRole());
        String newRefresh = tokenProvider.createRefreshToken(user.getEmail());

        long refreshExpireMillis = tokenProvider.getRefreshValidityMs();
        Instant newRefreshExpireAt = Instant.now().plusMillis(refreshExpireMillis);

        // 기존 엔티티에 새 토큰/만료시간 반영
        saved.rotate(newRefresh, newRefreshExpireAt);

        return new TokenResponse(newAccess, newRefresh);
    }
}
