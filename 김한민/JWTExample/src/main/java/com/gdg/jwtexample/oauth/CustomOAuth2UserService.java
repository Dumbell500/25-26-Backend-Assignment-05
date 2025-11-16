package com.gdg.jwtexample.oauth;

import com.gdg.jwtexample.domain.AuthProvider;
import com.gdg.jwtexample.domain.User;
import com.gdg.jwtexample.domain.UserRole;
import com.gdg.jwtexample.repository.UserRepository;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)
            throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId(); // "google"
        if (!"google".equals(registrationId)) {
            throw new OAuth2AuthenticationException("지원하지 않는 OAuth2 Provider 입니다: " + registrationId);
        }

        Map<String, Object> attributes = oAuth2User.getAttributes();

        String providerId = (String) attributes.get("sub");     // 구글 고유 ID
        String email = (String) attributes.get("email");
        String name = (String) attributes.getOrDefault("name", email);

        // 1) providerId 로 먼저 조회
        User user = userRepository.findByProviderId(providerId)
                .orElseGet(() ->
                        // 2) 없으면 새로 생성
                        createGoogleUser(providerId, email, name)
                );

        List<? extends GrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority(user.getRole().name()));

        // nameAttributeKey 를 "email" 로 두면 SecurityContext 의 principal name 이 이메일이 됨
        return new DefaultOAuth2User(authorities, attributes, "email");
    }

    private User createGoogleUser(String providerId, String email, String name) {
        User user = User.builder()
                .email(email)
                .password("GOOGLE_USER") // 실제 로그인에는 사용되지 않는 더미 값
                .role(UserRole.ROLE_USER)
                .provider(AuthProvider.GOOGLE)
                .providerId(providerId)
                .name(name)
                .build();

        return userRepository.save(user);
    }
}
