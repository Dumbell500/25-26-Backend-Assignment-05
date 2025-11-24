package com.gdg.jwtexample.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA용 기본 생성자는 보호
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 기본 로그인 ID (구글 로그인도 동일 이메일 사용)
    @Column(nullable = false, unique = true, length = 120)
    private String email;

    // LOCAL 계정만 사용, 소셜 계정은 null 허용
    @Column(length = 200)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UserRole role; // ROLE_USER, ROLE_ADMIN

    // 추가: 어떤 방식으로 가입했는지
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AuthProvider provider;

    // 추가: 구글의 고유 ID(sub). LOCAL 은 null 가능
    @Column(length = 100, unique = true)
    private String providerId;

    // 추가: 사용자 이름(닉네임)
    @Column(nullable = false, length = 50)
    private String name;

    @Builder
    public User(String email,
                String password,
                UserRole role,
                AuthProvider provider,
                String providerId,
                String name) {
        this.email = email;
        this.password = password;
        this.role = role;
        this.provider = provider;
        this.providerId = providerId;
        this.name = name;
    }
}
