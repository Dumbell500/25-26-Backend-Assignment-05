package com.gdg.jwtexample.repository;

import com.gdg.jwtexample.domain.AuthProvider;
import com.gdg.jwtexample.domain.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);

    // 구글 로그인용
    Optional<User> findByProviderId(String providerId);

    Optional<User> findByEmailAndProvider(String email, AuthProvider provider);
}
