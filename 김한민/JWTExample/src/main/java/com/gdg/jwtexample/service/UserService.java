package com.gdg.jwtexample.service;

import com.gdg.jwtexample.domain.User;
import com.gdg.jwtexample.dto.user.UserMeResponse;
import com.gdg.jwtexample.repository.UserRepository;
import java.util.NoSuchElementException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;

    public UserMeResponse getMe(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new NoSuchElementException("사용자를 찾을 수 없습니다."));
        return UserMeResponse.from(user);
    }
}
