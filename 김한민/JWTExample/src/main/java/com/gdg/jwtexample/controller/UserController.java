package com.gdg.jwtexample.controller;

import com.gdg.jwtexample.dto.user.UserMeResponse;
import com.gdg.jwtexample.service.UserService;
import java.security.Principal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<UserMeResponse> me(Principal principal) {
        return ResponseEntity.ok(userService.getMe(principal.getName()));
    }
}
