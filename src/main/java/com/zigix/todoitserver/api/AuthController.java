package com.zigix.todoitserver.api;

import com.zigix.todoitserver.domain.dto.AccessTokensResponse;
import com.zigix.todoitserver.domain.dto.AuthenticationResponse;
import com.zigix.todoitserver.domain.dto.LoginRequest;
import com.zigix.todoitserver.domain.dto.RegisterUserRequest;
import com.zigix.todoitserver.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/sign-up")
    public ResponseEntity<Void> signUp(@RequestBody @Valid RegisterUserRequest request) {
        authService.signUp(request);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyToken(@RequestParam("token") String token) {
        authService.verifyToken(token);
        return ResponseEntity.ok("Account activated");
    }

    @GetMapping("/refresh-token")
    public ResponseEntity<AccessTokensResponse> refreshToken(HttpServletRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }
}
