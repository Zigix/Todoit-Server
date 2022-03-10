package com.zigix.todoitserver.domain.mapper;

import com.zigix.todoitserver.domain.dto.RegisterUserRequest;
import com.zigix.todoitserver.domain.dto.UserView;
import com.zigix.todoitserver.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserMapper {
    private final PasswordEncoder passwordEncoder;

    public User mapToUser(RegisterUserRequest request) {
        return User.builder()
                .email(request.getEmail())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .enabled(false)
                .build();
    }

    public UserView mapToUserView(User user) {
        return UserView.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .createdDate(user.getCreatedDate())
                .lastModifiedDate(user.getLastModifiedDate())
                .enabled(user.isEnabled())
                .build();
    }
}
