package com.zigix.todoitserver.domain.mapper;

import com.zigix.todoitserver.domain.dto.RegisterUserRequest;
import com.zigix.todoitserver.domain.dto.UserView;
import com.zigix.todoitserver.domain.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.LocalDateTime;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@ExtendWith(SpringExtension.class)
class UserMapperTest {
    private UserMapper systemUnderTest;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @BeforeEach
    void setUp() {
        systemUnderTest = new UserMapper(passwordEncoder);
    }

    @Test
    void should_mapRegisterUserRequest_to_userEntity() {
        // given
        RegisterUserRequest request = new RegisterUserRequest(
                "john@example.com",
                "john",
                "12345678",
                "12345678"
        );

        // when
        User expected = systemUnderTest.mapToUser(request);

        // then
        assertThat(expected.getId()).isNull();
        assertThat(expected.getEmail()).isEqualTo(request.getEmail());
        assertThat(expected.getUsername()).isEqualTo(request.getUsername());
        assertThat(passwordEncoder.matches(request.getPassword(), expected.getPassword())).isTrue();
        assertThat(expected.getCreatedDate()).isNull();
        assertThat(expected.getLastModifiedDate()).isNull();
        assertThat(expected.isEnabled()).isFalse();
    }

    @Test
    void should_mapUserEntity_to_userView() {
        // given
        User user = new User(
                1L,
                "john@example.com",
                "john",
                passwordEncoder.encode("12345678"),
                LocalDateTime.parse("2015-12-03T10:15:35"),
                LocalDateTime.parse("2015-12-03T10:15:35"),
                true
        );

        // when
        UserView expected = systemUnderTest.mapToUserView(user);

        // then
        assertThat(expected.getId()).isEqualTo(user.getId());
        assertThat(expected.getEmail()).isEqualTo(user.getEmail());
        assertThat(expected.getUsername()).isEqualTo(user.getUsername());
        assertThat(expected.getCreatedDate()).isEqualTo(user.getCreatedDate());
        assertThat(expected.getLastModifiedDate()).isEqualTo(user.getLastModifiedDate());
        assertThat(expected.isEnabled()).isEqualTo(user.isEnabled());
    }
}