package com.zigix.todoitserver.service;

import com.zigix.todoitserver.domain.model.User;
import com.zigix.todoitserver.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.times;

@ExtendWith(SpringExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository mockUserRepository;

    @InjectMocks
    private UserServiceImpl systemUnderTest;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Test
    void should_throwUsernameNotFoundException_when_noUserWithPassedUsername() {
        // given
        given(mockUserRepository.findByUsername(anyString()))
                .willReturn(Optional.empty());

        // when
        Throwable thrown = catchThrowable(() -> systemUnderTest.loadUserByUsername("john"));

        // then
        then(mockUserRepository)
                .should(times(1))
                .findByUsername("john");

        assertThat(thrown)
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void should_returnUserDetails_when_passedUsernameIsCorrect() {
        // given
        User testUser = new User(
                1L,
                "john@example.com",
                "john",
                passwordEncoder.encode("12345678"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                LocalDateTime.parse("2007-12-03T10:15:30"),
                true
        );
        given(mockUserRepository.findByUsername(anyString()))
                .willReturn(Optional.of(testUser));

        // when
        UserDetails expected = systemUnderTest.loadUserByUsername(anyString());

        // then
        then(mockUserRepository)
                .should(times(1))
                .findByUsername(anyString());

        assertThat(expected).isEqualTo(testUser);
    }
}