package com.zigix.todoitserver.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zigix.todoitserver.config.jwt.JwtTokenUtil;
import com.zigix.todoitserver.domain.dto.AccessTokensResponse;
import com.zigix.todoitserver.domain.dto.AuthenticationResponse;
import com.zigix.todoitserver.domain.dto.LoginRequest;
import com.zigix.todoitserver.domain.mapper.UserMapper;
import com.zigix.todoitserver.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;
    private final UserMapper userMapper;
    private final ObjectMapper objectMapper;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authenticationToken = null;
        try {
            final LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

            authenticationToken = new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
            );
        } catch (IOException e) {
            e.printStackTrace();
        }
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) throws IOException, ServletException {
        User user = (User) authentication.getPrincipal();
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                user,
                null,
                user.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        String accessToken = jwtTokenUtil.generateAccessToken(user);
        String refreshToken = jwtTokenUtil.generateRefreshToken(user);
        AuthenticationResponse authenticationResponse = new AuthenticationResponse(
                userMapper.mapToUserView(user),
                new AccessTokensResponse(accessToken, refreshToken)
        );

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), authenticationResponse);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        objectMapper.writeValue(response.getOutputStream(), failed.getMessage());
    }
}
