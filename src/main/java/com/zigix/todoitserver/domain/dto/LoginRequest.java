package com.zigix.todoitserver.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {
    @NotBlank(message = "Username field cannot be blank")
    private String username;
    @NotBlank(message = "Password field cannot be blank")
    private String password;
}
