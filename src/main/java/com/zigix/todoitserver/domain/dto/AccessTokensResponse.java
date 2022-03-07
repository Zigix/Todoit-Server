package com.zigix.todoitserver.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AccessTokensResponse {
    private String accessToken;
    private String refreshToken;
}
