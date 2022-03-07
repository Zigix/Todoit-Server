package com.zigix.todoitserver.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserView {
    private Long id;
    private String email;
    private String username;
    private LocalDateTime createdDate;
    private LocalDateTime lastModifiedDate;
    private boolean enabled;
}
