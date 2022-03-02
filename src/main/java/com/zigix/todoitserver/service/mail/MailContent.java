package com.zigix.todoitserver.service.mail;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MailContent {
    private String recipient;
    private String subject;
    private String text;
}
