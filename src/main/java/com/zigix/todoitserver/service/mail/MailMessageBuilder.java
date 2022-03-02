package com.zigix.todoitserver.service.mail;

import lombok.RequiredArgsConstructor;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@RequiredArgsConstructor
public class MailMessageBuilder {
    private final TemplateEngine engine;

    public String getRegistrationMailContent(String name, String confirmationLink) {
        Context context = new Context();
        context.setVariable("name", name);
        context.setVariable("confirmationLink", confirmationLink);
        return engine.process("confirm-registration-template", context);
    }
}
