package com.zigix.todoitserver.service.mail;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailServiceImpl implements MailService {
    private final JavaMailSender mailSender;

    @Override
    public void sendMail(MailContent mailContent) {
        MimeMessagePreparator messagePreparator = mimeMessage -> {
            MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage);
            messageHelper.setFrom("todoit@example.com");
            messageHelper.setTo(mailContent.getRecipient());
            messageHelper.setSubject(mailContent.getSubject());
            messageHelper.setText(mailContent.getText(), true);
        };
        mailSender.send(messagePreparator);
    }
}
