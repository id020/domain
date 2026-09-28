package com.example.certmgr.service;

import com.example.certmgr.config.CertProperties;
import com.example.certmgr.entity.CertStatus;
import com.example.certmgr.entity.CertificateEntity;
import com.example.certmgr.entity.DomainEntity;
import com.example.certmgr.repository.CertificateRepository;
import com.example.certmgr.repository.DomainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 过期预警服务。
 *
 * <p>汇总即将过期/已过期域名与证书，并在开启邮件时发送预警通知。
 * 邮件发送失败仅记录日志，不影响检测主流程。</p>
 */
@Service
@RequiredArgsConstructor
public class AlertService {

    /** 域名数据访问 */
    private final DomainRepository domainRepo;

    /** 证书数据访问 */
    private final CertificateRepository certRepo;

    /** 自定义配置（阈值、邮件开关） */
    private final CertProperties certProperties;

    /** Spring 邮件发送器（由 spring-boot-starter-mail 自动配置） */
    private final JavaMailSender mailSender;

    /**
     * 获取即将过期或已过期域名列表。
     *
     * @return 域名列表
     */
    public List<DomainEntity> expiringDomains() {
        return domainRepo.findAll().stream()
                .filter(d -> d.getCertStatus() == CertStatus.EXPIRING
                        || d.getCertStatus() == CertStatus.EXPIRED)
                .collect(Collectors.toList());
    }

    /**
     * 获取即将过期或已过期证书列表（按阈值计算）。
     *
     * @return 证书列表
     */
    public List<CertificateEntity> expiringCertificates() {
        LocalDate threshold = LocalDate.now().plusDays(certProperties.getCheck().getAlertDays());
        return certRepo.findAll().stream()
                .filter(c -> c.getNotAfter() != null
                        && !c.getNotAfter().toLocalDate().isAfter(threshold))
                .collect(Collectors.toList());
    }

    /**
     * 若开启邮件预警，则发送一封汇总邮件（无预警项则跳过）。
     * 任何异常仅打印日志，不影响主流程。
     */
    public void sendAlertEmailIfEnabled() {
        if (!certProperties.getMail().isEnabled()) {
            return;
        }
        try {
            List<DomainEntity> domains = expiringDomains();
            List<CertificateEntity> certs = expiringCertificates();
            if (domains.isEmpty() && certs.isEmpty()) {
                return;
            }
            StringBuilder body = new StringBuilder("SSL 证书到期预警：\n\n");
            body.append("即将/已过期域名（").append(domains.size()).append(" 个）：\n");
            for (DomainEntity d : domains) {
                body.append("- ").append(d.getName())
                        .append("  状态=").append(d.getCertStatus())
                        .append("  剩余=").append(d.getCertDaysLeft()).append(" 天\n");
            }
            body.append("\n即将/已过期证书（").append(certs.size()).append(" 个）：\n");
            for (CertificateEntity c : certs) {
                body.append("- ").append(c.getName())
                        .append("  到期=").append(c.getNotAfter()).append("\n");
            }
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setFrom(certProperties.getMail().getFrom());
            msg.setTo(certProperties.getMail().getTo());
            msg.setSubject("【证书预警】SSL 证书即将到期");
            msg.setText(body.toString());
            mailSender.send(msg);
        } catch (Exception e) {
            System.err.println("邮件预警发送失败: " + e.getMessage());
        }
    }
}
