package com.example.certmgr.scheduler;

import com.example.certmgr.entity.DomainEntity;
import com.example.certmgr.service.AlertService;
import com.example.certmgr.service.DomainService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 定时检测调度器。
 *
 * <p>按配置 Cron（默认每日凌晨 2 点）对所有域名执行一次证书检测，
 * 并随后触发邮件预警（若开启）。单域名检测失败不影响其他域名。</p>
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CheckScheduler {

    /** 域名业务服务 */
    private final DomainService domainService;

    /** 自动续签服务 */
    private final com.example.certmgr.service.CertificateRenewalService renewalService;

    /** 预警服务 */
    private final AlertService alertService;

    /**
     * 定时执行入口。Cron 表达式来自 application.yml 的 cert.check.scheduler-cron。
     */
    @Scheduled(cron = "${cert.check.scheduler-cron:0 0 2 * * ?}")
    public void scheduledCheck() {
        log.info("开始定时检测所有域名证书...");
        for (DomainEntity domain : domainService.list()) {
            try {
                domainService.checkNow(domain.getId());
            } catch (Exception e) {
                log.warn("检测域名 {} 失败: {}", domain.getName(), e.getMessage());
            }
        }
        renewalService.renewDueCertificates();
        alertService.sendAlertEmailIfEnabled();
        log.info("定时检测完成");
    }
}
