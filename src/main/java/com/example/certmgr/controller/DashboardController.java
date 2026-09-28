package com.example.certmgr.controller;

import com.example.certmgr.entity.CertStatus;
import com.example.certmgr.entity.CertificateEntity;
import com.example.certmgr.entity.DomainEntity;
import com.example.certmgr.service.AlertService;
import com.example.certmgr.service.CertificateService;
import com.example.certmgr.service.DomainService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;

/**
 * 仪表盘控制器：系统首页，汇总关键统计与预警信息。
 *
 * <p>要求 {@code PERM_DASHBOARD_VIEW} 权限，未授权访问返回 403。</p>
 */
@Controller
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('PERM_DASHBOARD_VIEW')")
public class DashboardController {

    /** 域名业务服务 */
    private final DomainService domainService;

    /** 证书业务服务 */
    private final CertificateService certificateService;

    /** 预警服务 */
    private final AlertService alertService;

    /**
     * 首页仪表盘。
     *
     * @param model 视图模型
     * @return 仪表盘视图名
     */
    @GetMapping("/")
    public String dashboard(Model model) {
        List<DomainEntity> domains = domainService.list();
        List<CertificateEntity> certs = certificateService.list();

        long expired = 0;
        long expiring = 0;
        long errorNone = 0;

        for (DomainEntity domain : domains) {
            CertStatus status = domain.getCertStatus();

            if (status == CertStatus.EXPIRED) {
                expired++;
            } else if (status == CertStatus.EXPIRING) {
                expiring++;
            } else if (status == CertStatus.ERROR || status == CertStatus.NONE) {
                errorNone++;
            }
        }

        model.addAttribute("pageTitle", "仪表盘");
        model.addAttribute("totalDomains", domains.size());
        model.addAttribute("expiredCount", expired);
        model.addAttribute("expiringCount", expiring);
        model.addAttribute("errorNoneCount", errorNone);
        model.addAttribute("totalCerts", certs.size());
        model.addAttribute("domains", domains);
        model.addAttribute("alertDomains", alertService.expiringDomains());
        model.addAttribute("alertCerts", alertService.expiringCertificates());
        return "dashboard";
    }
}
