package com.example.certmgr.controller;

import com.example.certmgr.dto.DomainCheckResult;
import com.example.certmgr.entity.CertStatus;
import com.example.certmgr.entity.DomainEntity;
import com.example.certmgr.service.DomainService;
import com.example.certmgr.service.WhoisService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * 域名管理控制器：列表、新增/编辑、详情（含 DNS/Whois 信息）、检测与删除。
 *
 * <p>类级别要求 {@code PERM_DOMAIN_VIEW}，写操作（新增/编辑/检测/删除/刷新 Whois）
 * 进一步要求 {@code PERM_DOMAIN_EDIT} / {@code PERM_DOMAIN_DELETE}，由方法级注解约束。</p>
 */
@Controller
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('PERM_DOMAIN_VIEW')")
public class DomainController {

    /** 域名业务服务 */
    private final DomainService domainService;

    /** Whois 查询服务 */
    private final WhoisService whoisService;

    /**
     * 域名列表页。
     */
    @GetMapping("/domains")
    public String list(Model model) {
        model.addAttribute("pageTitle", "域名管理");
        model.addAttribute("domains", domainService.list());
        return "domains/list";
    }

    /**
     * 新增表单页。
     */
    @GetMapping("/domains/new")
    public String newForm(Model model) {
        model.addAttribute("pageTitle", "新增域名");
        model.addAttribute("domain", new DomainEntity());
        model.addAttribute("isNew", true);
        return "domains/form";
    }

    /**
     * 创建域名。
     */
    @PostMapping("/domains")
    @PreAuthorize("hasAuthority('PERM_DOMAIN_EDIT')")
    public String create(@ModelAttribute DomainEntity domain, RedirectAttributes ra) {
        if (domain.getName() == null || domain.getName().isBlank()) {
            ra.addFlashAttribute("error", "域名不能为空");
            return "redirect:/domains/new";
        }
        if (domain.getPort() == null || domain.getPort() < 1 || domain.getPort() > 65535) {
            domain.setPort(443);
        }
        if (domainService.exists(domain.getName())) {
            ra.addFlashAttribute("error", "域名已存在: " + domain.getName());
            return "redirect:/domains/new";
        }
        domainService.save(domain);
        // 新增后立即拉取 Whois 注册信息，使列表可展示域名过期时间与注册商
        domainService.refreshWhois(domain.getId());
        ra.addFlashAttribute("success", "域名已添加");
        return "redirect:/domains";
    }

    /**
     * 编辑表单页。
     */
    @GetMapping("/domains/{id}/edit")
    public String editForm(@PathVariable Long id, Model model) {
        model.addAttribute("pageTitle", "编辑域名");
        model.addAttribute("domain", domainService.get(id));
        model.addAttribute("isNew", false);
        return "domains/form";
    }

    /**
     * 更新域名。
     */
    @PostMapping("/domains/{id}")
    @PreAuthorize("hasAuthority('PERM_DOMAIN_EDIT')")
    public String update(@PathVariable Long id, @ModelAttribute DomainEntity domain,
                         RedirectAttributes ra) {
        DomainEntity existing = domainService.get(id);
        existing.setName(domain.getName());
        existing.setPort(domain.getPort() == null ? 443 : domain.getPort());
        existing.setDescription(domain.getDescription());
        // 同步手动补录的 Whois 注册信息（注册商 / 注册时间 / 域名过期时间）
        existing.setWhoisRegistrar(domain.getWhoisRegistrar());
        existing.setWhoisCreationDate(domain.getWhoisCreationDate());
        existing.setWhoisExpiryDate(domain.getWhoisExpiryDate());
        domainService.save(existing);
        ra.addFlashAttribute("success", "域名已更新");
        return "redirect:/domains/" + id;
    }

    /**
     * 域名详情页（含 DNS 与 Whois 信息）。
     */
    @GetMapping("/domains/{id}")
    public String detail(@PathVariable Long id, Model model) {
        DomainEntity domain = domainService.get(id);
        model.addAttribute("pageTitle", "域名详情 - " + domain.getName());
        model.addAttribute("domain", domain);
        model.addAttribute("whois", whoisService.query(domain.getName()));
        return "domains/detail";
    }

    /**
     * 手动触发检测。
     */
    @PostMapping("/domains/{id}/check")
    @PreAuthorize("hasAuthority('PERM_DOMAIN_EDIT')")
    public String check(@PathVariable Long id, RedirectAttributes ra) {
        DomainCheckResult result = domainService.checkNow(id);
        if (result.getStatus() == CertStatus.ERROR) {
            ra.addFlashAttribute("error", "检测失败: " + result.getError());
        } else {
            ra.addFlashAttribute("success", "检测完成，剩余 " + result.getDaysLeft() + " 天");
        }
        return "redirect:/domains/" + id;
    }

    /**
     * 刷新域名的 Whois 注册信息（环境可连通 43 端口时生效，否则保留原值）。
     */
    @PostMapping("/domains/{id}/refresh-whois")
    @PreAuthorize("hasAuthority('PERM_DOMAIN_EDIT')")
    public String refreshWhois(@PathVariable Long id, RedirectAttributes ra) {
        com.example.certmgr.dto.WhoisResult result = domainService.refreshWhois(id);
        if (result.getError() != null) {
            ra.addFlashAttribute("error", "WHOIS 查询失败：" + result.getError());
        } else {
            ra.addFlashAttribute("success", "注册信息已更新（来源：" + result.getSource() + "）");
        }
        return "redirect:/domains/" + id;
    }

    /**
     * 删除域名。
     */
    @PostMapping("/domains/{id}/delete")
    @PreAuthorize("hasAuthority('PERM_DOMAIN_DELETE')")
    public String delete(@PathVariable Long id, RedirectAttributes ra) {
        domainService.delete(id);
        ra.addFlashAttribute("success", "域名已删除");
        return "redirect:/domains";
    }
}
