package com.example.certmgr.controller;

import com.example.certmgr.entity.CertificateEntity;
import com.example.certmgr.service.CertificateService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 证书管理控制器：列表、上传、ACME 签发、详情、下载与删除。
 *
 * <p>类级别要求 {@code PERM_CERT_VIEW}，写/签/删操作进一步要求相应细粒度权限。</p>
 */
@Controller
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('PERM_CERT_VIEW')")
public class CertificateController {

    /** 证书业务服务 */
    private final CertificateService certificateService;

    private final com.example.certmgr.service.CertificateRenewalService renewalService;

    /**
     * 证书列表页。
     */
    @GetMapping("/certificates")
    public String list(Model model) {
        model.addAttribute("pageTitle", "证书管理");
        model.addAttribute("certificates", certificateService.list());
        return "certificates/list";
    }

    /**
     * 上传表单页。
     */
    @GetMapping("/certificates/new")
    public String newForm(Model model) {
        model.addAttribute("pageTitle", "上传证书");
        model.addAttribute("isNew", true);
        return "certificates/form";
    }

    /**
     * 处理证书上传（PEM 文本）。
     */
    @PostMapping("/certificates/upload")
    @PreAuthorize("hasAuthority('PERM_CERT_EDIT')")
    public String upload(@RequestParam String name,
                         @RequestParam String domainName,
                         @RequestParam String certPem,
                         @RequestParam(required = false) String privateKeyPem,
                         RedirectAttributes ra) {
        try {
            certificateService.upload(name, domainName, certPem, privateKeyPem);
            ra.addFlashAttribute("success", "证书已上传入库");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/certificates";
    }

    /**
     * ACME 签发表单页。
     */
    @GetMapping("/certificates/issue")
    @PreAuthorize("hasAuthority('PERM_CERT_ISSUE')")
    public String issueForm(Model model) {
        model.addAttribute("pageTitle", "ACME 签发");
        return "certificates/issue";
    }

    /**
     * 处理 ACME 签发。
     */
    @PostMapping("/certificates/issue")
    @PreAuthorize("hasAuthority('PERM_CERT_ISSUE')")
    public String issue(@RequestParam String domainName,
                        @RequestParam(required = false) String sans,
                        @RequestParam(defaultValue = "false") boolean autoRenew,
                        RedirectAttributes ra) {
        try {
            List<String> sanList = (sans == null || sans.isBlank())
                    ? List.of()
                    : Arrays.stream(sans.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList());
            certificateService.issue(domainName, sanList, autoRenew);
            ra.addFlashAttribute("success", "ACME 签发完成，证书已入库");
        } catch (Exception e) {
            ra.addFlashAttribute("error", "签发失败: " + e.getMessage());
        }
        return "redirect:/certificates";
    }

    /**
     * 证书详情页。
     */
    @GetMapping("/certificates/{id}")
    public String detail(@PathVariable Long id, Model model) {
        CertificateEntity cert = certificateService.get(id);
        model.addAttribute("pageTitle", "证书详情 - " + cert.getName());
        model.addAttribute("cert", cert);
        return "certificates/detail";
    }

    /**
     * 下载证书 PEM 文件。
     */
    @GetMapping("/certificates/{id}/download")
    public ResponseEntity<Resource> download(@PathVariable Long id) throws UnsupportedEncodingException {
        CertificateEntity cert = certificateService.get(id);
        byte[] data = cert.getCertPem().getBytes(StandardCharsets.UTF_8);
        ByteArrayResource resource = new ByteArrayResource(data);
        // 清理文件名，避免响应头注入
        String safeName = cert.getName().replaceAll("[^a-zA-Z0-9._-]", "_") + ".crt";
        String disposition = "attachment; filename=\"" + safeName + "\"; "
                + "filename*=UTF-8''" + URLEncoder.encode(safeName, StandardCharsets.UTF_8.name());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition)
                .contentType(MediaType.TEXT_PLAIN)
                .body(resource);
    }

    /** 手动触发续签，沿用现有签发权限。 */
    @PostMapping("/certificates/{id}/renew")
    @PreAuthorize("hasAuthority('PERM_CERT_ISSUE')")
    public String renew(@PathVariable Long id, RedirectAttributes ra) {
        try {
            renewalService.renew(id);
            ra.addFlashAttribute("success", "续签成功。若部署到内置 HTTPS，请重启应用加载新证书。");
        } catch (Exception e) {
            ra.addFlashAttribute("error", "续签失败：" + e.getMessage());
        }
        return "redirect:/certificates/" + id;
    }

    /**
     * 删除证书。
     */
    @PostMapping("/certificates/{id}/delete")
    @PreAuthorize("hasAuthority('PERM_CERT_DELETE')")
    public String delete(@PathVariable Long id, RedirectAttributes ra) {
        certificateService.delete(id);
        ra.addFlashAttribute("success", "证书已删除");
        return "redirect:/certificates";
    }
}
