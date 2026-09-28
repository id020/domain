package com.example.certmgr.service;

import com.example.certmgr.config.CertProperties;
import com.example.certmgr.entity.CertificateEntity;
import com.example.certmgr.entity.CertificateType;
import com.example.certmgr.repository.CertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ACME 自动续签与 Spring Boot 内置 HTTPS 证书部署。
 * 证书写入 PKCS12 文件采用临时文件 + 原子替换，避免覆盖正在使用的文件。
 * 注意：内置 Tomcat 的当前 TLS 配置通常需要重启进程才会重新读取 PKCS12。
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CertificateRenewalService {
    private final CertificateRepository repository;
    private final AcmeService acmeService;
    private final CertProperties properties;
    private final ConcurrentHashMap<Long, Boolean> inProgress = new ConcurrentHashMap<>();

    /** 每天检查自动续签证书；单张失败不会阻塞其他证书。 */
    public void renewDueCertificates() {
        int days = properties.getAcme().getRenewBeforeDays();
        for (CertificateEntity cert : repository.findAll()) {
            if (cert.getType() != CertificateType.ACME_ISSUED
                    || !Boolean.TRUE.equals(cert.getAutoRenew()) || cert.getNotAfter() == null
                    || cert.getNotAfter().isAfter(LocalDateTime.now().plusDays(days))) continue;
            try {
                renew(cert.getId());
            } catch (Exception e) {
                log.error("证书自动续签失败，id={}，domain={}：{}", cert.getId(), cert.getDomainName(), e.getMessage(), e);
            }
        }
    }

    /** 手动或定时续签：加锁避免同一张证书重复下单。 */
    public CertificateEntity renew(Long id) {
        if (inProgress.putIfAbsent(id, true) != null) {
            throw new IllegalStateException("该证书正在续签，请勿重复提交");
        }
        try {
            CertificateEntity old = repository.findById(id)
                    .orElseThrow(() -> new IllegalArgumentException("证书不存在：" + id));
            CertificateEntity renewed = acmeService.renew(old);
            if (properties.getAcme().isDeployToEmbeddedHttps()) {
                deploy(renewed);
            }
            return renewed;
        } finally {
            inProgress.remove(id);
        }
    }

    /**
     * 仅当配置了部署域名时才部署，防止多张证书相互覆盖同一个 HTTPS 密钥库。
     * 部署后需要重启 Spring Boot 应用使内置 HTTPS 加载新证书。
     */
    public void deploy(CertificateEntity cert) {
        CertProperties.Acme cfg = properties.getAcme();
        if (cfg.getDeployDomain() == null || !cfg.getDeployDomain().equalsIgnoreCase(cert.getDomainName())) {
            return;
        }
        if (cfg.getKeystorePassword() == null || cfg.getKeystorePassword().isBlank()) {
            throw new IllegalStateException("请配置 ACME_KEYSTORE_PASSWORD");
        }
        try {
            String key = cert.getPrivateKeyPem().replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
            PrivateKey privateKey = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key)));
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            var parsed = factory.generateCertificates(new ByteArrayInputStream(
                    cert.getCertPem().getBytes(StandardCharsets.UTF_8)));
            List<java.security.cert.Certificate> chain = new ArrayList<>(parsed);
            if (chain.isEmpty()) throw new IllegalStateException("证书链为空");
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            char[] password = cfg.getKeystorePassword().toCharArray();
            store.setKeyEntry("https", privateKey, password, chain.toArray(new java.security.cert.Certificate[0]));
            Path target = Path.of(cfg.getKeystorePath()).toAbsolutePath();
            Files.createDirectories(target.getParent());
            Path tmp = Files.createTempFile(target.getParent(), ".https-", ".p12.tmp");
            try {
                try (OutputStream out = Files.newOutputStream(tmp)) { store.store(out, password); }
                try {
                    Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                    Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally { Files.deleteIfExists(tmp); }
            log.warn("已部署新证书到 {}，请重启 Spring Boot 应用以加载新证书", target);
        } catch (Exception e) {
            throw new IllegalStateException("PKCS12 部署失败（证书已签发入库）：" + e.getMessage(), e);
        }
    }
}
