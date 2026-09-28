package com.example.certmgr.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 自定义业务配置。
 *
 * <p>供检测服务、ACME 签发、邮件预警等组件注入使用。</p>
 */
@Component
@ConfigurationProperties(prefix = "cert")
@Data
public class CertProperties {

    /** 证书检测相关配置 */
    private Check check = new Check();

    /** 邮件预警相关配置 */
    private Mail mail = new Mail();

    /** ACME 自动签发相关配置 */
    private Acme acme = new Acme();

    /** 检测配置 */
    @Data
    public static class Check {
        /** SSL 连接与读取超时（毫秒） */
        private int timeoutMs = 5000;
        /** 剩余天数阈值：<= 该值视为即将过期 */
        private int alertDays = 30;
        /** 定时检测 Cron 表达式（默认每日凌晨 2 点） */
        private String schedulerCron = "0 0 2 * * ?";
    }

    /** 邮件配置 */
    @Data
    public static class Mail {
        /** 是否真正发送邮件（关闭时仅站内提示） */
        private boolean enabled = false;
        /** 发件人 */
        private String from = "cert-manager@company.com";
        /** 收件人 */
        private String to = "admin@company.com";
    }

    /** ACME 配置 */
    @Data
    public static class Acme {
        /** ACME 目录地址（Let's Encrypt 生产/测试） */
        private String serverUrl = "https://acme-v02.api.letsencrypt.org/directory";
        /** ACME 账户联系邮箱 */
        private String contactEmail = "admin@company.com";
        /** 挑战类型：HTTP-01 或 DNS-01 */
        private String challenge = "HTTP-01";
        /** HTTP-01 验证文件存放根目录 */
        private String webroot = "./acme-challenges";
        /** 到期前多少天开始自动续签 */
        private int renewBeforeDays = 30;
        /** 是否自动部署到 Spring Boot 内置 HTTPS 的 PKCS12 文件 */
        private boolean deployToEmbeddedHttps = false;
        /** 仅此域名的证书可替换当前 HTTPS 密钥库 */
        private String deployDomain;
        /** Spring Boot 的 server.ssl.key-store 指向的同一文件 */
        private String keystorePath = "./data/https.p12";
        /** 从环境变量注入，禁止提交真实密码 */
        private String keystorePassword;
    }
}
