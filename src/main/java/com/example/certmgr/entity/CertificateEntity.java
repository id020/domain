package com.example.certmgr.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

/**
 * 证书实体：证书库中保存的每一张证书记录。
 *
 * <p>支持两种来源：
 * <ul>
 *   <li>手动上传（UPLOADED）：用户上传 PEM 证书链与私钥，系统解析元信息后入库；</li>
 *   <li>ACME 自动签发（ACME_ISSUED）：系统通过 Let's Encrypt 自动申请并保存。</li>
 * </ul>
 * 私钥 {@code privateKeyPem} 属敏感信息，本系统面向内网，直接以文本存储；
 * 若需更强安全，可改为加密存储或仅保存证书不保存私钥。</p>
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "certificate")
public class CertificateEntity {

    /** 主键 ID，自增 */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 证书别名，便于在列表中识别 */
    @Column(nullable = false, length = 255)
    private String name;

    /** 主域名（CN） */
    @Column(length = 255)
    private String commonName;

    /** 适用域名列表（SAN），多个以逗号分隔 */
    @Column(length = 2000)
    private String sanDomains;

    /** 来源类型：UPLOADED / ACME_ISSUED */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CertificateType type;

    /** 证书 PEM 文本（含完整链） */
    @Column(columnDefinition = "TEXT")
    private String certPem;

    /** 私钥 PEM 文本（敏感） */
    @Column(columnDefinition = "TEXT")
    private String privateKeyPem;

    /** 证书生效时间（notBefore） */
    private LocalDateTime notBefore;

    /** 证书到期时间（notAfter） */
    private LocalDateTime notAfter;

    /** 签发者（CA 名称） */
    @Column(length = 255)
    private String issuer;

    /** 证书序列号（十六进制） */
    @Column(length = 255)
    private String serialNumber;

    /** 签名算法，如 SHA256withRSA */
    @Column(length = 100)
    private String signatureAlgorithm;

    /** 公钥算法与长度，如 RSA 2048 */
    @Column(length = 100)
    private String publicKeyAlgorithm;

    /** 证书状态：VALID / EXPIRED / REVOKED */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private CertificateStatus status = CertificateStatus.VALID;

    /** 是否开启自动续期（ACME 签发时有效） */
    private Boolean autoRenew = false;

    /** 关联管理的域名（字符串，便于匹配多域名 SAN） */
    @Column(length = 255)
    private String domainName;

    /** 创建时间（插入时自动写入） */
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    /** 更新时间（每次更新自动刷新） */
    @UpdateTimestamp
    private LocalDateTime updatedAt;
}
