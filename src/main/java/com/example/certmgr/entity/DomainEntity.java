package com.example.certmgr.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

/**
 * 域名实体：系统中被监控的域名对象。
 *
 * <p>除基础信息（域名、端口、备注）外，还缓存“最近一次检测到的证书状态”
 * 字段（certStatus / certExpiryAt / certDaysLeft 等），便于列表页与预警
 * 直接读取，而无需每次实时连网探测。</p>
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "domain", uniqueConstraints = @UniqueConstraint(columnNames = "name"))
public class DomainEntity {

    /** 主键 ID，自增 */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 域名（如 www.example.com），全局唯一 */
    @Column(nullable = false, unique = true, length = 255)
    private String name;

    /** 证书探测端口，默认 443 */
    @Column(nullable = false)
    private Integer port = 443;

    /** 备注说明，可为空 */
    @Column(length = 500)
    private String description;

    // ===================== 缓存的证书检测状态 =====================

    /** 证书整体状态：OK / EXPIRING / EXPIRED / NONE / ERROR */
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private CertStatus certStatus;

    /** 当前生效证书的到期时间 */
    private LocalDateTime certExpiryAt;

    /** 当前生效证书的签发者（CA 名称） */
    @Column(length = 255)
    private String certIssuer;

    /** 当前生效证书的主域名（CN） */
    @Column(length = 255)
    private String certCommonName;

    /** 距离过期剩余天数（ >=0 表示未过期，负数表示已过期） */
    private Integer certDaysLeft;

    /** 最近一次检测时间 */
    private LocalDateTime lastCheckAt;

    /** 最近一次检测错误信息；无错误则为 null */
    @Column(length = 1000)
    private String lastError;

    // ===================== 缓存的域名注册(Whois)信息 =====================

    /** 域名注册商（来自 Whois） */
    @Column(length = 255)
    private String whoisRegistrar;

    /** 域名注册（创建）时间（原始字符串，如 2000-01-01T00:00:00Z） */
    @Column(length = 100)
    private String whoisCreationDate;

    /** 域名过期(注册到期)时间（原始字符串，如 2030-01-01T00:00:00Z） */
    @Column(length = 100)
    private String whoisExpiryDate;

    // ===================== 审计字段 =====================

    /** 创建时间（插入时自动写入，不可更新） */
    @CreationTimestamp
    @Column(updatable = false)
    private LocalDateTime createdAt;

    /** 更新时间（每次更新自动刷新） */
    @UpdateTimestamp
    private LocalDateTime updatedAt;
}
