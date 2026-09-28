package com.example.certmgr.dto;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 证书元信息数据传输对象。
 * 用于承载从 X509 证书中解析出的结构化字段，
 * 既服务于远程探测结果，也用于上传证书时的解析。
 */
@Data
public class CertInfo {

    /** 主域名（CN） */
    private String commonName;

    /** 适用域名列表（SAN） */
    private List<String> sanDomains;

    /** 签发者（CA 名称） */
    private String issuer;

    /** 证书生效时间 */
    private LocalDateTime notBefore;

    /** 证书到期时间 */
    private LocalDateTime notAfter;

    /** 序列号（十六进制） */
    private String serialNumber;

    /** 签名算法，如 SHA256withRSA */
    private String signatureAlgorithm;

    /** 公钥算法与长度，如 RSA 2048 */
    private String publicKeyAlgorithm;
}
