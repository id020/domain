package com.example.certmgr.entity;

/**
 * 证书来源类型枚举。
 * <ul>
 *   <li>UPLOADED —— 用户手动上传的证书文件（PEM + 私钥）</li>
 *   <li>ACME_ISSUED —— 通过 ACME 协议（Let's Encrypt）自动签发</li>
 * </ul>
 */
public enum CertificateType {
    UPLOADED,
    ACME_ISSUED
}
