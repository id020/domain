package com.example.certmgr.entity;

/**
 * 证书库中单张证书的存储状态枚举。
 * <ul>
 *   <li>VALID —— 有效（当前未过期）</li>
 *   <li>EXPIRED —— 已过期</li>
 *   <li>REVOKED —— 已被吊销</li>
 * </ul>
 */
public enum CertificateStatus {
    VALID,
    EXPIRED,
    REVOKED
}
