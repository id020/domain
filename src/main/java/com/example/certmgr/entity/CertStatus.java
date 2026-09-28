package com.example.certmgr.entity;

/**
 * 域名证书整体状态枚举。
 * <ul>
 *   <li>OK —— 证书有效且剩余天数充足</li>
 *   <li>EXPIRING —— 即将过期（剩余天数低于阈值）</li>
 *   <li>EXPIRED —— 证书已过期</li>
 *   <li>NONE —— 未检测到证书（如端口未提供 SSL）</li>
 *   <li>ERROR —— 检测过程出错（连接超时、拒绝等）</li>
 * </ul>
 */
public enum CertStatus {
    OK,
    EXPIRING,
    EXPIRED,
    NONE,
    ERROR
}
