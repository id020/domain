package com.example.certmgr.dto;

import com.example.certmgr.entity.CertStatus;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 域名证书检测结果对象。
 * 由 {@code SslCheckService} 执行一次远程探测后返回，
 * 包含连通性、证书元信息、剩余天数与整体状态。
 */
@Data
public class DomainCheckResult {

    /** 被检测的域名 */
    private String host;

    /** 探测端口 */
    private int port;

    /** 是否连通（TCP + TLS 握手成功） */
    private boolean reachable;

    /** 是否获取到证书 */
    private boolean certPresent;

    /** 解析出的证书元信息（无证书则为 null） */
    private CertInfo certInfo;

    /** 距离过期剩余天数（>=0 未过期，<0 已过期） */
    private int daysLeft;

    /** 综合状态：OK / EXPIRING / EXPIRED / NONE / ERROR */
    private CertStatus status;

    /** 错误信息（无错误则为 null） */
    private String error;

    /** 检测发生时间 */
    private LocalDateTime checkTime;
}
