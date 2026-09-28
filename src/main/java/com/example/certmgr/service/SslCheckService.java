package com.example.certmgr.service;

import com.example.certmgr.config.CertProperties;
import com.example.certmgr.dto.CertInfo;
import com.example.certmgr.dto.DomainCheckResult;
import com.example.certmgr.entity.CertStatus;
import com.example.certmgr.util.CertParser;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

/**
 * SSL 证书检测服务。
 *
 * <p>通过原生 {@code SSLSocket} 与目标域名建立 TLS 握手，
 * 读取对端证书链并解析叶子证书，计算剩余有效天数与整体状态。
 * 使用“信任全部证书”的上下文，仅读取证书内容，不校验合法性，适合巡检场景。</p>
 */
@Service
public class SslCheckService {

    /** 注入自定义配置（超时、阈值等） */
    private final CertProperties certProperties;

    /** 信任所有证书的 SSLSocketFactory（巡检专用） */
    private SSLSocketFactory trustAllFactory;

    public SslCheckService(CertProperties certProperties) {
        this.certProperties = certProperties;
    }

    /**
     * 初始化信任全部证书的 SSL 上下文。
     * 仅在应用启动时执行一次。
     */
    @PostConstruct
    public void init() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        // 自定义 TrustManager：跳过服务端证书合法性校验
        TrustManager tm = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // 巡检场景不校验客户端
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // 巡检场景不校验服务端，仅读取证书
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        ctx.init(null, new TrustManager[]{tm}, new SecureRandom());
        this.trustAllFactory = ctx.getSocketFactory();
    }

    /**
     * 探测指定域名:端口的证书情况。
     *
     * @param host 域名或 IP
     * @param port 端口（通常 443）
     * @return 检测结果（含状态、剩余天数、错误信息等）
     */
    public DomainCheckResult check(String host, int port) {
        DomainCheckResult result = new DomainCheckResult();
        result.setHost(host);
        result.setPort(port);
        result.setCheckTime(LocalDateTime.now());

        int timeout = certProperties.getCheck().getTimeoutMs();
        int alertDays = certProperties.getCheck().getAlertDays();

        try (SSLSocket socket = (SSLSocket) trustAllFactory.createSocket()) {
            // 建立 TCP 连接并限定超时
            socket.connect(new InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);
            // 设置 SNI，确保多虚拟主机场景取到正确的证书
            SSLParameters params = new SSLParameters();
            params.setServerNames(java.util.List.of(new SNIHostName(host)));
            socket.setSSLParameters(params);
            // 触发 TLS 握手
            socket.startHandshake();
            result.setReachable(true);

            // 获取对端证书链（首位为叶子证书）
            java.security.cert.Certificate[] peer = socket.getSession().getPeerCertificates();
            if (peer != null && peer.length > 0) {
                X509Certificate leaf = (X509Certificate) peer[0];
                CertInfo info = CertParser.parse(leaf);
                result.setCertPresent(true);
                result.setCertInfo(info);
                // 计算剩余天数
                int daysLeft = (int) ChronoUnit.DAYS.between(LocalDateTime.now(), info.getNotAfter());
                result.setDaysLeft(daysLeft);
                result.setStatus(determineStatus(daysLeft, alertDays));
            } else {
                result.setCertPresent(false);
                result.setStatus(CertStatus.NONE);
            }
        } catch (Exception e) {
            // 连接/握手失败，记录错误
            result.setReachable(false);
            result.setCertPresent(false);
            result.setStatus(CertStatus.ERROR);
            result.setError(e.getMessage());
        }
        return result;
    }

    /**
     * 根据剩余天数与阈值判定状态。
     *
     * @param daysLeft 剩余天数
     * @param alertDays 预警阈值
     * @return 对应状态
     */
    private CertStatus determineStatus(int daysLeft, int alertDays) {
        if (daysLeft < 0) {
            return CertStatus.EXPIRED;
        }
        if (daysLeft <= alertDays) {
            return CertStatus.EXPIRING;
        }
        return CertStatus.OK;
    }
}
