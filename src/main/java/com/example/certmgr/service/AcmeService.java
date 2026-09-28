package com.example.certmgr.service;

import com.example.certmgr.config.CertProperties;
import com.example.certmgr.dto.CertInfo;
import com.example.certmgr.entity.CertificateEntity;
import com.example.certmgr.entity.CertificateStatus;
import com.example.certmgr.entity.CertificateType;
import com.example.certmgr.repository.CertificateRepository;
import com.example.certmgr.util.CertParser;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

import org.springframework.stereotype.Service;

import java.io.Reader;
import java.io.Writer;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * ACME 自动签发服务。
 *
 * <p>基于 acme4j 与 Let's Encrypt（或兼容 CA）完成：
 * 账户注册 → 创建订单 → HTTP-01 挑战（写入验证文件并由应用对外提供）
 * → 生成 CSR → 下载证书 → 解析并落库（来源标记为 ACME_ISSUED）。</p>
 *
 * <p><b>前置条件</b>：域名需公网可达，且 80 端口的
 * {@code /.well-known/acme-challenge/} 路径能访问到本系统写入的验证文件
 * （本应用已内置 {@code ChallengeController} 对外提供该路径）。</p>
 */
@Service
public class AcmeService {

    /** 自定义 ACME 配置 */
    private final CertProperties certProperties;

    /** 证书数据访问 */
    private final CertificateRepository certRepo;

    public AcmeService(CertProperties certProperties, CertificateRepository certRepo) {
        this.certProperties = certProperties;
        this.certRepo = certRepo;
    }

    /**
     * 签发证书并入库。
     *
     * @param domainName 主域名
     * @param sans 附加 SAN 域名（可为空）
     * @param autoRenew 是否开启自动续期
     * @return 保存后的证书实体
     */
    public CertificateEntity issue(String domainName, List<String> sans, boolean autoRenew) {
        try {
            String serverUrl = certProperties.getAcme().getServerUrl();
            String contactEmail = certProperties.getAcme().getContactEmail();
            String challengeType = certProperties.getAcme().getChallenge();
            String webroot = certProperties.getAcme().getWebroot();

            // 1. 建立会话并获取/注册账户
            Session session = new Session(serverUrl);
            KeyPair accountKey = loadOrCreateAccountKey();
            Account account = findOrRegisterAccount(session, accountKey, contactEmail);

            // 2. 汇总待签发域名（主域名 + SAN）
            Set<String> domains = new LinkedHashSet<>();
            domains.add(domainName);
            if (sans != null) {
                sans.removeIf(s -> s == null || s.isBlank());
                domains.addAll(sans);
            }

            // 3. 创建订单
            Order order = account.newOrder().domains(domains.toArray(new String[0])).create();

            // 4. 逐个授权完成挑战
            Collection<Authorization> authorizations = order.getAuthorizations();
            for (Authorization auth : authorizations) {
                if (auth.getStatus() == Status.VALID) {
                    continue;
                }
                if ("HTTP-01".equalsIgnoreCase(challengeType)) {
                    Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
                    if (challenge == null) {
                        throw new IllegalStateException("该授权不支持 HTTP-01 挑战");
                    }
                    // 将验证文件写入 webroot，供 CA 抓取
                    Path dir = Paths.get(webroot, ".well-known", "acme-challenge");
                    Files.createDirectories(dir);
                    Files.write(dir.resolve(challenge.getToken()),
                            challenge.getAuthorization().getBytes(StandardCharsets.UTF_8));
                    // 通知 CA 开始校验
                    challenge.trigger();
                    waitFor(challenge::getStatus, "挑战");
                } else {
                    throw new UnsupportedOperationException("当前仅实现 HTTP-01 挑战，DNS-01 需自行扩展");
                }
            }

            // 5. 生成域名密钥对与 CSR，提交订单
            KeyPair domainKey = KeyPairUtils.createKeyPair(2048);
            CSRBuilder csrb = new CSRBuilder();
            for (String d : domains) {
                csrb.addDomain(d);
            }
            csrb.sign(domainKey);
            byte[] csr = csrb.getEncoded();
            order.execute(csr);
            waitFor(order::getStatus, "订单");

            // 6. 下载证书
            Certificate certificate = order.getCertificate();
            // getCertificate() 返回叶子证书；getCertificateChain() 返回完整链（含叶子）
            X509Certificate leaf = certificate.getCertificate();
            List<X509Certificate> chain = certificate.getCertificateChain();

            // 7. 组装 PEM（证书链 + 私钥）
            StringBuilder certPem = new StringBuilder();
            for (X509Certificate c : chain) {
                certPem.append(toPem("CERTIFICATE", c.getEncoded()));
            }
            String keyPem = toPem("PRIVATE KEY", domainKey.getPrivate().getEncoded());

            // 8. 解析元信息并落库
            CertInfo info = CertParser.parse(leaf);
            CertificateEntity entity = new CertificateEntity();
            entity.setName(domainName + " (ACME)");
            entity.setDomainName(domainName);
            entity.setCommonName(info.getCommonName());
            entity.setSanDomains(String.join(",", info.getSanDomains()));
            entity.setIssuer(info.getIssuer());
            entity.setNotBefore(info.getNotBefore());
            entity.setNotAfter(info.getNotAfter());
            entity.setSerialNumber(info.getSerialNumber());
            entity.setSignatureAlgorithm(info.getSignatureAlgorithm());
            entity.setPublicKeyAlgorithm(info.getPublicKeyAlgorithm());
            entity.setCertPem(certPem.toString());
            entity.setPrivateKeyPem(keyPem);
            entity.setType(CertificateType.ACME_ISSUED);
            boolean expired = leaf.getNotAfter().toInstant().isBefore(Instant.now());
            entity.setStatus(expired ? CertificateStatus.EXPIRED : CertificateStatus.VALID);
            entity.setAutoRenew(autoRenew);
            return certRepo.save(entity);
        } catch (Exception e) {
            throw new IllegalStateException("ACME 签发失败: " + e.getMessage(), e);
        }
    }

    /**
     * 为已有 ACME 证书重新签发。保留原记录 ID，避免续签后产生重复证书。
     * 签发失败时不修改旧证书；成功后才替换内容。
     */
    public CertificateEntity renew(CertificateEntity existing) {
        if (existing.getType() != CertificateType.ACME_ISSUED) {
            throw new IllegalArgumentException("仅 ACME 签发的证书支持自动续签");
        }
        List<String> sans = existing.getSanDomains() == null ? List.of()
                : java.util.Arrays.stream(existing.getSanDomains().split(","))
                .map(String::trim).filter(v -> !v.isEmpty())
                .filter(v -> !v.equalsIgnoreCase(existing.getDomainName())).toList();
        CertificateEntity fresh = issue(existing.getDomainName(), sans, true);
        existing.setCertPem(fresh.getCertPem());
        existing.setPrivateKeyPem(fresh.getPrivateKeyPem());
        existing.setNotBefore(fresh.getNotBefore());
        existing.setNotAfter(fresh.getNotAfter());
        existing.setCommonName(fresh.getCommonName());
        existing.setSanDomains(fresh.getSanDomains());
        existing.setIssuer(fresh.getIssuer());
        existing.setSerialNumber(fresh.getSerialNumber());
        existing.setSignatureAlgorithm(fresh.getSignatureAlgorithm());
        existing.setPublicKeyAlgorithm(fresh.getPublicKeyAlgorithm());
        existing.setStatus(fresh.getStatus());
        CertificateEntity saved = certRepo.save(existing);
        certRepo.delete(fresh);
        return saved;
    }

    /**
     * 查找已有账户，不存在则注册新账户。
     *
     * <p>账户位置 URL 持久化到文件，续期时可直接登录复用，避免重复注册冲突。</p>
     *
     * @param session ACME 会话
     * @param accountKey 账户密钥对
     * @param email 联系邮箱
     * @return 账户对象
     * @throws Exception 通信异常
     */
    private Account findOrRegisterAccount(Session session, KeyPair accountKey, String email) throws Exception {
        Path locPath = accountBaseDir().resolve("acme-account-url.txt");
        Path keyPath = accountBaseDir().resolve("acme-account.key");
        // 若已存在账户位置与密钥，则直接登录复用
        if (Files.exists(locPath) && Files.exists(keyPath)) {
            String urlStr = Files.readString(locPath).trim();
            URL accountUrl = new URL(urlStr);
            return session.login(accountUrl, accountKey).getAccount();
        }
        // 否则注册新账户，并持久化账户位置 URL 供后续续期
        Login login = new AccountBuilder()
                .addContact("mailto:" + email)
                .agreeToTermsOfService()
                .useKeyPair(accountKey)
                .createLogin(session);
        URL accountUrl = login.getAccountLocation();
        Files.writeString(locPath, accountUrl.toString());
        return login.getAccount();
    }

    /**
     * 加载或创建 ACME 账户密钥（持久化到文件，保证续期一致）。
     *
     * @return 账户密钥对
     * @throws Exception IO 或生成异常
     */
    private KeyPair loadOrCreateAccountKey() throws Exception {
        Path path = accountBaseDir().resolve("acme-account.key");
        if (Files.exists(path)) {
            try (Reader reader = Files.newBufferedReader(path)) {
                return KeyPairUtils.readKeyPair(reader);
            }
        }
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        Files.createDirectories(accountBaseDir());
        try (Writer writer = Files.newBufferedWriter(path)) {
            KeyPairUtils.writeKeyPair(keyPair, writer);
        }
        return keyPair;
    }

    /**
     * 计算 ACME 账户相关文件的存放目录。
     *
     * <p>取 webroot 的上级目录，避免验证文件与密钥混放。</p>
     *
     * @return 账户文件目录
     */
    private Path accountBaseDir() {
        Path root = Paths.get(certProperties.getAcme().getWebroot()).toAbsolutePath();
        Path parent = root.getParent();
        if (parent == null) throw new IllegalStateException("ACME webroot 需要有父目录");
        return parent;
    }

    /**
     * 轮询等待状态变为 VALID，或超时/失败抛出异常。
     *
     * @param statusSupplier 状态获取器
     * @param what 描述（用于错误信息）
     * @throws InterruptedException 线程中断
     * @throws IllegalStateException 失败或超时
     */
    private void waitFor(Supplier<Status> statusSupplier, String what) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 180_000L; // 最多等待 3 分钟
        while (true) {
            Status status = statusSupplier.get();
            if (status == Status.VALID) {
                return;
            }
            if (status == Status.INVALID || status == Status.REVOKED || status == Status.DEACTIVATED) {
                throw new IllegalStateException(what + " 失败，状态: " + status);
            }
            if (System.currentTimeMillis() > deadline) {
                throw new IllegalStateException(what + " 超时未就绪");
            }
            Thread.sleep(3000);
        }
    }

    /**
     * 将 DER 编码内容包装为 PEM 文本。
     *
     * @param type 头部类型（CERTIFICATE / PRIVATE KEY）
     * @param der DER 编码字节
     * @return PEM 文本
     */
    private String toPem(String type, byte[] der) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(i + 64, base64.length())).append("\n");
        }
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString();
    }
}
