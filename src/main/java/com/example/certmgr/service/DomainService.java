package com.example.certmgr.service;

import com.example.certmgr.dto.DomainCheckResult;
import com.example.certmgr.dto.WhoisResult;
import com.example.certmgr.entity.CertStatus;
import com.example.certmgr.entity.DomainEntity;
import com.example.certmgr.repository.DomainRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 域名业务服务。
 *
 * <p>负责域名的增删改查，以及触发 Whois 与证书检测并把结果回写到域名的缓存字段，
 * 使列表页与预警可直接使用最新状态而无需实时连网。</p>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DomainService {

    /** 域名数据访问 */
    private final DomainRepository domainRepo;

    /** SSL 检测服务 */
    private final SslCheckService sslCheckService;

    /** Whois 查询服务 */
    private final WhoisService whoisService;

    /**
     * 查询全部域名。
     *
     * @return 域名列表
     */
    public List<DomainEntity> list() {
        return domainRepo.findAll();
    }

    /**
     * 按 ID 查询域名（不存在抛异常）。
     *
     * @param id 主键
     * @return 域名实体
     */
    public DomainEntity get(Long id) {
        return domainRepo.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("域名不存在: " + id));
    }

    /**
     * 按名称查询域名。
     *
     * @param name 域名
     * @return 域名实体
     */
    public DomainEntity getByName(String name) {
        return domainRepo.findByName(name)
                .orElseThrow(() -> new IllegalArgumentException("域名不存在: " + name));
    }

    /**
     * 判断域名是否已存在。
     *
     * @param name 域名
     * @return 存在返回 true
     */
    public boolean exists(String name) {
        return domainRepo.existsByName(name);
    }

    /**
     * 保存或更新域名实体。
     *
     * @param entity 域名实体
     * @return 持久化后的实体
     */
    public DomainEntity save(DomainEntity entity) {
        return domainRepo.save(entity);
    }

    /**
     * 删除域名。
     *
     * @param id 主键
     */
    public void delete(Long id) {
        domainRepo.deleteById(id);
    }

    /**
     * 手动触发一次证书检测，并将结果回写到域名缓存字段。
     *
     * @param id 域名主键
     * @return 本次检测结果
     */
    public DomainCheckResult checkNow(Long id) {
        DomainEntity domain = get(id);
        DomainCheckResult result = sslCheckService.check(domain.getName(), domain.getPort());
        applyResult(domain, result);
        // 检测证书的同时刷新域名注册(Whois)缓存，保证列表可展示域名过期时间
        refreshWhoisFields(domain);
        domainRepo.save(domain);
        return result;
    }

    /**
     * 仅刷新域名的 Whois 注册信息（注册商 / 注册时间 / 域名过期时间），不探测证书。
     * 新增域名时调用，使列表立即具备“域名过期时间”与“域名信息”。
     *
     * @param id 域名主键
     */
    public WhoisResult refreshWhois(Long id) {
        DomainEntity domain = get(id);
        WhoisResult result = refreshWhoisFields(domain);
        domainRepo.save(domain);
        return result;
    }

    /**
     * 查询 Whois 并把注册信息写入域名实体的缓存字段。
     * Whois 查询失败不影响主流程（证书检测 / 域名保存）。
     *
     * @param domain 域名实体
     */
    private WhoisResult refreshWhoisFields(DomainEntity domain) {
        try {
            WhoisResult whois = whoisService.query(domain.getName());
            // 保存前统一日期格式；结构化日期缺失时，从原始 WHOIS/RDAP 响应补全。
            WhoisService.completeDatesFromRaw(whois);
            // 仅当查询成功（无错误）且字段非空时才覆盖，避免清空用户手动补录的注册信息
            if (whois.getError() == null) {
                if (whois.getRegistrar() != null) {
                    domain.setWhoisRegistrar(whois.getRegistrar());
                }
                if (whois.getCreationDate() != null) {
                    domain.setWhoisCreationDate(whois.getCreationDate());
                }
                if (whois.getExpiryDate() != null) {
                    domain.setWhoisExpiryDate(whois.getExpiryDate());
                }
            }
            return whois;
        } catch (Exception e) {
            log.error("刷新 Whois 失败, domain={}", domain.getName(), e);
            WhoisResult failed = new WhoisResult();
            failed.setError(e.getMessage());
            return failed;
        }
    }

    /**
     * 对指定域名与端口执行一次“只读”检测（不落库）。
     *
     * @param name 域名
     * @param port 端口
     * @return 检测结果
     */
    public DomainCheckResult checkNow(String name, int port) {
        return sslCheckService.check(name, port);
    }

    /**
     * 将检测结果映射回域名实体的缓存字段。
     *
     * @param domain 域名实体
     * @param result 检测结果
     */
    private void applyResult(DomainEntity domain, DomainCheckResult result) {
        domain.setLastCheckAt(result.getCheckTime());
        domain.setCertStatus(result.getStatus());
        domain.setLastError(result.getError());
        if (result.isCertPresent() && result.getCertInfo() != null) {
            domain.setCertExpiryAt(result.getCertInfo().getNotAfter());
            domain.setCertIssuer(result.getCertInfo().getIssuer());
            domain.setCertCommonName(result.getCertInfo().getCommonName());
            domain.setCertDaysLeft(result.getDaysLeft());
        } else {
            domain.setCertExpiryAt(null);
            domain.setCertIssuer(null);
            domain.setCertCommonName(null);
            domain.setCertDaysLeft(null);
        }
    }
}
