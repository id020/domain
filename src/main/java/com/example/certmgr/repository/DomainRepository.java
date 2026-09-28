package com.example.certmgr.repository;

import com.example.certmgr.entity.DomainEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * 域名数据访问层。
 * 基于 Spring Data JPA，提供按域名查询与存在性判断能力。
 */
@Repository
public interface DomainRepository extends JpaRepository<DomainEntity, Long> {

    /**
     * 根据域名精确查询。
     *
     * @param name 域名
     * @return 匹配的域名实体（可能为空）
     */
    Optional<DomainEntity> findByName(String name);

    /**
     * 判断指定域名是否已存在。
     *
     * @param name 域名
     * @return 存在返回 true
     */
    boolean existsByName(String name);
}
