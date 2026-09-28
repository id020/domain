package com.example.certmgr.repository;

import com.example.certmgr.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

/**
 * 用户数据访问接口。
 *
 * <p>基于 Spring Data JPA，提供按用户名查询的能力，供 {@code UserDetailsServiceImpl}
 * 在登录时加载用户。</p>
 */
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    /**
     * 根据登录用户名查询用户。
     *
     * @param username 用户名
     * @return 命中的用户（不存在时返回空 Optional）
     */
    Optional<UserEntity> findByUsername(String username);

    /**
     * 判断指定用户名是否已存在（新增用户时校验唯一性）。
     *
     * @param username 用户名
     * @return 存在返回 true
     */
    boolean existsByUsername(String username);

    /**
     * 查询全部用户并按 ID 升序返回，保证用户管理列表顺序稳定。
     *
     * @return 用户列表
     */
    List<UserEntity> findAllByOrderByIdAsc();
}
