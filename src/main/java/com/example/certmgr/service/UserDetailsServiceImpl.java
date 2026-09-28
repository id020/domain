package com.example.certmgr.service;

import com.example.certmgr.entity.UserEntity;
import com.example.certmgr.repository.UserRepository;
import com.example.certmgr.security.Permissions;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 自定义用户详情服务：将系统用户适配为 Spring Security 的 {@link UserDetails}。
 *
 * <p>Spring Security 在认证时调用本类的 {@link #loadUserByUsername(String)} 加载用户，
 * 并使用配置的 {@code PasswordEncoder}（BCrypt）校验密码。</p>
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    /** 用户数据访问接口 */
    private final UserRepository userRepository;

    /**
     * 根据用户名加载用户详情。
     *
     * @param username 登录用户名
     * @return Spring Security 使用的用户详情对象
     * @throws UsernameNotFoundException 当用户不存在时抛出
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity u = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("用户不存在: " + username));
        // 角色映射为 ROLE_xxx；细粒度权限映射为 PERM_xxx（管理员自动拥有 Permissions.ALL 全部权限）
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + u.getRole()));
        for (String perm : u.getPermissionSet()) {
            authorities.add(new SimpleGrantedAuthority(Permissions.PREFIX + perm));
        }
        // 启用状态、账号/凭证/锁定均未过期
        return new User(u.getUsername(), u.getPassword(), u.isEnabled(), true, true, true, authorities);
    }
}
