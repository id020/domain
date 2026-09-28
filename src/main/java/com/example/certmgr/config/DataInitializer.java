package com.example.certmgr.config;

import com.example.certmgr.entity.UserEntity;
import com.example.certmgr.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 数据初始化器：首次启动时创建默认管理员账号。
 *
 * <p>仅当 {@code users} 表为空时插入一个默认管理员（admin / admin123），
 * 避免重复启动反复插入。生产环境请登录后立即修改密码或删除该初始化逻辑。</p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    /** 用户数据访问接口 */
    private final UserRepository userRepository;

    /** 密码编码器（BCrypt） */
    private final PasswordEncoder passwordEncoder;

    /**
     * 应用启动后执行。
     *
     * @param args 命令行参数（未使用）
     */
    @Override
    public void run(String... args) {
        if (userRepository.count() == 0) {
            UserEntity admin = new UserEntity();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin123")); // 明文 admin123，BCrypt 加密入库
            admin.setDisplayName("系统管理员");
            admin.setRole("ADMIN");
            admin.setEnabled(true);
            userRepository.save(admin);
            log.info("已初始化默认管理员账号 [admin / admin123]，请尽快登录修改密码。");
        }
    }
}
