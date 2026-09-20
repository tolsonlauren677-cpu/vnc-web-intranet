// 密码管理工具

class PasswordManager {
    constructor() {
        this.passwordStorageKey = 'vnc_saved_passwords';
    }

    /**
     * 保存密码到本地存储
     * @param {string} ip - VNC服务器IP地址
     * @param {string} password - VNC密码
     */
    savePassword(ip, password) {
        try {
            const passwords = this.getSavedPasswords();
            passwords[ip] = password;
            localStorage.setItem(this.passwordStorageKey, JSON.stringify(passwords));
            return true;
        } catch (error) {
            console.error('保存密码失败:', error);
            return false;
        }
    }

    /**
     * 获取保存的密码
     * @param {string} ip - VNC服务器IP地址
     * @returns {string|null} 密码或null
     */
    getPassword(ip) {
        try {
            const passwords = this.getSavedPasswords();
            return passwords[ip] || null;
        } catch (error) {
            console.error('获取密码失败:', error);
            return null;
        }
    }

    /**
     * 删除保存的密码
     * @param {string} ip - VNC服务器IP地址
     */
    deletePassword(ip) {
        try {
            const passwords = this.getSavedPasswords();
            if (passwords[ip]) {
                delete passwords[ip];
                localStorage.setItem(this.passwordStorageKey, JSON.stringify(passwords));
                return true;
            }
            return false;
        } catch (error) {
            console.error('删除密码失败:', error);
            return false;
        }
    }

    /**
     * 获取所有保存的密码
     * @returns {Object} 密码对象
     */
    getSavedPasswords() {
        try {
            const saved = localStorage.getItem(this.passwordStorageKey);
            return saved ? JSON.parse(saved) : {};
        } catch (error) {
            console.error('读取密码失败:', error);
            return {};
        }
    }

    /**
     * 清空所有保存的密码
     */
    clearAllPasswords() {
        try {
            localStorage.removeItem(this.passwordStorageKey);
            return true;
        } catch (error) {
            console.error('清空密码失败:', error);
            return false;
        }
    }

    /**
     * 显示/隐藏密码
     * @param {HTMLElement} passwordInput - 密码输入框元素
     * @param {HTMLElement} toggleButton - 切换按钮元素
     */
    togglePasswordVisibility(passwordInput, toggleButton) {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleButton.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
            passwordInput.type = 'password';
            toggleButton.innerHTML = '<i class="fas fa-eye"></i>';
        }
    }

    /**
     * 验证密码强度
     * @param {string} password - 密码
     * @returns {Object} 包含强度评分和反馈的对象
     */
    validatePasswordStrength(password) {
        let score = 0;
        const feedback = [];

        // 长度检查
        if (password.length >= 8) {
            score += 1;
        } else {
            feedback.push('密码长度至少8位');
        }

        // 包含数字
        if (/[0-9]/.test(password)) {
            score += 1;
        } else {
            feedback.push('包含至少一个数字');
        }

        // 包含小写字母
        if (/[a-z]/.test(password)) {
            score += 1;
        } else {
            feedback.push('包含至少一个小写字母');
        }

        // 包含大写字母
        if (/[A-Z]/.test(password)) {
            score += 1;
        } else {
            feedback.push('包含至少一个大写字母');
        }

        // 包含特殊字符
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            score += 1;
        } else {
            feedback.push('包含至少一个特殊字符');
        }

        let strength = '弱';
        if (score >= 4) {
            strength = '强';
        } else if (score >= 3) {
            strength = '中';
        }

        return {
            score,
            strength,
            feedback
        };
    }
}

// 创建全局实例
const passwordManager = new PasswordManager();

// 导出到全局作用域
if (typeof window !== 'undefined') {
    window.PasswordManager = PasswordManager;
    window.passwordManager = passwordManager;
}