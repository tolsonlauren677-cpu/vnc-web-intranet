# Security Policy

## Scope

这个项目会建立浏览器到 VNC 服务的远程桌面连接。安全问题可能导致远程桌面访问、内网主机探测、凭据泄露或会话劫持，因此请谨慎报告。

## Supported versions

只对仓库默认分支和最近发布版本进行安全修复。部署者应及时更新 noVNC、Python 依赖和浏览器环境。

## Reporting a vulnerability

请不要在公开 Issue、Pull Request、聊天记录或截图中提交安全漏洞细节、VNC 密码、导出的配置文件或内部主机地址。

优先使用 GitHub 仓库的 **Security → Advisories → Report a vulnerability** 私密报告功能。报告应尽量包含：

- 受影响的版本或提交；
- 复现步骤；
- 影响范围；
- 必要时提供脱敏日志或最小化示例。

如果仓库尚未启用私密漏洞报告，请先联系维护者，等待确认后再发送敏感细节。

## Deployment notes

- 不要将 WebSocket 代理端口直接暴露到公网；
- 使用随机 `SECRET_KEY`，不要使用示例值；
- 使用 HTTPS/WSS、VPN 或带身份认证的反向代理；
- 不要把浏览器导出的 `vnc-web-client-data-*.json` 提交到 Git；
- 发现密码或令牌泄露时，应立即轮换，而不是只删除文件。
