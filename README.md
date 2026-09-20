# TaskControllerManager VNC Web Client

一个基于 [noVNC](https://github.com/novnc/noVNC) 的轻量 VNC 浏览器客户端，提供中文管理界面、VNC WebSocket 代理、连接测试、剪贴板编码转换以及常用远程操作入口。

## 功能

- 在现代浏览器中连接 VNC 服务；
- 使用 WebSocket-to-TCP 代理连接不原生支持 WebSocket 的 VNC 服务；
- 支持 VNC 密码认证和常见 noVNC 编码；
- 支持中文 Windows VNC 环境常见的剪贴板编码转换；
- 保存连接历史和可选的本地连接配置；
- 支持连接刷新时主动关闭旧的 VNC 会话。

## 安全边界

本项目默认面向可信内网或 VPN 环境，不是开箱即用的公网远程桌面网关。

- 当前代码默认让 WebSocket 代理监听所有网卡；生产环境应显式设置 `WS_PROXY_HOST=127.0.0.1`，只有在确认网络边界后才改为其他监听地址；
- 当前项目不提供完整的用户、角色和权限管理；
- 不要直接把 `6080` 端口暴露到公网；
- 浏览器保存的 VNC 密码会进入浏览器本地存储，导出的配置文件可能包含明文密码；
- 生产环境必须设置随机的 `SECRET_KEY`，不要使用代码中的占位值；
- 建议通过 HTTPS/WSS、VPN、防火墙或带认证的反向代理保护服务。

## 环境要求

- Python 3.10 或更高版本；
- 一个可访问的 VNC 服务；
- 支持 WebSocket 和现代 JavaScript 的浏览器。

## 安装

```powershell
cd D:\work\TaskControllerManager\vnc-web-client
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

`.env.example` 是配置清单模板；当前启动入口直接读取操作系统环境变量，不会自动加载 `.env` 文件。请按模板设置环境变量；Windows PowerShell 示例：

```powershell
$env:SECRET_KEY = "replace-with-a-long-random-value"
$env:WS_PROXY_HOST = "127.0.0.1"
$env:PORT = "5888"
python app.py
```

启动后访问：

```text
http://127.0.0.1:5888
```

WebSocket 代理默认监听 `127.0.0.1:6080`。如果页面与代理不在同一台机器上，需要通过防火墙和反向代理明确限制访问来源。

## 使用 URL 直接连接

可以把 VNC 目标写入页面 URL。页面打开后会自动填写目标并开始连接：

```text
http://192.0.2.10:5888/?ip=192.0.2.20&port=5900&name=%E7%A4%BA%E4%BE%8B%E8%B4%9F%E8%BD%BD%E6%9C%BA
```

上面的地址使用了文档专用的虚拟示例值：

- `192.0.2.10`：提供 Web 页面的一方；
- `192.0.2.20`：VNC 目标主机；
- `5900`：VNC 端口；
- `name`：页面标题和当前连接的显示名称，中文需要进行 URL 编码。

实际使用时，请将示例中的 Web 服务地址、VNC 主机地址、端口和名称替换成自己的值。例如：

```text
http://<web-host>:5888/?ip=<vnc-host>&port=5900&name=<url-encoded-name>
```

如果当前浏览器已经为该 VNC 主机保存过密码，页面会按目标主机地址从浏览器本地存储读取密码并自动使用；URL 本身不包含密码。首次使用或浏览器中没有对应保存密码时，仍需要在页面中输入密码。如果勾选保存密码，密码会保存在当前浏览器和当前站点的本地存储中。

## 配置项

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `5888` | HTTP 页面端口 |
| `HTTP_THREADS` | `16` | Waitress HTTP 工作线程数 |
| `WS_PROXY_HOST` | `0.0.0.0` | WebSocket 代理监听地址；生产环境建议改为 `127.0.0.1` |
| `WS_PROXY_PORT` | `6080` | WebSocket 代理端口 |
| `SECRET_KEY` | 无安全默认值 | 必须设置为随机值 |

## 开发与部署

开发调试可以直接运行：

```powershell
python app.py
```

入口会启动 Waitress HTTP 服务和独立的 WebSocket-to-VNC 代理。生产环境建议将 HTTP 服务置于 HTTPS 反向代理后，并限制代理端口的网络访问范围。

## 第三方组件和版权

本项目包含 noVNC 的浏览器端核心代码，版权和许可证信息保留在 [`static/novnc/LICENSE.txt`](static/novnc/LICENSE.txt)。noVNC 核心主要采用 Mozilla Public License 2.0（MPL-2.0），其中部分资源和组件使用 BSD、MIT、SIL OFL 等许可证。

本项目还包含 pako 压缩库，其许可证位于 [`static/novnc/vendor/pako/LICENSE`](static/novnc/vendor/pako/LICENSE)。发布源码或二进制包时，请同时保留这些版权和许可证文件。

## 报告问题

普通功能问题可以提交 GitHub Issue。安全漏洞请不要直接公开到 Issue，请使用仓库的 GitHub Security Advisories/private vulnerability reporting 功能；如果仓库未启用该功能，请先联系维护者后再披露细节。

## 许可证

本项目新增代码按 MPL-2.0 发布，完整说明见 [`LICENSE`](LICENSE)。第三方组件仍以其各自的许可证为准。
