"""
应用配置模块
使用 Pydantic Settings 管理配置
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


# 项目根目录
BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """应用配置"""

    # 应用配置
    app_name: str = "GPT Team 管理系统"
    app_version: str = "0.1.0"
    app_host: str = "0.0.0.0"
    app_port: int = 8008
    debug: bool = True
    admin_path: str = "/admin"
    admin_login_path: str = "/login"

    # 数据库配置
    # 建议在 Docker 中使用 data 目录挂载，以避免文件挂载权限或类型问题
    database_url: str = f"sqlite+aiosqlite:///{BASE_DIR}/data/team_manage.db"

    # 安全配置
    secret_key: str = "your-secret-key-here-change-in-production"
    admin_password: str = "admin123"

    # 日志配置
    log_level: str = "INFO"

    # 代理配置
    proxy: str = ""
    proxy_enabled: bool = False

    # Linux DO Connect OAuth
    linuxdo_client_id: str = ""
    linuxdo_client_secret: str = ""
    linuxdo_redirect_uri: str = "http://localhost:8008/auth/linuxdo/callback"
    linuxdo_scope: str = "user"
    linuxdo_auth_url: str = "https://connect.linux.do/oauth2/authorize"
    linuxdo_token_url: str = "https://connect.linux.do/oauth2/token"
    linuxdo_userinfo_url: str = "https://connect.linux.do/api/user"
    oauth_required: bool = True

    # JWT 配置
    jwt_verify_signature: bool = False

    # 时区配置
    timezone: str = "Asia/Shanghai"

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )

    @property
    def admin_path_normalized(self) -> str:
        return normalize_path(self.admin_path, "/admin")

    @property
    def admin_login_path_normalized(self) -> str:
        return normalize_path(self.admin_login_path, "/login")


# 创建全局配置实例
settings = Settings()
# 规范化路径
def normalize_path(path: str, default: str) -> str:
    raw = (path or "").strip()
    if not raw:
        return default
    if not raw.startswith("/"):
        raw = f"/{raw}"
    raw = raw.rstrip("/")
    return raw or default
