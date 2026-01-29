"""
数据库连接模块
SQLite 异步连接配置和会话管理
"""
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.config import settings

# 创建异步引擎
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,  # 开发环境打印 SQL
    future=True,
    connect_args={"timeout": 30}
)

# 创建异步会话工厂
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# 创建 Base 类
Base = declarative_base()


async def get_db() -> AsyncSession:
    """
    获取数据库会话
    用于 FastAPI 依赖注入
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """
    初始化数据库
    创建所有表
    """
    async with engine.begin() as conn:
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.run_sync(Base.metadata.create_all)
        await _ensure_redemption_record_oauth_columns(conn)


async def _ensure_redemption_record_oauth_columns(conn):
    result = await conn.execute(text("PRAGMA table_info(redemption_records)"))
    existing = {row[1] for row in result.fetchall()}

    if "oauth_username" not in existing:
        await conn.execute(text("ALTER TABLE redemption_records ADD COLUMN oauth_username VARCHAR(255)"))
    if "oauth_avatar_template" not in existing:
        await conn.execute(text("ALTER TABLE redemption_records ADD COLUMN oauth_avatar_template VARCHAR(255)"))


async def close_db():
    """
    关闭数据库连接
    """
    await engine.dispose()
