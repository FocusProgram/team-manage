"""
认证路由
处理管理员登录和登出
"""
import asyncio
import logging
import secrets
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.auth import auth_service
from app.dependencies.auth import get_current_user
from app.config import settings

logger = logging.getLogger(__name__)

# 创建路由器
router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)


# 请求模型
class LoginRequest(BaseModel):
    """登录请求"""
    password: str = Field(..., description="管理员密码", min_length=1)


class ChangePasswordRequest(BaseModel):
    """修改密码请求"""
    old_password: str = Field(..., description="旧密码", min_length=1)
    new_password: str = Field(..., description="新密码", min_length=6)


# 响应模型
class LoginResponse(BaseModel):
    """登录响应"""
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None


class LogoutResponse(BaseModel):
    """登出响应"""
    success: bool
    message: str


class ChangePasswordResponse(BaseModel):
    """修改密码响应"""
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    管理员登录

    Args:
        request: FastAPI Request 对象
        login_data: 登录数据
        db: 数据库会话

    Returns:
        登录结果
    """
    try:
        logger.info("管理员登录请求")

        # 验证密码
        result = await auth_service.verify_admin_login(
            login_data.password,
            db
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result["error"]
            )

        # 设置 Session
        request.session["user"] = {
            "username": "admin",
            "is_admin": True
        }

        logger.info("管理员登录成功，Session 已创建")

        return LoginResponse(
            success=True,
            message="登录成功",
            error=None
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"登录失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"登录失败: {str(e)}"
        )


@router.post("/logout", response_model=LogoutResponse)
async def logout(request: Request):
    """
    管理员登出

    Args:
        request: FastAPI Request 对象

    Returns:
        登出结果
    """
    try:
        # 清除 Session
        request.session.clear()

        logger.info("管理员登出成功")

        return LogoutResponse(
            success=True,
            message="登出成功"
        )

    except Exception as e:
        logger.error(f"登出失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"登出失败: {str(e)}"
        )


@router.post("/change-password", response_model=ChangePasswordResponse)
async def change_password(
    request: Request,
    password_data: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    修改管理员密码

    Args:
        request: FastAPI Request 对象
        password_data: 密码数据
        db: 数据库会话
        current_user: 当前用户（需要登录）

    Returns:
        修改结果
    """
    try:
        logger.info("管理员修改密码请求")

        # 修改密码
        result = await auth_service.change_admin_password(
            password_data.old_password,
            password_data.new_password,
            db
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )

        # 清除 Session，要求重新登录
        request.session.clear()

        logger.info("管理员密码修改成功")

        return ChangePasswordResponse(
            success=True,
            message="密码修改成功，请重新登录",
            error=None
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"修改密码失败: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"修改密码失败: {str(e)}"
        )


@router.get("/status")
async def get_auth_status(request: Request):
    """
    获取认证状态

    Args:
        request: FastAPI Request 对象

    Returns:
        认证状态
    """
    user = request.session.get("user")

    return {
        "authenticated": user is not None,
        "user": user
    }


@router.get("/linuxdo/login")
async def linuxdo_login(request: Request):
    """开始 Linux DO OAuth 登录"""
    if not settings.linuxdo_client_id or not settings.linuxdo_client_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Linux DO OAuth 未配置"
        )

    state = secrets.token_urlsafe(16)
    request.session["linuxdo_oauth_state"] = state

    params = {
        "client_id": settings.linuxdo_client_id,
        "redirect_uri": settings.linuxdo_redirect_uri,
        "response_type": "code",
        "scope": settings.linuxdo_scope,
        "state": state,
    }

    from urllib.parse import urlencode
    auth_url = f"{settings.linuxdo_auth_url}?{urlencode(params)}"
    return RedirectResponse(url=auth_url)


@router.get("/linuxdo/callback")
async def linuxdo_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
    """处理 Linux DO OAuth 回调"""
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="缺少授权码")

    session_state = request.session.get("linuxdo_oauth_state")
    if not session_state or state != session_state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="无效的 state")

    def post_token():
        from curl_cffi import requests
        data = {
            "client_id": settings.linuxdo_client_id,
            "client_secret": settings.linuxdo_client_secret,
            "code": code,
            "redirect_uri": settings.linuxdo_redirect_uri,
            "grant_type": "authorization_code",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        return requests.post(settings.linuxdo_token_url, data=data, headers=headers, timeout=15)

    token_resp = await asyncio.to_thread(post_token)
    if token_resp.status_code >= 400:
        logger.error("Linux DO token 获取失败: %s", token_resp.text)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="获取访问令牌失败")

    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        logger.error("Linux DO token 响应缺少 access_token: %s", token_data)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="获取访问令牌失败")

    def get_userinfo():
        from curl_cffi import requests
        headers = {"Authorization": f"Bearer {access_token}"}
        return requests.get(settings.linuxdo_userinfo_url, headers=headers, timeout=15)

    user_resp = await asyncio.to_thread(get_userinfo)
    if user_resp.status_code >= 400:
        logger.error("Linux DO 用户信息获取失败: %s", user_resp.text)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="获取用户信息失败")

    user_info = user_resp.json()
    user_data = user_info.get("user") if isinstance(user_info, dict) else None
    if not isinstance(user_data, dict):
        user_data = user_info if isinstance(user_info, dict) else {}
    request.session.pop("linuxdo_oauth_state", None)
    request.session["oauth_user"] = {
        "id": user_data.get("id"),
        "username": user_data.get("username"),
        "name": user_data.get("name"),
        "avatar_template": user_data.get("avatar_template"),
        "trust_level": user_data.get("trust_level"),
        "active": user_data.get("active"),
    }

    return RedirectResponse(url="/")


@router.get("/linuxdo/logout")
async def linuxdo_logout(request: Request):
    """退出 Linux DO OAuth 登录"""
    request.session.pop("oauth_user", None)
    request.session.pop("linuxdo_oauth_state", None)
    return RedirectResponse(url="/")
