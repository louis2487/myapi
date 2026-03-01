from __future__ import annotations

from fastapi import APIRouter

from .admin import router as admin_router
from .auth import router as auth_router
from .cash import router as cash_router
from .phone import router as phone_router
from .popup import router as popup_router
from .points import router as points_router
from .posts import router as posts_router
from .referrals import router as referrals_router
from .stats import router as stats_router
from .ui_config import router as ui_config_router
from .users import router as users_router
from .version import router as version_router

router = APIRouter()

# 커뮤니티 기능 라우터 묶음
router.include_router(auth_router)
router.include_router(phone_router)
router.include_router(version_router)
router.include_router(referrals_router)
router.include_router(points_router)
router.include_router(stats_router)
router.include_router(cash_router)
router.include_router(users_router)
router.include_router(posts_router)
router.include_router(admin_router)
router.include_router(ui_config_router)
router.include_router(popup_router)

