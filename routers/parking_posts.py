from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from deps import get_db
from models import Community_Post
from routers.community.posts import (
    CommentCreate,
    CommentListOut,
    CommentOut,
    CommentUpdate,
    PostCreate,
    PostOut,
    PostUpdate,
    PostsOut2,
    create_comment as community_create_comment,
    create_post_plus as community_create_post_plus,
    delete_comment as community_delete_comment,
    delete_post as community_delete_post,
    get_liked_posts as community_get_liked_posts,
    get_post as community_get_post,
    like_post as community_like_post,
    list_comments as community_list_comments,
    list_my_posts_by_type as community_list_my_posts_by_type,
    list_posts_plus as community_list_posts_plus,
    search_posts_by_title as community_search_posts_by_title,
    unlike_post as community_unlike_post,
    update_comment as community_update_comment,
    update_post as community_update_post,
)

router = APIRouter()
PARKING_POST_TYPE = 11


def _require_parking_notice_post(db: Session, post_id: int) -> Community_Post:
    post = db.query(Community_Post).filter(Community_Post.id == post_id).first()
    if not post or int(getattr(post, "post_type", 0) or 0) != PARKING_POST_TYPE:
        raise HTTPException(status_code=404, detail="Post not found")
    return post


@router.post("/parking/posts/{username}", response_model=PostOut)
def parking_create_post(username: str, body: PostCreate, db: Session = Depends(get_db)):
    return community_create_post_plus(post_type=PARKING_POST_TYPE, username=username, body=body, db=db)


@router.post("/parking/posts/{username}/type/{post_type}", response_model=PostOut)
def parking_create_post_by_type(post_type: int, username: str, body: PostCreate, db: Session = Depends(get_db)):
    # parking 게시판은 고정 타입(11)만 사용합니다.
    return community_create_post_plus(post_type=PARKING_POST_TYPE, username=username, body=body, db=db)


@router.get("/parking/posts", response_model=PostsOut2)
def parking_list_posts(
    username: str | None = Query(None, description="좋아요 여부 계산용 유저명"),
    cursor: str | None = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(100, ge=1, le=100),
    status: str | None = Query(None, description="published | closed"),
    regions: str | None = Query(None, description="지역 필터(복수): 콤마로 구분"),
    province: str | None = Query(None, description="지역 필터: 시/도"),
    city: str | None = Query(None, description="지역 필터: 시/군/구"),
    db: Session = Depends(get_db),
):
    return community_list_posts_plus(
        post_type=PARKING_POST_TYPE,
        username=username,
        cursor=cursor,
        limit=limit,
        status=status,
        regions=regions,
        province=province,
        city=city,
        db=db,
    )


@router.get("/parking/posts/custom", response_model=PostsOut2)
def parking_list_posts_custom(
    username: str | None = Query(None, description="좋아요 여부 계산용 유저명"),
    cursor: str | None = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(100, ge=1, le=100),
    status: str | None = Query(None, description="published | closed"),
    regions: str | None = Query(None, description="지역 필터(복수): 콤마로 구분"),
    province: str | None = Query(None, description="지역 필터: 시/도"),
    city: str | None = Query(None, description="지역 필터: 시/군/구"),
    db: Session = Depends(get_db),
):
    # /community/posts/custom 과 동일 포맷으로 제공하되, parking 공지글 타입(11)만 반환합니다.
    return community_list_posts_plus(
        post_type=PARKING_POST_TYPE,
        username=username,
        cursor=cursor,
        limit=limit,
        status=status,
        regions=regions,
        province=province,
        city=city,
        db=db,
    )


@router.get("/parking/posts/type/{post_type}", response_model=PostsOut2)
def parking_list_posts_by_type(
    post_type: int,
    username: str | None = Query(None, description="좋아요 여부 계산용 유저명"),
    cursor: str | None = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(100, ge=1, le=100),
    status: str | None = Query(None, description="published | closed"),
    regions: str | None = Query(None, description="지역 필터(복수): 콤마로 구분"),
    province: str | None = Query(None, description="지역 필터: 시/도"),
    city: str | None = Query(None, description="지역 필터: 시/군/구"),
    db: Session = Depends(get_db),
):
    # type path는 호환성을 위해 남겨두고, 실제 조회는 11로 고정합니다.
    return community_list_posts_plus(
        post_type=PARKING_POST_TYPE,
        username=username,
        cursor=cursor,
        limit=limit,
        status=status,
        regions=regions,
        province=province,
        city=city,
        db=db,
    )


@router.get("/parking/posts/type/{post_type}/my/{username}", response_model=PostsOut2)
def parking_list_my_posts_by_type(
    post_type: int,
    username: str,
    cursor: str | None = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(1000, ge=1, le=1000),
    status: str | None = Query(None, description="published | closed"),
    db: Session = Depends(get_db),
):
    return community_list_my_posts_by_type(
        post_type=PARKING_POST_TYPE,
        username=username,
        cursor=cursor,
        limit=limit,
        status=status,
        db=db,
    )


@router.get("/parking/posts/search/title", response_model=PostsOut2)
def parking_search_posts_by_title(
    q: str = Query(..., description="검색어(제목 포함)", min_length=1, max_length=80),
    username: str | None = Query(None, description="좋아요 여부 계산용 유저명(선택)"),
    cursor: str | None = Query(None, description="커서: ISO8601 created_at"),
    limit: int = Query(50, ge=1, le=100),
    status: str | None = Query("published", description="published | closed (선택)"),
    db: Session = Depends(get_db),
):
    return community_search_posts_by_title(
        q=q,
        post_type=PARKING_POST_TYPE,
        username=username,
        cursor=cursor,
        limit=limit,
        status=status,
        db=db,
    )


@router.get("/parking/posts/{post_id}", response_model=PostOut)
def parking_get_post(post_id: int, db: Session = Depends(get_db)):
    _require_parking_notice_post(db, post_id)
    return community_get_post(post_id=post_id, db=db)


@router.put("/parking/posts/{post_id}", response_model=PostOut)
def parking_update_post(post_id: int, body: PostUpdate, db: Session = Depends(get_db)):
    _require_parking_notice_post(db, post_id)
    return community_update_post(post_id=post_id, body=body, db=db)


@router.delete("/parking/posts/{post_id}")
def parking_delete_post(post_id: int, db: Session = Depends(get_db)):
    _require_parking_notice_post(db, post_id)
    return community_delete_post(post_id=post_id, db=db)


@router.post("/parking/posts/{post_id}/comments/{username}", response_model=CommentOut, status_code=status.HTTP_201_CREATED)
def parking_create_comment(
    username: str,
    post_id: int,
    payload: CommentCreate,
    db: Session = Depends(get_db),
):
    _require_parking_notice_post(db, post_id)
    return community_create_comment(username=username, post_id=post_id, payload=payload, db=db)


@router.get("/parking/posts/{post_id}/comments", response_model=CommentListOut)
def parking_list_comments(
    post_id: int,
    cursor: str | None = Query(None, description="ISO8601 created_at 커서"),
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
):
    _require_parking_notice_post(db, post_id)
    return community_list_comments(post_id=post_id, cursor=cursor, limit=limit, db=db)


@router.put("/parking/comments/{comment_id}/{username}", response_model=CommentOut)
def parking_update_comment(
    comment_id: int,
    username: str,
    payload: CommentUpdate,
    db: Session = Depends(get_db),
):
    return community_update_comment(comment_id=comment_id, username=username, payload=payload, db=db)


@router.delete("/parking/comments/{comment_id}/{username}", status_code=status.HTTP_204_NO_CONTENT)
def parking_delete_comment(
    comment_id: int,
    username: str,
    db: Session = Depends(get_db),
):
    return community_delete_comment(comment_id=comment_id, username=username, db=db)


@router.post("/parking/posts/{post_id}/like/{username}")
async def parking_like_post(
    post_id: int,
    username: str,
    db: Session = Depends(get_db),
):
    _require_parking_notice_post(db, post_id)
    return await community_like_post(post_id=post_id, username=username, db=db)


@router.delete("/parking/posts/{post_id}/like/{username}")
async def parking_unlike_post(
    post_id: int,
    username: str,
    db: Session = Depends(get_db),
):
    _require_parking_notice_post(db, post_id)
    return await community_unlike_post(post_id=post_id, username=username, db=db)


@router.get("/parking/posts/liked/{username}")
async def parking_get_liked_posts(
    username: str,
    cursor: str | None = None,
    limit: int = 20,
    db: Session = Depends(get_db),
):
    # 원본 liked API 동작을 유지합니다. (필요 시 후속으로 post_type=11 필터 추가 가능)
    return await community_get_liked_posts(username=username, cursor=cursor, limit=limit, db=db)
