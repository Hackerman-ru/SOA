import pytest
import requests
import time
import uuid
import json
from datetime import datetime

BASE_URL = "http://localhost:8080/api/v1"
MAX_RETRIES = 10
RETRY_DELAY = 3

def wait_for_condition(condition_func):
    for _ in range(MAX_RETRIES):
        if condition_func():
            return True
        time.sleep(RETRY_DELAY)
    return False

def create_user(username, password, email):
    payload = {"username": username, "password": password, "email": email}
    response = requests.post(
        f"{BASE_URL}/user/register",
        json=payload
    )
    assert response.status_code == 200
    return response

def login_user(username, password):
    session = requests.Session()
    payload = {"username": username, "password": password}
    response = session.post(
        f"{BASE_URL}/user/login",
        json=payload
    )
    assert response.status_code == 200
    return session

def create_post(session, title, description, creator_id, is_private, tags):
    payload = {
        "title": title,
        "description": description,
        "creator_id": creator_id,
        "is_private": is_private,
        "tags": tags,
    }
    response = session.post(
        f"{BASE_URL}/post/create",
        json=payload
    )
    assert response.status_code == 200
    return response.json()["id"]

def test_full_flow_user_registration_to_analytics():
    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "strongpassword"
    email = f"{username}@mail.ru"
    
    response = create_user(username, password, email)
    user_id = response.json()["id"]
    session = login_user(username, password)
    
    post_id = create_post(session, "Test Post", "Test description", user_id, False, ["test tag1", "test tag2"])
    
    views = 3
    likes = 4
    comments = 2
    for i in range(views):
        session.post(
            f"{BASE_URL}/post/view",
            json={"post_id": post_id, "user_id": user_id}
        )
    for i in range(likes):
        session.post(
            f"{BASE_URL}/post/like",
            json={"post_id": post_id, "user_id": user_id}
        )
    for i in range(comments):
        session.post(
            f"{BASE_URL}/post/comment",
            json={"post_id": post_id, "user_id": user_id, "text": "Great post!"}
        )
    
    def check_stats():
        payload = { "post_id": post_id }
        stats_resp = session.get(
            f"{BASE_URL}/reaction/stats",
            json=payload
        )
        if stats_resp.status_code != 200:
            return False
        stats = stats_resp.json()
        return stats["views"] == views and stats["likes"] == likes and stats["comments"] == comments
    
    assert wait_for_condition(check_stats), "Stats not updated"

def test_many_accounts():
    usernames = [f"user_{uuid.uuid4().hex[:8]}", f"user_{uuid.uuid4().hex[:8]}"]
    passwords = ["keklol123", "1234"]
    vlcs = [[3, 4, 2], [9, 0, 5]]

    user_ids = []
    post_ids = []

    for username, password, [views, likes, comments] in zip(usernames, passwords, vlcs):
        email = f"{username}@mail.ru"
        
        response = create_user(username, password, email)
        user_id = response.json()["id"]
        user_ids.append(user_id)

        session = login_user(username, password)

        post_id = create_post(session, "Test Post", "Test description", user_id, False, ["test tag1", "test tag2"])
        post_ids.append(post_id)

        for i in range(views):
            session.post(
                f"{BASE_URL}/post/view",
                json={"post_id": post_id, "user_id": user_id}
            )
        for i in range(likes):
            session.post(
                f"{BASE_URL}/post/like",
                json={"post_id": post_id, "user_id": user_id}
            )
        for i in range(comments):
            session.post(
                f"{BASE_URL}/post/comment",
                json={"post_id": post_id, "user_id": user_id, "text": "Great post!"}
            )
        
        def check_stats():
            payload = { "post_id": post_id }
            stats_resp = session.get(
                f"{BASE_URL}/reaction/stats",
                json=payload
            )
            if stats_resp.status_code != 200:
                return False
            stats = stats_resp.json()
            return stats["views"] == views and stats["likes"] == likes and stats["comments"] == comments
        
        assert wait_for_condition(check_stats), "Stats not updated"
        
        session.post(
            f"{BASE_URL}/user/logout"
        )
    
    payload = { "post_id": post_ids[0] }
    resp = session.get(
                f"{BASE_URL}/reaction/views_dynamic",
                json=payload
            )
    assert resp.status_code == 200
    dynamic = resp.json()
    assert len(dynamic) == 1
    today = datetime.today().strftime('%Y-%m-%d')
    assert dynamic[0]["count"] == vlcs[0][0] and dynamic[0]["date"] == today

    payload = { "metric" : 2 }
    resp = session.get(
                f"{BASE_URL}/reaction/top_posts",
                json=payload
            )
    assert resp.status_code == 200
    top = resp.json()
    assert len(top) >= 2

    resp = session.get(
                f"{BASE_URL}/reaction/top_creators",
                json=payload
            )
    assert resp.status_code == 200
    top = resp.json()
    assert len(top) >= 2

def test_reading_comments():
    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "strongpassword"
    email = f"{username}@mail.ru"
    
    response = create_user(username, password, email)
    user_id = response.json()["id"]
    session = login_user(username, password)
    
    post_id = create_post(session, "Test Post", "Test description", user_id, False, ["test tag1", "test tag2"])
    
    views = 3
    likes = 4
    comments = 7
    for i in range(views):
        session.post(
            f"{BASE_URL}/post/view",
            json={"post_id": post_id, "user_id": user_id}
        )
    for i in range(likes):
        session.post(
            f"{BASE_URL}/post/like",
            json={"post_id": post_id, "user_id": user_id}
        )
    for i in range(comments):
        session.post(
            f"{BASE_URL}/post/comment",
            json={"post_id": post_id, "user_id": user_id, "text": "Great post!"}
        )
    
    def check_stats():
        payload = { "post_id": post_id }
        stats_resp = session.get(
            f"{BASE_URL}/reaction/stats",
            json=payload
        )
        if stats_resp.status_code != 200:
            return False
        stats = stats_resp.json()
        return stats["views"] == views and stats["likes"] == likes and stats["comments"] == comments
    
    assert wait_for_condition(check_stats), "Stats not updated"
    session.post(
        f"{BASE_URL}/user/logout"
    )

    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "strongpassword"
    email = f"{username}@mail.ru"

    response = create_user(username, password, email)
    user_id = response.json()["id"]
    session = login_user(username, password)

    payload = {
        "post_id": post_id,
        "user_id": user_id,
        "page_size": 3,
        "page_token": "",
    }

    response = session.get(
        f"{BASE_URL}/post/comments",
        json=payload
    )
    assert response.status_code == 200
    response = response.json()
    assert len(response["comments"]) == 3
    payload["page_token"] = response["next_page_token"]

    response = session.get(
        f"{BASE_URL}/post/comments",
        json=payload
    )
    assert response.status_code == 200
    response = response.json()
    assert len(response["comments"]) == 3
    payload["page_token"] = response["next_page_token"]

    response = session.get(
        f"{BASE_URL}/post/comments",
        json=payload
    )
    assert response.status_code == 200
    response = response.json()
    assert len(response["comments"]) == 1
    assert response["next_page_token"] == ''
