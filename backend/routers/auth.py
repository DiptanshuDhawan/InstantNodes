"""Account endpoints: sign up, sign in, sign out, current user and password change.

The handlers are plain functions so FastAPI runs them in its thread pool: password hashing
takes about 0.2 s and must not block the event loop that serves the consoles.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from models.schemas import LoginRequest, PasswordChangeRequest, RegisterRequest
from services import auth

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request, response: Response):
    ip = auth.client_ip(request)
    wait = auth.REGISTRATIONS.retry_after(ip)
    if wait:
        raise auth.too_many(wait, "Too many accounts were created from this network.")
    auth.REGISTRATIONS.record(ip)

    name = body.name.strip()
    email = auth.normalise_email(body.email)
    problem = (
        auth.name_problem(name)
        or auth.email_problem(email)
        or auth.password_problem(body.password, email)
    )
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    try:
        user = auth.create_user(email, name, body.password)
    except auth.EmailTaken:
        raise HTTPException(
            status_code=409, detail="An account with this email already exists. Sign in instead."
        ) from None

    token = auth.create_session(user["id"], request.headers.get("user-agent", ""))
    auth.set_session_cookie(response, token)
    return {"user": auth.public_user(user)}


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response):
    ip = auth.client_ip(request)
    email = auth.normalise_email(body.email)
    key = f"{ip}|{email}"
    wait = max(auth.LOGIN_FAILURES.retry_after(key), auth.LOGIN_FAILURES_BY_IP.retry_after(ip))
    if wait:
        raise auth.too_many(wait, "Too many failed sign-in attempts.")

    user = auth.authenticate(email, body.password) if email and body.password else None
    if user is None:
        auth.LOGIN_FAILURES.record(key)
        auth.LOGIN_FAILURES_BY_IP.record(ip)
        raise HTTPException(status_code=401, detail="The email or password is incorrect.")
    auth.LOGIN_FAILURES.reset(key)

    token = auth.create_session(user["id"], request.headers.get("user-agent", ""))
    auth.set_session_cookie(response, token)
    return {"user": auth.public_user(user)}


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    everywhere: bool = Query(False, description="Sign out on every device"),
):
    token = request.cookies.get(auth.COOKIE_NAME)
    user = auth.user_for_token(token)
    if user is not None and everywhere:
        auth.delete_user_sessions(user["id"])
    else:
        auth.delete_session(token)
    auth.clear_session_cookie(response)
    return {"message": "Signed out."}


@router.get("/me")
def me(request: Request):
    """The signed-in user, or ``{"user": null}``: being signed out is not an error here."""
    user = auth.user_for_token(request.cookies.get(auth.COOKIE_NAME))
    return {"user": auth.public_user(user) if user else None}


@router.post("/password")
def change_password(body: PasswordChangeRequest, user: dict = Depends(auth.current_user)):
    key = str(user["id"])
    wait = auth.PASSWORD_FAILURES.retry_after(key)
    if wait:
        raise auth.too_many(wait, "Too many wrong current passwords.")
    if not auth.password_matches(user["id"], body.current_password):
        auth.PASSWORD_FAILURES.record(key)
        raise HTTPException(status_code=400, detail="The current password is incorrect.")
    problem = auth.password_problem(body.new_password, user["email"])
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    if body.new_password == body.current_password:
        raise HTTPException(
            status_code=400, detail="The new password must be different from the current one."
        )
    auth.PASSWORD_FAILURES.reset(key)
    auth.set_password(user["id"], body.new_password, keep_session_id=user["auth_session_id"])
    return {"message": "Password changed. You were signed out on your other devices."}
