from __future__ import annotations

import os
from functools import wraps
from pathlib import Path
from typing import Callable, Any

from flask import Flask, flash, redirect, render_template, request, send_from_directory, session, url_for

from database import get_dashboard_stats, get_recent_scans, get_scan_detail, init_db, save_scan_result
from scanner_core import REPORTS_DIR, perform_scan, validate_target

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.secret_key = os.environ.get("NETWATCH_SECRET", "change-this-secret-for-demo")

DEMO_USERNAME = os.environ.get("NETSENTINEL_USER", "admin")
DEMO_PASSWORD = os.environ.get("NETSENTINEL_PASS", "admin123")

init_db()


def login_required(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_USERNAME and password == DEMO_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            flash("Giriş başarılı. NetWatch dashboard hazır.", "success")
            return redirect(url_for("dashboard"))
        flash("Kullanıcı adı veya şifre hatalı.", "danger")
    return render_template("login.html", username=DEMO_USERNAME, password=DEMO_PASSWORD)


@app.route("/logout")
def logout():
    session.clear()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    stats = get_dashboard_stats()
    recent_scans = get_recent_scans(limit=5)
    return render_template("dashboard.html", stats=stats, recent_scans=recent_scans)


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "fast")
    arguments = {
        "fast": "-F -sV",
        "basic": "-F",
        "service": "-sV --top-ports 100",
    }.get(scan_type, "-F -sV")

    try:
        validate_target(target)
        result = perform_scan(target, arguments=arguments)
        scan_id = save_scan_result(result)
        if result.get("warning"):
            flash(result["warning"], "warning")
        if result.get("baseline_created"):
            flash("İlk tarama baseline olarak kaydedildi.", "info")
        flash("Tarama tamamlandı ve sonuçlar kaydedildi.", "success")
        return redirect(url_for("scan_detail", scan_id=scan_id))
    except Exception as exc:
        flash(str(exc), "danger")
        return redirect(url_for("dashboard"))


@app.route("/history")
@login_required
def history():
    scans = get_recent_scans(limit=50)
    return render_template("history.html", scans=scans)


@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id: int):
    detail = get_scan_detail(scan_id)
    if detail is None:
        flash("Tarama bulunamadı.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("scan_result.html", detail=detail)


@app.route("/reports/<path:filename>")
@login_required
def reports(filename: str):
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
