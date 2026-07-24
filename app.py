import os
import secrets
from datetime import datetime
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, abort, send_from_directory
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from sqlalchemy import or_, func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_UPLOAD_SIZE = 5 * 1024 * 1024

PRODUCT_REPORT_THRESHOLD = 3
USER_REPORT_THRESHOLD = 5


app = Flask(__name__, instance_relative_config=True)
Path(app.instance_path).mkdir(parents=True, exist_ok=True)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SQLALCHEMY_DATABASE_URI="sqlite:///" + str(Path(app.instance_path) / "market.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=MAX_UPLOAD_SIZE,
    UPLOAD_FOLDER=str(UPLOAD_DIR),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "로그인이 필요합니다."
login_manager.login_message_category = "warning"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.String(300), default="")
    role = db.Column(db.String(20), nullable=False, default="user")
    status = db.Column(db.String(20), nullable=False, default="active")
    balance = db.Column(db.Integer, nullable=False, default=10000)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    products = db.relationship("Product", backref="seller", lazy=True)

    @property
    def is_active(self):
        return self.status == "active"

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image_filename = db.Column(db.String(255))
    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="active")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    body = db.Column(db.String(1000), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    target_type = db.Column(db.String(20), nullable=False)
    target_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)

    reporter = db.relationship("User")


class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.role != "admin":
            abort(403)
        return view_func(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def save_image(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename):
        raise ValueError("허용되지 않는 이미지 확장자입니다.")
    original = secure_filename(file_storage.filename)
    ext = original.rsplit(".", 1)[1].lower()
    filename = f"{secrets.token_hex(16)}.{ext}"
    file_storage.save(UPLOAD_DIR / filename)
    return filename


def remove_image(filename):
    if not filename:
        return
    path = UPLOAD_DIR / filename
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def active_user_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if current_user.status != "active":
            flash("휴면 또는 차단된 계정은 이 기능을 사용할 수 없습니다.", "danger")
            return redirect(url_for("index"))
        return view_func(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_now():
    return {"now": datetime.utcnow()}


@app.route("/")
def index():
    latest_products = (
        Product.query
        .filter_by(status="active")
        .order_by(Product.created_at.desc())
        .limit(8)
        .all()
    )
    return render_template("index.html", products=latest_products)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        if not (4 <= len(username) <= 30):
            flash("아이디는 4~30자로 입력하세요.", "danger")
        elif not username.replace("_", "").isalnum():
            flash("아이디는 영문, 숫자, 밑줄만 사용할 수 있습니다.", "danger")
        elif User.query.filter(func.lower(User.username) == username.lower()).first():
            flash("이미 사용 중인 아이디입니다.", "danger")
        elif not (2 <= len(display_name) <= 50):
            flash("계정명은 2~50자로 입력하세요.", "danger")
        elif len(password) < 8:
            flash("비밀번호는 8자 이상이어야 합니다.", "danger")
        elif password != password_confirm:
            flash("비밀번호 확인이 일치하지 않습니다.", "danger")
        else:
            user = User(username=username, display_name=display_name)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("회원가입이 완료되었습니다. 로그인해 주세요.", "success")
            return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter(func.lower(User.username) == username.lower()).first()

        if not user or not user.check_password(password):
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "danger")
        elif user.status != "active":
            flash("현재 로그인할 수 없는 계정입니다.", "danger")
        else:
            login_user(user)
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("로그아웃했습니다.", "info")
    return redirect(url_for("index"))


@app.route("/mypage", methods=["GET", "POST"])
@login_required
@active_user_required
def mypage():
    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        bio = request.form.get("bio", "").strip()
        new_password = request.form.get("new_password", "")

        if not (2 <= len(display_name) <= 50):
            flash("계정명은 2~50자로 입력하세요.", "danger")
        elif len(bio) > 300:
            flash("소개글은 300자 이하로 입력하세요.", "danger")
        elif new_password and len(new_password) < 8:
            flash("새 비밀번호는 8자 이상이어야 합니다.", "danger")
        else:
            current_user.display_name = display_name
            current_user.bio = bio
            if new_password:
                current_user.set_password(new_password)
            db.session.commit()
            flash("프로필이 수정되었습니다.", "success")
            return redirect(url_for("mypage"))

    my_products = Product.query.filter_by(seller_id=current_user.id).order_by(Product.created_at.desc()).all()
    transfers = (
        Transfer.query
        .filter(or_(Transfer.sender_id == current_user.id, Transfer.receiver_id == current_user.id))
        .order_by(Transfer.created_at.desc())
        .limit(20)
        .all()
    )
    return render_template("mypage.html", products=my_products, transfers=transfers)


@app.route("/users/<int:user_id>")
def user_profile(user_id):
    user = db.get_or_404(User, user_id)
    products = Product.query.filter_by(seller_id=user.id, status="active").order_by(Product.created_at.desc()).all()
    return render_template("profile.html", profile_user=user, products=products)


@app.route("/products")
def products():
    q = request.args.get("q", "").strip()
    query = Product.query.filter_by(status="active")
    if q:
        query = query.filter(or_(
            Product.name.ilike(f"%{q}%"),
            Product.description.ilike(f"%{q}%")
        ))
    items = query.order_by(Product.created_at.desc()).all()
    return render_template("products.html", products=items, q=q)


@app.route("/products/new", methods=["GET", "POST"])
@login_required
@active_user_required
def product_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        price_raw = request.form.get("price", "").strip()
        image = request.files.get("image")

        try:
            price = int(price_raw)
        except ValueError:
            price = -1

        if not (1 <= len(name) <= 120):
            flash("상품명은 1~120자로 입력하세요.", "danger")
        elif not description:
            flash("상품 설명을 입력하세요.", "danger")
        elif price < 0:
            flash("가격은 0 이상의 정수여야 합니다.", "danger")
        else:
            try:
                image_filename = save_image(image)
            except ValueError as exc:
                flash(str(exc), "danger")
                return render_template("product_form.html", product=None)

            product = Product(
                name=name,
                description=description,
                price=price,
                image_filename=image_filename,
                seller_id=current_user.id,
            )
            db.session.add(product)
            db.session.commit()
            flash("상품이 등록되었습니다.", "success")
            return redirect(url_for("product_detail", product_id=product.id))

    return render_template("product_form.html", product=None)


@app.route("/products/<int:product_id>")
def product_detail(product_id):
    product = db.get_or_404(Product, product_id)
    if product.status != "active" and (
        not current_user.is_authenticated or
        (current_user.id != product.seller_id and current_user.role != "admin")
    ):
        abort(404)
    return render_template("product_detail.html", product=product)


@app.route("/products/<int:product_id>/edit", methods=["GET", "POST"])
@login_required
@active_user_required
def product_edit(product_id):
    product = db.get_or_404(Product, product_id)
    if current_user.id != product.seller_id and current_user.role != "admin":
        abort(403)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        price_raw = request.form.get("price", "").strip()
        image = request.files.get("image")

        try:
            price = int(price_raw)
        except ValueError:
            price = -1

        if not (1 <= len(name) <= 120) or not description or price < 0:
            flash("입력값을 확인하세요.", "danger")
        else:
            if image and image.filename:
                try:
                    new_image = save_image(image)
                except ValueError as exc:
                    flash(str(exc), "danger")
                    return render_template("product_form.html", product=product)
                remove_image(product.image_filename)
                product.image_filename = new_image

            product.name = name
            product.description = description
            product.price = price
            db.session.commit()
            flash("상품이 수정되었습니다.", "success")
            return redirect(url_for("product_detail", product_id=product.id))

    return render_template("product_form.html", product=product)


@app.route("/products/<int:product_id>/delete", methods=["POST"])
@login_required
def product_delete(product_id):
    product = db.get_or_404(Product, product_id)
    if current_user.id != product.seller_id and current_user.role != "admin":
        abort(403)

    remove_image(product.image_filename)
    db.session.delete(product)
    db.session.commit()
    flash("상품이 삭제되었습니다.", "info")
    return redirect(url_for("mypage" if current_user.role != "admin" else "admin_dashboard"))


# @app.route("/chat", methods=["GET", "POST"])
# @login_required
# @active_user_required
# def public_chat():
#     if request.method == "POST":
#         body = request.form.get("body", "").strip()
#         if not body or len(body) > 1000:
#             flash("메시지는 1~1000자로 입력하세요.", "danger")
#         else:
#             db.session.add(Message(sender_id=current_user.id, receiver_id=None, body=body))
#             db.session.commit()
#             return redirect(url_for("public_chat"))

#     messages = (
#         Message.query
#         .filter_by(receiver_id=None)
#         .order_by(Message.created_at.desc())
#         .limit(100)
#         .all()
#     )
#     messages.reverse()
#     return render_template("chat.html", messages=messages, partner=None)

@app.route("/chat", methods=["GET", "POST"])
@login_required
@active_user_required
def public_chat():
    if request.method == "POST":
        body = request.form.get("body", "").strip()

        if not body or len(body) > 1000:
            flash("메시지는 1~1000자로 입력하세요.", "danger")
        else:
            message = Message(
                sender_id=current_user.id,
                receiver_id=None,
                body=body
            )
            db.session.add(message)
            db.session.commit()

            return redirect(url_for("public_chat"))

    # 전체 채팅 메시지
    messages = (
        Message.query
        .filter_by(receiver_id=None)
        .order_by(Message.created_at.desc())
        .limit(100)
        .all()
    )
    messages.reverse()

    # 현재 사용자가 참여한 1:1 메시지
    private_messages = (
        Message.query
        .filter(
            Message.receiver_id.isnot(None),
            or_(
                Message.sender_id == current_user.id,
                Message.receiver_id == current_user.id
            )
        )
        .order_by(Message.created_at.desc())
        .all()
    )

    # 상대방별 가장 최근 메시지만 저장
    conversations = []
    added_user_ids = set()

    for message in private_messages:
        if message.sender_id == current_user.id:
            partner = message.receiver
        else:
            partner = message.sender

        if partner.id not in added_user_ids:
            conversations.append({
                "partner": partner,
                "last_message": message
            })
            added_user_ids.add(partner.id)

    return render_template(
        "chat.html",
        messages=messages,
        partner=None,
        conversations=conversations
    )

@app.route("/chat/<int:user_id>", methods=["GET", "POST"])
@login_required
@active_user_required
def private_chat(user_id):
    partner = db.get_or_404(User, user_id)
    if partner.id == current_user.id:
        flash("자기 자신과는 1:1 채팅할 수 없습니다.", "warning")
        return redirect(url_for("public_chat"))

    if request.method == "POST":
        body = request.form.get("body", "").strip()
        if not body or len(body) > 1000:
            flash("메시지는 1~1000자로 입력하세요.", "danger")
        else:
            db.session.add(Message(
                sender_id=current_user.id,
                receiver_id=partner.id,
                body=body
            ))
            db.session.commit()
            return redirect(url_for("private_chat", user_id=partner.id))

    messages = (
        Message.query
        .filter(or_(
            db.and_(Message.sender_id == current_user.id, Message.receiver_id == partner.id),
            db.and_(Message.sender_id == partner.id, Message.receiver_id == current_user.id),
        ))
        .order_by(Message.created_at.asc())
        .limit(200)
        .all()
    )
    # return render_template("chat.html", messages=messages, partner=partner)
    return render_template("chat.html", messages=messages, partner=partner, conversations=[])


@app.route("/report/<target_type>/<int:target_id>", methods=["GET", "POST"])
@login_required
@active_user_required
def report(target_type, target_id):
    if target_type not in {"user", "product"}:
        abort(404)

    if target_type == "user":
        target = db.get_or_404(User, target_id)
        if target.id == current_user.id:
            abort(400)
    else:
        target = db.get_or_404(Product, target_id)
        if target.seller_id == current_user.id:
            abort(400)

    if request.method == "POST":
        reason = request.form.get("reason", "").strip()
        duplicate = Report.query.filter_by(
            reporter_id=current_user.id,
            target_type=target_type,
            target_id=target_id,
            status="pending",
        ).first()

        if duplicate:
            flash("이미 처리 대기 중인 신고가 있습니다.", "warning")
        elif not (5 <= len(reason) <= 500):
            flash("신고 사유는 5~500자로 입력하세요.", "danger")
        else:
            db.session.add(Report(
                reporter_id=current_user.id,
                target_type=target_type,
                target_id=target_id,
                reason=reason,
            ))
            db.session.commit()
            apply_report_thresholds(target_type, target_id)
            flash("신고가 접수되었습니다.", "success")
            return redirect(url_for("index"))

    return render_template("report.html", target_type=target_type, target=target)


def apply_report_thresholds(target_type, target_id):
    count = Report.query.filter_by(
        target_type=target_type,
        target_id=target_id,
        status="pending"
    ).count()

    if target_type == "product" and count >= PRODUCT_REPORT_THRESHOLD:
        product = db.session.get(Product, target_id)
        if product:
            product.status = "blocked"
    elif target_type == "user" and count >= USER_REPORT_THRESHOLD:
        user = db.session.get(User, target_id)
        if user and user.role != "admin":
            user.status = "dormant"

    db.session.commit()


@app.route("/transfer", methods=["GET", "POST"])
@login_required
@active_user_required
def transfer():
    if request.method == "POST":
        receiver_username = request.form.get("receiver_username", "").strip()
        amount_raw = request.form.get("amount", "").strip()

        receiver = User.query.filter(func.lower(User.username) == receiver_username.lower()).first()
        try:
            amount = int(amount_raw)
        except ValueError:
            amount = 0

        if not receiver:
            flash("상대방 아이디를 찾을 수 없습니다.", "danger")
        elif receiver.id == current_user.id:
            flash("자기 자신에게 송금할 수 없습니다.", "danger")
        elif receiver.status != "active":
            flash("현재 송금할 수 없는 사용자입니다.", "danger")
        elif amount <= 0:
            flash("송금액은 1원 이상이어야 합니다.", "danger")
        elif current_user.balance < amount:
            flash("잔액이 부족합니다.", "danger")
        else:
            try:
                current_user.balance -= amount
                receiver.balance += amount
                db.session.add(Transfer(
                    sender_id=current_user.id,
                    receiver_id=receiver.id,
                    amount=amount
                ))
                db.session.commit()
                flash(f"{receiver.username}님에게 {amount:,}원을 송금했습니다.", "success")
                return redirect(url_for("mypage"))
            except Exception:
                db.session.rollback()
                flash("송금 처리 중 오류가 발생했습니다.", "danger")

    return render_template("transfer.html")


@app.route("/admin")
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    products = Product.query.order_by(Product.created_at.desc()).all()
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template("admin.html", users=users, products=products, reports=reports)


@app.route("/admin/reports/<int:report_id>/process", methods=["POST"])
@admin_required
def admin_process_report(report_id):
    report = db.get_or_404(Report, report_id)
    report.status = "processed"
    report.processed_at = datetime.utcnow()
    db.session.commit()
    flash("신고를 처리 상태로 변경했습니다.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.role == "admin":
        flash("관리자 계정 상태는 변경할 수 없습니다.", "warning")
    else:
        user.status = "active" if user.status != "active" else "dormant"
        db.session.commit()
        flash("사용자 상태를 변경했습니다.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/products/<int:product_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_product(product_id):
    product = db.get_or_404(Product, product_id)
    product.status = "active" if product.status != "active" else "blocked"
    db.session.commit()
    flash("상품 상태를 변경했습니다.", "success")
    return redirect(url_for("admin_dashboard"))


@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="접근 권한이 없습니다."), 403


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="페이지를 찾을 수 없습니다."), 404


@app.errorhandler(413)
def too_large(_):
    return render_template("error.html", code=413, message="업로드 파일은 5MB 이하여야 합니다."), 413


def create_initial_admin():
    admin = User.query.filter_by(username="admin").first()
    if admin is None:
        admin = User(
            username="admin",
            display_name="관리자",
            role="admin",
            status="active",
            balance=0,
            bio="플랫폼 관리자 계정",
        )
        admin.set_password(os.environ.get("ADMIN_PASSWORD", "ChangeMe123!"))
        db.session.add(admin)
        db.session.commit()


with app.app_context():
    db.create_all()
    create_initial_admin()


if __name__ == "__main__":
    app.run(debug=True)
