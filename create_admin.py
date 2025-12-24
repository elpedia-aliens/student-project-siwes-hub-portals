from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    email = "admin@siwes.com"

    existing_admin = User.query.filter_by(email=email).first()

    if existing_admin:
        print("❗ Admin already exists")
    else:
        admin = User(
            fullname="Super Admin",
            email=email,
            password=generate_password_hash("admin123"),
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin created successfully")

print("DONE")