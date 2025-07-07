from app import app, db, User
from werkzeug.security import generate_password_hash

# You can define the admin's username, email, and password here
ADMIN_USERNAME = 'admin'
ADMIN_EMAIL = 'admin@project.com'
ADMIN_PASSWORD = 'AdminPassword123!'

with app.app_context():
    # Check if an admin user already exists
    if User.query.filter_by(role='admin').first():
        print("An admin user already exists.")
    else:
        # If not, create a new admin user
        hashed_password = generate_password_hash(ADMIN_PASSWORD)
        admin_user = User(
            username=ADMIN_USERNAME,
            email=ADMIN_EMAIL,
            password_hash=hashed_password,
            role='admin' # Set the role to 'admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{ADMIN_USERNAME}' has been created successfully.")
