from app import app, db

print("Creating the database...")

# Create all database tables within the application context
# This ensures that Flask works with the correct configuration.
with app.app_context():
    db.create_all()

print("Database 'site.db' has been created successfully!")
