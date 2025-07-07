# check_db.py
from app import app, db, User, Location, Route

print("--- Veritabanı Kontrol Script'i Başlatıldı ---")

with app.app_context():
    print("\n--- KULLANICILAR ---")
    users = User.query.all()
    if not users:
        print("Kullanıcı Bulunamadı.")
    for user in users:
        print(f"ID: {user.id}, Kullanıcı Adı: {user.username}, Rol: {user.role}")

    print("\n--- KONUMLAR ---")
    locations = Location.query.all()
    if not locations:
        print("Konum Bulunamadı.")
    for loc in locations:
        print(f"ID: {loc.id}, Konum Adı: {loc.name}, Sahip ID: {loc.user_id}")

    print("\n--- ROTALAR ---")
    routes = Route.query.all()
    if not routes:
        print("Rota Bulunamadı.")
    for route in routes:
        print(f"ID: {route.id}, Rota Adı: {route.name}, Sahip ID: {route.user_id}, Başlangıç ID: {route.start_location_id}, Bitiş ID: {route.end_location_id}")

print("\n--- Kontrol Tamamlandı ---")