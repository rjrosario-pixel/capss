from main import create_app
from models.db_models import db

app = create_app()

with app.app_context():
    # Your logic inside the app context
    print("App context is working.")
    # Example: print all users
    from models.db_models import User
    users = User.query.all()
    for user in users:
        print(user.username)
