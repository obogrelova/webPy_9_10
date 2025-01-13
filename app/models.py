from app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60),nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    clicks = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'User {self.username} - clicks: {self.clicks}'