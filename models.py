from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.String(10), nullable=False)
    end_date = db.Column(db.String(10), nullable=False)
    employees = db.Column(db.String(200), nullable=True)
