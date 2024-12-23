from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

employee_contract = db.Table('employee_contract',
                             db.Column('employee_id', db.Integer, db.ForeignKey('employee.id'), primary_key=True),
                             db.Column('contract_id', db.Integer, db.ForeignKey('contract.id'), primary_key=True)
                             )


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = title = db.Column(db.String(50), nullable=False)
    contracts = db.relationship('Contract', secondary=employee_contract, backref=db.backref('employees', lazy=True))


class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.String(10), nullable=False)
    end_date = db.Column(db.String(10), nullable=False)
    marker = db.Column(db.String(7), nullable=True)
    transferred_to_production = db.Column()
