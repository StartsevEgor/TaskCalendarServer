from flask import Flask, request, jsonify
from models import db, Contract
from datetime import datetime

app = Flask(__name__)

# Настройки базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


def create_tables():
    db.create_all()


# Добавление нового контракта (POST-запрос)
@app.route('/add', methods=['POST'])
def add_contract():
    data = request.json
    try:
        new_contract = Contract(
            title=data['title'],
            start_date=data['start_date'],
            end_date=data['end_date'],
            employees=data.get('employees', '')
        )
        db.session.add(new_contract)
        db.session.commit()
        return jsonify({"message": "Contract added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Получение контрактов в указанном диапазоне (POST-запрос)
@app.route('/get', methods=['POST'])
def get_contracts():
    data = request.json
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')

        # Получение всех контрактов, которые затрагивают указанный диапазон
        contracts = Contract.query.filter(
            (db.func.date(Contract.start_date) <= end_date) &
            (db.func.date(Contract.end_date) >= start_date)
        ).all()

        result = [
            {
                "id": contract.id,
                "title": contract.title,
                "start_date": contract.start_date,
                "end_date": contract.end_date,
                "employees": contract.employees
            } for contract in contracts
        ]

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    with app.app_context():  # Создание контекста приложения для работы с базой данных
        create_tables()
    app.run(port=8080, host='0.0.0.0')
