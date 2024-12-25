import bcrypt
import os
import sqlite3
import uuid
from datetime import datetime

from flask import Flask, request, jsonify

DB_PATH = 'database.db'
app = Flask(__name__)
sessions = {}


def make_database():
    con = sqlite3.connect("database.sqlite")
    cur = con.cursor()
    with open("db_settings.txt", "r") as f:
        cur.executescript(f.read())


# Хэширование пароля
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


# Проверка пароля
def check_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def execute_query(query, params=(), fetch_all=''):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        if fetch_all:
            return cursor.fetchall() if fetch_all == "y" else cursor.fetchone()


# Вспомогательная функция для преобразования данных

def format_contract_row(row):
    return {
        "id": row[0],
        "title": row[1],
        "marker": row[2],
        "number": row[3],
        "start_date": row[4],
        "end_date": row[5],
        "transferred_to_production": bool(row[6]),
        "file": row[7],
        "material_is_purchased": bool(row[8]),
        "produced": bool(row[9]),
        "painted": bool(row[10]),
        "completed": bool(row[11]),
        "salary_is_taken_into_account": bool(row[12]),
    }


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    position = data['position']
    login_ = data['login']
    password = data['password']

    query = '''
            SELECT 1 FROM Employees
            WHERE login = ?
            LIMIT 1
        '''
    if execute_query(query, (login_,), fetch_all="n") is not None:
        return jsonify({"error": "User already exists"}), 400

    # Хэшируем пароль перед сохранением
    hashed_password = hash_password(password)
    query2 = 'INSERT INTO Employees (name, position, hashed_password, login) VALUES (?, ?, ?, ?)'
    execute_query(query2, (username, position, hashed_password, login_), fetch_all="n")
    return jsonify({"message": "User registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    login_ = data['login']
    password = data['password']

    query = '''
                SELECT hashed_password FROM Employees
                WHERE login = ?
                LIMIT 1
            '''

    if check_password(password, execute_query(query, (login_,), fetch_all="n")):
        token = str(uuid.uuid4())
        sessions[token] = login_
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401


# Получение контрактов в диапазоне дат
@app.route('/get_contracts', methods=['POST'])
def get_contracts():
    data = request.json
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')

        query = '''
            SELECT * FROM Contracts
            WHERE (start_date <= ?) AND (end_date >= ?) 
        '''
        result = execute_query(query, (end_date, start_date))

        formatted_result = [format_contract_row(row) for row in result]
        return jsonify(formatted_result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Получение сотрудников
@app.route('/get_employees', methods=['GET'])
def get_employees():
    try:
        query = 'SELECT * FROM Employees'
        result = execute_query(query)
        formatted_result = [
            {"id": row[0], "name": row[1], "position": row[2]} for row in result
        ]
        return jsonify(formatted_result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Добавление нового сотрудника
@app.route('/add_employee', methods=['POST'])
def add_employee():
    data = request.json
    try:
        query = 'INSERT INTO Employees (name, position) VALUES (?, ?)'
        execute_query(query, (data['name'], data.get('position', '')), fetch_all=False)
        return jsonify({"message": "Employee added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Получение расписания
@app.route('/get_calendar', methods=['POST'])
def get_calendar():
    data = request.json
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')

        query = '''
            SELECT * FROM Calendar
            WHERE (start >= ?) AND (end <= ?)
        '''
        result = execute_query(query, (start_date, end_date))

        formatted_result = [
            {
                "id": row[0],
                "start": row[1],
                "end": row[2],
                "contract": row[3],
                "montage": row[4],
            } for row in result
        ]
        return jsonify(formatted_result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Добавление связи сотрудника и контракта
@app.route('/assign_employee_to_contract', methods=['POST'])
def assign_employee_to_contract():
    data = request.json
    try:
        query = 'INSERT INTO EmployeesContracts (EmployeeID, ContractID) VALUES (?, ?)'
        execute_query(query, (data['employee_id'], data['contract_id']), fetch_all=False)
        return jsonify({"message": "Employee assigned to contract successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    if not os.path.isfile(DB_PATH):
        make_database()
    app.run(port=8080, host='0.0.0.0')
