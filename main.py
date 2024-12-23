from flask import Flask, request, jsonify
from datetime import datetime
import sqlite3
import os

DB_PATH = 'database.db'
app = Flask(__name__)


def make_database():
    con = sqlite3.connect("database.sqlite")
    cur = con.cursor()
    with open("db_settings.txt", "r") as f:
        cur.executescript(f.read())


def execute_query(query, params=(), fetch_all=True):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        if fetch_all:
            return cursor.fetchall()
        return cursor.fetchone()


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
