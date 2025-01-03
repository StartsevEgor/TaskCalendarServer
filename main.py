import bcrypt
import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from firebase_admin import messaging, credentials, initialize_app

from flask import Flask, request, jsonify

DB_PATH = 'database.db'
TOKEN_TTL = 60
app = Flask(__name__)
sessions = {}

# Инициализация Firebase
cred = credentials.Certificate("serviceAccountKey.json")
initialize_app(cred)


def send_push_notification(title, body, token):
    message = messaging.Message(
        notification=messaging.Notification(title=title, body=body),
        token=token,
    )
    messaging.send(message)


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


def execute_query(query: str, params=(), fetch_all=''):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall() if fetch_all == "y" else (cursor.fetchone() if fetch_all else None)
    except sqlite3.Error as e:
        print(f"SQL Error: {e}")
        return None


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


def ttl_check(expires_at: datetime):
    return expires_at < datetime.now()


def token_check(token):
    session = sessions.get(token)
    if not session:
        return jsonify({"error": "Пользователь еще не вошел в систему"}), 400
    if not ttl_check(session["expires_at"]):
        del sessions[token]
        return jsonify({"error": "Истёк срок действия токена"}), 400
    session["expires_at"] = datetime.now() + timedelta(minutes=TOKEN_TTL)
    return None


def get_user_id(login_):
    query_id = '''
        SELECT ID FROM Employees
        WHERE login = ?
        LIMIT 1
    '''
    return execute_query(query_id, (login_,), fetch_all="n")[0]


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    position = data['position']
    login_ = data['login']
    password = data['password']
    firebase_token = data['firebase_token']

    query = '''
            SELECT 1 FROM Employees
            WHERE login = ?
            LIMIT 1
        '''
    if execute_query(query, (login_,), fetch_all="n") is not None:
        return jsonify({"error": "Пользователь уже существует"}), 400

    # Хэшируем пароль перед сохранением
    hashed_password = hash_password(password)
    query2 = 'INSERT INTO Employees (name, position, hashed_password, login, firebase_token) VALUES (?, ?, ?, ?, ?)'
    execute_query(query2, (username, position, hashed_password, login_, firebase_token))
    return jsonify({"message": "Пользователь успешно зарегистрировался", "id": get_user_id(login_)}), 201


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
    hashed_password = execute_query(query, (login_,), fetch_all="n")[0]
    if not hashed_password:
        return jsonify({"error": "Пользователь ещё не зарегистрирован"}), 400
    if hashed_password and check_password(password, hashed_password):
        token = str(uuid.uuid4())
        sessions[token] = {"login": login_, "expires_at": datetime.now() + timedelta(minutes=TOKEN_TTL)}
        return jsonify({"token": token, "id": get_user_id(login_)})
    return jsonify({"error": "Неверные учетные данные"}), 401


# Получение контрактов в диапазоне дат
@app.route('/get_contracts', methods=['POST'])
def get_contracts():
    data = request.json
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
        token = data['token']
        check = token_check(token)
        if check:
            return check

        query_position = '''
            SELECT position FROM Employees
            WHERE login = ?
            LIMIT 1
        '''
        position = execute_query(query_position, (sessions[token]["login"],), fetch_all="n")[0]
        if not position:
            return jsonify({"error": "Пользователь не найден"}), 400

        if position not in ["admin"]:
            user_id = get_user_id(sessions[token])
            if not user_id:
                return jsonify({"error": "ID пользователя не найден"}), 400

            query_employee = '''
                SELECT * FROM Contracts
                WHERE (ID IN (
                    SELECT ContractID FROM EmployeesContracts
                    WHERE EmployeeID = ?
                ))
                AND (start_date <= ?) AND (end_date >= ?)
            '''
            result = execute_query(query_employee, (user_id, end_date, start_date), fetch_all="y")
        else:
            query_admin = '''
                        SELECT * FROM Contracts
                        WHERE (start_date <= ?) AND (end_date >= ?)
                    '''
            result = execute_query(query_admin, (end_date, start_date), fetch_all="y")

        formatted_result = [format_contract_row(row) for row in result]
        return jsonify(formatted_result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


import os

# Путь для хранения файлов контрактов
CONTRACT_FILES_PATH = 'contract_files'

# Создание папки для файлов, если её нет
if not os.path.exists(CONTRACT_FILES_PATH):
    os.makedirs(CONTRACT_FILES_PATH)


@app.route('/add_contract', methods=['POST'])
def add_contract():
    data = request.form  # Используем request.form для текстовых данных
    token = data.get('token')

    # Проверка токена
    check = token_check(token)
    if check:
        return check

    # Проверка, что пользователь - администратор
    query_position = '''
        SELECT position FROM Employees
        WHERE login = ?
        LIMIT 1
    '''
    position = execute_query(query_position, (sessions[token]["login"],), fetch_all="n")
    if not position or position[0] != "admin":
        return jsonify({"error": "Доступ запрещён. Только администраторы могут добавлять контракты"}), 403

    # Извлечение данных контракта
    title = data.get('title')
    marker = data.get('marker')
    number = data.get('number')
    start_date = data.get('start_date')
    end_date = data.get('end_date')

    # Проверка, что обязательные поля заполнены
    if not (title and marker and number and start_date and end_date):
        return jsonify({"error": "Не все обязательные поля заполнены"}), 400

    # Обработка файла
    file = request.files.get('file')
    file_path = None
    if file:
        # Проверка расширения файла
        allowed_extensions = {'docx', 'xlsx'}
        if file.filename.split('.')[-1].lower() not in allowed_extensions:
            return jsonify({"error": "Недопустимый формат файла. Разрешены только .docx и .xlsx"}), 400

        # Генерация уникального имени файла
        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        file_path = os.path.join(CONTRACT_FILES_PATH, unique_filename)

        # Сохранение файла
        try:
            file.save(file_path)
        except Exception as e:
            return jsonify({"error": f"Ошибка сохранения файла: {str(e)}"}), 500

    try:
        # Добавление контракта в базу данных
        query_insert = '''
            INSERT INTO Contracts (title, marker, number, start_date, end_date, file)
            VALUES (?, ?, ?, ?, ?, ?)
        '''
        execute_query(query_insert, (title, marker, number, start_date, end_date, unique_filename))
        return jsonify({"message": "Контракт успешно добавлен"}), 201
    except Exception as e:
        # Удаление файла в случае ошибки
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({"error": str(e)}), 500


# Добавление связи сотрудника и контракта
@app.route('/assign_employee_to_contract', methods=['POST'])
def assign_employee_to_contract():
    data = request.json
    token = data['token']
    check = token_check(token)
    if check:
        return check
    try:
        query = 'INSERT INTO Requests (ID, ContractID, EmployeeID) VALUES (?, ?, ?)'
        execute_query(query, (str(uuid.uuid4()), data['contract_id'], data['employee_id']))

        query_admin = '''
            SELECT firebase_token FROM Employees
            WHERE login = ?
            LIMIT 1
        '''
        admin_token = execute_query(query_admin, (sessions[token]['login'],), fetch_all="n")

        # Уведомляем администратора через Firebase
        send_push_notification(
            "Новый запрос на подтверждение",
            f"Контракт {data['contract_id']} отправлен на подтверждение",
            admin_token
        )
        return jsonify({"message": "Request sent for approval"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Просмотр, одобрение или отклонение запросов
@app.route('/review_assignment_requests', methods=['POST'])
def review_assignment_requests():
    data = request.json
    token = data['token']
    check = token_check(token)
    if check:
        return check

    # Проверяем роль пользователя
    query_position = '''
        SELECT position FROM Employees
        WHERE login = ?
        LIMIT 1
    '''
    position = execute_query(query_position, (sessions[token]["login"],), fetch_all="n")[0]
    if position != 'admin':
        return jsonify({"error": "Доступ разрешён только администраторам"}), 403

    query = '''
        SELECT ID, EmployeeID, ContractID, Status, RequestedAt
        FROM AssignmentRequests
        WHERE Status = 'PENDING'
    '''
    pending_requests = execute_query(query, fetch_all="y")
    formatted_requests = [
        {"request_id": r[0], "employee_id": r[1], "contract_id": r[2], "status": r[3], "requested_at": r[4]}
        for r in pending_requests
    ]
    return jsonify(formatted_requests), 200


@app.route('/update_assignment_request', methods=['POST'])
def update_assignment_request():
    data = request.json
    token = data['token']
    check = token_check(token)
    if check:
        return check

    query_position = '''
        SELECT position FROM Employees
        WHERE login = ?
        LIMIT 1
    '''
    position = execute_query(query_position, (sessions[token]["login"],), fetch_all="n")[0]
    if position != 'admin':
        return jsonify({"error": "Доступ разрешён только администраторам"}), 403

    try:
        request_id = data['request_id']
        new_status = data['status']  # APPROVED или REJECTED

        if new_status not in ['APPROVED', 'REJECTED']:
            return jsonify({"error": "Некорректный статус"}), 400

        if new_status == 'APPROVED':
            # Получаем данные о запросе
            query_request = '''
                SELECT EmployeeID, ContractID
                FROM AssignmentRequests
                WHERE ID = ?
            '''
            request_data = execute_query(query_request, (request_id,), fetch_all="n")
            if request_data:
                employee_id, contract_id = request_data

                # Добавляем связь сотрудника и контракта
                query_assign = '''
                    INSERT INTO EmployeesContracts (EmployeeID, ContractID)
                    VALUES (?, ?)
                '''
                execute_query(query_assign, (employee_id, contract_id))

        # Обновляем статус запроса
        query_update = '''
            UPDATE AssignmentRequests
            SET Status = ?
            WHERE ID = ?
        '''
        execute_query(query_update, (new_status, request_id))

        return jsonify({"message": f"Запрос {new_status.lower()} успешно"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Обновление статуса запроса
@app.route('/update_assignment_request', methods=['POST'])
def update_assignment_request():
    data = request.json
    token = data['token']
    check = token_check(token)
    if check:
        return check

    query_position = '''
        SELECT position FROM Employees
        WHERE login = ?
        LIMIT 1
    '''
    position = execute_query(query_position, (sessions[token]["login"],), fetch_all="n")[0]
    if position != 'admin':
        return jsonify({"error": "Доступ разрешён только администраторам"}), 403

    try:
        request_id = data['request_id']
        new_status = data['status']  # APPROVED или REJECTED

        if new_status not in ['APPROVED', 'REJECTED']:
            return jsonify({"error": "Некорректный статус"}), 400

        if new_status == 'APPROVED':
            # Получаем данные о запросе
            query_request = '''
                SELECT EmployeeID, ContractID
                FROM AssignmentRequests
                WHERE ID = ?
            '''
            request_data = execute_query(query_request, (request_id,), fetch_all="n")
            if request_data:
                employee_id, contract_id = request_data

                # Добавляем связь сотрудника и контракта
                query_assign = '''
                    INSERT INTO EmployeesContracts (EmployeeID, ContractID)
                    VALUES (?, ?)
                '''
                execute_query(query_assign, (employee_id, contract_id))

            # Удаляем запрос после обработки
            query_delete = '''
                DELETE FROM AssignmentRequests
                WHERE ID = ?
            '''
            execute_query(query_delete, (request_id,))
            return jsonify({"message": f"Запрос успешно одобрен и удалён"}), 200

        elif new_status == 'REJECTED':
            # Удаляем отклонённый запрос
            query_delete = '''
                DELETE FROM AssignmentRequests
                WHERE ID = ?
            '''
            execute_query(query_delete, (request_id,))
            return jsonify({"message": f"Запрос успешно отклонён и удалён"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    if not os.path.isfile(DB_PATH):
        make_database()
    app.run(port=8080, host='0.0.0.0')
