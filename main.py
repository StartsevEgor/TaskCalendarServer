import bcrypt
import os
import sqlite3
import uuid
import json
from datetime import datetime, timedelta
from firebase_admin import messaging, credentials, initialize_app
from flask import Flask, request, jsonify, send_file

# Путь для хранения файлов контрактов
CONTRACT_FILES_PATH = 'contract_files'

DB_PATH = 'database.db'
ACCESS_TOKEN_TTL = 30
REFRESH_TOKEN_TTL = 7
app = Flask(__name__)
sessions = {}

# Инициализация Firebase
cred = credentials.Certificate("serviceAccountKey.json")
initialize_app(cred)

# Создание папки для файлов, если её нет
if not os.path.exists(CONTRACT_FILES_PATH):
    os.makedirs(CONTRACT_FILES_PATH)


def send_push_notification(title, body, token):
    message = messaging.Message(
        notification=messaging.Notification(title=title, body=body),
        token=token,
    )
    messaging.send(message)


def make_database():
    con = sqlite3.connect("database.db")
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
            if fetch_all == "y":
                result = cursor.fetchall()
            elif fetch_all == "n":
                result = cursor.fetchone()
            elif fetch_all == "t":
                result = bool(cursor.fetchone())
            else:
                result = None
            conn.commit()
            return result
    except sqlite3.Error as e:
        print(f"SQL Error: {e}")
        return [None]


# Вспомогательная функция для преобразования данных

def format_contract_row(row, return_employees=True):
    result = {
        "id": row[0],
        "title": row[1],
        "marker": row[2],
        "number": row[3],
        "start_date": row[4],
        "end_date": row[5],
        "price": row[6],
        "transferred_to_production": row[7] == "true",
        "file": row[8],
        "material_is_purchased": row[9] == "true",
        "produced": row[10] == "true",
        "painted": row[11] == "true",
        "completed": row[12] == "true",
        "salary_is_taken_into_account": row[13] == "true"
    }
    if return_employees:
        result["employees"] = row[14]
    print(result)
    return result


def ttl_check(expires_at: datetime):
    print(expires_at, datetime.now())
    return datetime.now() < expires_at


def token_check(token):
    session = sessions.get(token)
    if not session:
        print("Пользователь еще не вошел в систему")
        return jsonify({"error": "Пользователь еще не вошел в систему"}), 400
    if not ttl_check(session["expires_at"]):
        del sessions[token]
        print("Истёк срок действия токена")
        return jsonify({"error": "Истёк срок действия токена"}), 400
    session["expires_at"] = datetime.now() + timedelta(minutes=ACCESS_TOKEN_TTL)
    return None


def position_check(token, access):
    query_position = '''
            SELECT position FROM Employees
            WHERE login = ?
            LIMIT 1
        '''
    position = execute_query(query_position, (sessions[token]["login"],), fetch_all="n")[0]
    if position not in access:
        return jsonify({"error": f"Доступ разрешён только для {', '.join(access)}"}), 403
    return None


def get_user_id(login_):
    query_id = '''
        SELECT ID FROM Employees
        WHERE login = ?
        LIMIT 1
    '''
    return str(execute_query(query_id, (login_,), fetch_all="n")[0])


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    position = data.get('position')
    login_ = data.get('login')
    password = data.get('password')
    firebase_token = data.get('firebase_token')
    print(1)
    # Проверка, существует ли пользователь с таким логином
    query = '''
        SELECT 1 FROM Employees
        WHERE login = ?
        LIMIT 1
    '''
    if execute_query(query, (login_,), fetch_all="t"):
        return jsonify({"error": "Пользователь с таким логином уже существует"}), 400
    print(2)

    # Проверка, существует ли заявка с таким логином
    query_request = '''
        SELECT 1 FROM RegistrationRequests
        WHERE login = ?
        LIMIT 1
    '''
    if execute_query(query_request, (login_,), fetch_all="t"):
        return jsonify({"error": "Заявка с таким логином уже отправлена"}), 400
    print(3)

    hashed_password = hash_password(password)
    try:
        query_insert = '''
            INSERT INTO RegistrationRequests (name, position, login, hashed_password, firebase_token)
            VALUES (?, ?, ?, ?, ?)
        '''
        execute_query(query_insert, (username, position, login_, hashed_password, firebase_token))
        print(4)
        query_admins = '''
            SELECT firebase_token FROM Employees
            WHERE position = 'admin'
        '''
        admin_tokens = execute_query(query_admins, fetch_all="y")
        print(5)
        if len(admin_tokens) == 0:
            refresh_token = str(uuid.uuid4())
            refresh_token_expires = datetime.now() + timedelta(days=REFRESH_TOKEN_TTL)

            query_add_employee = '''
                INSERT INTO Employees 
                (name, position, login, hashed_password, firebase_token, refresh_token, refresh_token_expires)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            '''
            execute_query(query_add_employee, (username, position, login_, hashed_password,
                                               firebase_token, refresh_token, refresh_token_expires))
            return jsonify({
                "message": "Успешная регистрация первого пользователя компании",
                "refresh_token": refresh_token,
                "refresh_token_expires": refresh_token_expires.isoformat(),
                "id": get_user_id(login_)
            }), 201

        # Уведомляем администраторов через Firebase
        for admin_token in admin_tokens:
            send_push_notification(
                "Подтвердите регистрацию сотрудника",
                f"Сотрудник {username} хочет поступить на должность {position}",
                admin_token
            )
        return jsonify({"message": "Запрос отправлен на подтверждение"}), 201
    except Exception:
        return jsonify({"error": "Ошибка регистрации"}), 400


@app.route('/view_registration_requests', methods=['POST'])
def view_registration_requests():
    data = request.json
    token = data['token']
    check_token, check_position = token_check(token), position_check(token, ["admin"])
    if check_token:
        return check_token
    if check_position:
        return check_position

    # Получаем заявки
    query_requests = '''
        SELECT id, name, position FROM RegistrationRequests
    '''
    requests = execute_query(query_requests, fetch_all="y")
    return jsonify([{"id": r[0], "name": r[1], "position": r[2]} for r in requests]), 200


@app.route('/update_registration_request', methods=['POST'])
def update_registration_request():
    data = request.json
    token = data['token']
    check_token, check_position = token_check(token), position_check(token, ["admin"])
    if check_token:
        return check_token
    if check_position:
        return check_position

    try:
        request_id = data['request_id']
        new_status = data['status']  # APPROVED или REJECTED

        if new_status not in ['APPROVED', 'REJECTED']:
            return jsonify({"error": "Некорректный статус"}), 400

        if new_status == 'APPROVED':
            # Получаем данные о запросе
            query_request = '''
                SELECT name, position, login, hashed_password, firebase_token
                FROM RegistrationRequests
                WHERE ID = ?
            '''
            request_data = execute_query(query_request, (request_id,), fetch_all="n")
            if request_data:
                name, position, login_, hashed_password, firebase_token = request_data

                # Добавляем нового сотрудника
                query_add_employee = '''
                    INSERT INTO Employees (name, position, login, hashed_password, firebase_token)
                    VALUES (?, ?, ?, ?, ?)
                '''
                execute_query(query_add_employee, (name, position, login_, hashed_password, firebase_token))

            # Удаляем запрос после обработки
            query_delete = '''
                DELETE FROM RegistrationRequests
                WHERE ID = ?
            '''
            execute_query(query_delete, (request_id,))
            return jsonify({"message": f"Заявка успешно одобрена и удалена"}), 200

        elif new_status == 'REJECTED':
            # Удаляем отклонённый запрос
            query_delete = '''
                DELETE FROM RegistrationRequests
                WHERE ID = ?
            '''
            execute_query(query_delete, (request_id,))
            return jsonify({"message": f"Заявка успешно отклонена и удалена"}), 200

    except Exception:
        return jsonify({"error": "Ошибка обработки заявки"}), 400


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    login_ = data.get('login')
    password = data.get('password')

    query = '''
        SELECT hashed_password FROM Employees
        WHERE login = ?
        LIMIT 1
    '''
    hashed_password = execute_query(query, (login_,), fetch_all="n")[0]
    if not hashed_password:
        return jsonify({"error": "Пользователь ещё не зарегистрирован"}), 400
    if hashed_password and check_password(password, hashed_password):
        refresh_token = str(uuid.uuid4())
        refresh_token_expires = datetime.now() + timedelta(days=REFRESH_TOKEN_TTL)

        update_query = '''
                    UPDATE Employees
                    SET refresh_token = ?, refresh_token_expires = ?
                    WHERE login = ?
                '''
        execute_query(update_query, (refresh_token, refresh_token_expires, login_))

        return jsonify({
            "refresh_token": refresh_token,
            "refresh_token_expires": refresh_token_expires.isoformat(),
            "id": get_user_id(login_)
        })
    return jsonify({"error": "Неверные учетные данные"}), 401


@app.route('/login_with_token', methods=['POST'])
def login_with_token():
    data = request.json
    login_ = data.get('login')
    refresh_token = data.get('refresh_token')
    firebase_token = data.get('firebase_token')

    # Проверка валидности refresh_token
    query = '''
        SELECT refresh_token, refresh_token_expires
        FROM Employees
        WHERE login = ?
        LIMIT 1
    '''
    result = execute_query(query, (login_,), fetch_all="n")

    if not result:
        return jsonify({"error": "Пользователь не найден"}), 404

    db_token, expires_at = result
    if db_token != refresh_token or datetime.now() > datetime.fromisoformat(expires_at):
        return jsonify({"error": "Токен недействителен или истёк"}), 401

    # Генерация нового refresh_token и access_token
    new_refresh_token = str(uuid.uuid4())
    new_refresh_token_expires = datetime.now() + timedelta(days=REFRESH_TOKEN_TTL)
    access_token = str(uuid.uuid4())  # Краткосрочный токен
    access_token_expires = datetime.now() + timedelta(minutes=ACCESS_TOKEN_TTL)

    # Обновление refresh_token в базе данных
    update_query = '''
        UPDATE Employees
        SET firebase_token = ?, refresh_token = ?, refresh_token_expires = ?
        WHERE login = ?
    '''
    execute_query(update_query, (firebase_token, new_refresh_token, new_refresh_token_expires, login_))
    sessions[access_token] = {"login": login_, "expires_at": access_token_expires}
    # Возврат токенов
    return jsonify({
        "refresh_token": new_refresh_token,
        "refresh_token_expires": new_refresh_token_expires,
        "access_token": access_token,
    }), 200


# Получение контрактов в диапазоне дат
@app.route('/get_contracts', methods=['POST'])
def get_contracts():
    data = request.json
    print(data)
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d')
        token = data['access_token']
        check = token_check(token)
        if check:
            return check

        query_position = '''
            SELECT position FROM Employees
            WHERE login = ?
            LIMIT 1
        '''
        print(0.1)
        position = execute_query(query_position, (sessions[token]["login"],), fetch_all="n")[0]
        print(0.2)
        if not position:
            print(1)
            return jsonify({"error": "Пользователь не найден"}), 400

        if position not in ["admin"]:
            user_id = get_user_id(sessions[token]["login"])
            if not user_id:
                print(2)
                return jsonify({"error": "ID пользователя не найден"}), 400

            query_employee = '''
                SELECT * FROM Contracts
                WHERE (ID IN (
                    SELECT ContractID FROM EmployeesContracts
                    WHERE EmployeeID = ?
                ))
                AND (start_date <= ?) AND (end_date >= ?)
            '''
            print(0.3)
            result = execute_query(query_employee, (user_id, end_date, start_date), fetch_all="y")
            print(0.4)
        else:
            query_admin = '''
                        SELECT * FROM Contracts
                        WHERE (start_date <= ?) AND (end_date >= ?)
                    '''
            print(0.5)
            result = execute_query(query_admin, (end_date, start_date), fetch_all="y")
            print(0.6)

        # Добавляем список сотрудников для каждого контракта
        enriched_result = []
        for row in result:
            contract_id = row[0]  # ID контракта
            query_employees = '''
                    SELECT name FROM Employees
                    WHERE ID IN (
                        SELECT EmployeeID FROM EmployeesContracts
                        WHERE ContractID = ?
                    )
                '''
            print(0.7)
            employees = execute_query(query_employees, (contract_id,), fetch_all="y")
            print(0.8)
            employee_names = [employee[0] for employee in employees]  # Извлекаем имена сотрудников
            enriched_result.append(row + (employee_names,))  # Добавляем список сотрудников в конец строки

        formatted_result = [format_contract_row(row) for row in enriched_result]
        return jsonify(formatted_result), 200
    except Exception:
        print(3)
        return jsonify({"error": "Ошибка получения контрактов"}), 400


@app.route('/get_contract_file', methods=['POST'])
def get_contract_file():
    data = request.json
    token = data.get('access_token')
    contract_id = data.get('contract_id')

    # Проверка токена
    check_token = token_check(token)
    if check_token:
        return check_token

    # Проверка прав доступа
    check_position = position_check(token, ["admin"])
    if check_position:
        # Если пользователь не администратор, проверяем, привязан ли он к контракту
        user_id = get_user_id(sessions[token]["login"])
        if not user_id:
            return jsonify({"error": "ID пользователя не найден"}), 400

        query_check_access = '''
            SELECT 1 FROM EmployeesContracts
            WHERE EmployeeID = ? AND ContractID = ?
            LIMIT 1
        '''
        has_access = execute_query(query_check_access, (user_id, contract_id), fetch_all="t")
        if not has_access:
            return jsonify({"error": "У вас нет доступа к этому контракту"}), 403

    # Получение имени файла из базы данных
    query_get_file = '''
        SELECT file FROM Contracts
        WHERE ID = ?
        LIMIT 1
    '''
    file_name = execute_query(query_get_file, (contract_id,), fetch_all="n")[0]

    if not file_name:
        return jsonify({"error": "Файл для этого контракта не найден"}), 404

    # Путь к файлу
    file_path = os.path.join(CONTRACT_FILES_PATH, str(file_name))

    # Проверка существования файла
    if not os.path.exists(file_path):
        return jsonify({"error": "Файл не существует на сервере"}), 404

    # Отправка файла напрямую
    try:
        return send_file(
            file_path,
            as_attachment=True,  # Файл будет скачиваться, а не отображаться в браузере
            download_name=file_name  # Имя файла для клиента
        )
    except Exception as e:
        return jsonify({"error": f"Ошибка чтения файла: {str(e)}"}), 500


@app.route('/get_unassigned_contracts', methods=['POST'])
def get_unassigned_contracts():
    data = request.json
    token = data.get('access_token')

    # Проверка токена
    check_token = token_check(token)
    if check_token:
        return check_token

    query = '''
        SELECT *
        FROM Contracts
        WHERE ID NOT IN (
            SELECT ContractID
            FROM EmployeesContracts
        )
    '''
    result = execute_query(query, fetch_all="y")

    # Форматирование результата
    formatted_result = [format_contract_row(row, return_employees=False) for row in result]
    print(123, formatted_result[0]["completed"], type(formatted_result[0]["completed"]))
    return jsonify(formatted_result), 200


@app.route('/add_contract', methods=['POST'])
def add_contract():
    data = request.form  # Используем request.form для текстовых данных
    token = data.get('token')
    check_token, check_position = token_check(token), position_check(token, ["admin"])
    if check_token:
        return check_token
    if check_position:
        return check_position

    title = data.get('title')
    marker = data.get('marker')
    number = data.get('number')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    price = data.get('price')
    transferred_to_production = data.get('transferred_to_production')
    material_is_purchased = data.get('material_is_purchased')
    produced = data.get('produced')
    painted = data.get('painted')
    completed = data.get('completed')
    salary_is_taken_into_account = data.get('salary_is_taken_into_account')

    # Проверка обязательных полей
    if not all([title, marker, number, start_date, end_date, transferred_to_production, material_is_purchased,
                produced, painted, completed, salary_is_taken_into_account]):
        return jsonify({"error": "Не все обязательные поля заполнены"}), 400

    file = request.files.get('file')
    unique_filename = None
    file_path = None
    if file:
        allowed_extensions = {'docx', 'xlsx'}
        if file.filename.split('.')[-1].lower() not in allowed_extensions:
            return jsonify({"error": "Недопустимый формат файла. Разрешены только .docx и .xlsx"}), 400

        max_file_size = 10 * 1024 * 1024 * 5  # 50 MB
        if len(file.read()) > max_file_size:
            return jsonify({"error": "Файл слишком большой. Максимальный размер: 50 MB"}), 400
        file.seek(0)

        # Генерация уникального имени файла
        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        file_path = os.path.join(CONTRACT_FILES_PATH, unique_filename)

        # Сохранение файла
        try:
            file.save(file_path)
        except Exception:
            return jsonify({"error": f"Ошибка сохранения файла"}), 500

    try:
        # Добавление контракта в базу данных
        query_insert = '''
            INSERT INTO Contracts (
                title, marker, number, start_date, end_date, price, transferred_to_production, file, 
                material_is_purchased, produced, painted, completed, salary_is_taken_into_account
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        execute_query(query_insert, (
            title, marker, number, start_date, end_date, price, transferred_to_production,
            unique_filename, material_is_purchased, produced, painted, completed, salary_is_taken_into_account
        ))
        return jsonify({"message": "Контракт успешно добавлен"}), 201
    except Exception:
        # Удаление файла в случае ошибки
        if unique_filename and os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({"error": "Ошибка добавления контракта"}), 500


@app.route('/request_contract_change', methods=['POST'])
def request_contract_change():
    data = request.json
    token = data.get('access_token')
    contract_id = data.get('contract_id')
    changes = data.get('changes')  # Словарь с изменениями

    # Проверка токена
    check_token = token_check(token)
    if check_token:
        return check_token

    # Проверка прав доступа
    check_position = position_check(token, ["admin"])
    if not check_position:
        # Администратор может изменять контракты напрямую
        try:
            update_query = '''
                UPDATE Contracts
                SET 
                    title = COALESCE(?, title),
                    marker = COALESCE(?, marker),
                    number = COALESCE(?, number),
                    start_date = COALESCE(?, start_date),
                    end_date = COALESCE(?, end_date),
                    price = COALESCE(?, price),
                    transferred_to_production = COALESCE(?, transferred_to_production),
                    file = COALESCE(?, file),
                    material_is_purchased = COALESCE(?, material_is_purchased),
                    produced = COALESCE(?, produced),
                    painted = COALESCE(?, painted),
                    completed = COALESCE(?, completed),
                    salary_is_taken_into_account = COALESCE(?, salary_is_taken_into_account)
                WHERE ID = ?
            '''
            execute_query(update_query, (
                changes.get('title'),
                changes.get('marker'),
                changes.get('number'),
                changes.get('start_date'),
                changes.get('end_date'),
                changes.get('price'),
                changes.get('transferred_to_production'),
                changes.get('file'),
                changes.get('material_is_purchased'),
                changes.get('produced'),
                changes.get('painted'),
                changes.get('completed'),
                changes.get('salary_is_taken_into_account'),
                contract_id
            ))
            return jsonify({"message": "Контракт успешно обновлен"}), 200
        except Exception as e:
            return jsonify({"error": f"Ошибка обновления контракта: {str(e)}"}), 500

    # Для обычных сотрудников создаем заявку
    user_id = get_user_id(sessions[token]["login"])
    if not user_id:
        return jsonify({"error": "ID пользователя не найден"}), 400

    try:
        query_insert = '''
            INSERT INTO ContractChangeRequests (ContractID, EmployeeID, Changes)
            VALUES (?, ?, ?)
        '''
        execute_query(query_insert, (contract_id, user_id, json.dumps(changes)))
        return jsonify({"message": "Заявка на изменение контракта отправлена"}), 201
    except Exception as e:
        return jsonify({"error": f"Ошибка создания заявки: {str(e)}"}), 500


@app.route('/view_contract_change_requests', methods=['POST'])
def view_contract_change_requests():
    data = request.json
    token = data.get('access_token')

    # Проверка токена
    check_token = token_check(token)
    if check_token:
        return check_token

    # Проверка прав доступа
    check_position = position_check(token, ["admin"])
    if check_position:
        return check_position

    try:
        query = '''
            SELECT ID, ContractID, EmployeeID, Changes, Status, RequestedAt
            FROM ContractChangeRequests
            WHERE Status = 'PENDING'
        '''
        pending_requests = execute_query(query, fetch_all="y")
        formatted_requests = [
            {
                "request_id": r[0],
                "contract_id": r[1],
                "employee_id": r[2],
                "changes": json.loads(r[3]),
                "status": r[4],
                "requested_at": r[5]
            }
            for r in pending_requests
        ]
        return jsonify(formatted_requests), 200
    except Exception as e:
        return jsonify({"error": f"Ошибка получения заявок: {str(e)}"}), 500


@app.route('/update_contract_change_request', methods=['POST'])
def update_contract_change_request():
    data = request.json
    token = data.get('access_token')
    request_id = data.get('request_id')
    new_status = data.get('status')  # APPROVED или REJECTED

    # Проверка токена
    check_token = token_check(token)
    if check_token:
        return check_token

    # Проверка прав доступа
    check_position = position_check(token, ["admin"])
    if check_position:
        return check_position

    if new_status not in ['APPROVED', 'REJECTED']:
        return jsonify({"error": "Некорректный статус"}), 400

    try:
        # Получаем данные о заявке
        query_request = '''
            SELECT ContractID, Changes
            FROM ContractChangeRequests
            WHERE ID = ?
        '''
        request_data = execute_query(query_request, (request_id,), fetch_all="n")
        if not request_data:
            return jsonify({"error": "Заявка не найдена"}), 404

        contract_id, changes_json = request_data
        changes = json.loads(changes_json)

        if new_status == 'APPROVED':
            # Применяем изменения к контракту
            update_query = '''
                UPDATE Contracts
                SET 
                    title = COALESCE(?, title),
                    marker = COALESCE(?, marker),
                    number = COALESCE(?, number),
                    start_date = COALESCE(?, start_date),
                    end_date = COALESCE(?, end_date),
                    price = COALESCE(?, price),
                    transferred_to_production = COALESCE(?, transferred_to_production),
                    file = COALESCE(?, file),
                    material_is_purchased = COALESCE(?, material_is_purchased),
                    produced = COALESCE(?, produced),
                    painted = COALESCE(?, painted),
                    completed = COALESCE(?, completed),
                    salary_is_taken_into_account = COALESCE(?, salary_is_taken_into_account)
                WHERE ID = ?
            '''
            execute_query(update_query, (
                changes.get('title'),
                changes.get('marker'),
                changes.get('number'),
                changes.get('start_date'),
                changes.get('end_date'),
                changes.get('price'),
                changes.get('transferred_to_production'),
                changes.get('file'),
                changes.get('material_is_purchased'),
                changes.get('produced'),
                changes.get('painted'),
                changes.get('completed'),
                changes.get('salary_is_taken_into_account'),
                contract_id
            ))

        # Удаляем заявку
        query_delete = '''
            DELETE FROM ContractChangeRequests
            WHERE ID = ?
        '''
        execute_query(query_delete, (request_id,))
        return jsonify({"message": f"Заявка успешно {new_status.lower()}"}), 200
    except Exception as e:
        return jsonify({"error": f"Ошибка обработки заявки: {str(e)}"}), 500


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

        query_admins = '''
            SELECT firebase_token FROM Employees
            WHERE position = 'admin'
        '''
        admin_tokens = execute_query(query_admins, fetch_all="y")

        # Уведомляем администраторов через Firebase
        for admin_token in admin_tokens:
            send_push_notification(
                "Подтвердите взятие контракта",
                f"{data['username']} хочет взять контракт {data['contract_id']}",
                admin_token
            )
        return jsonify({"message": "Запрос отправлен на подтверждение"}), 201
    except Exception:
        return jsonify({"error": "Ошибка принятия контракта"}), 400


# Просмотр, одобрение или отклонение запросов
@app.route('/review_assignment_requests', methods=['POST'])
def review_assignment_requests():
    data = request.json
    token = data['token']
    check_token, check_position = token_check(token), position_check(token, ["admin"])
    if check_token:
        return check_token
    if check_position:
        return check_position

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


# Обновление статуса запроса
@app.route('/update_assignment_request', methods=['POST'])
def update_assignment_request():
    data = request.json
    token = data['token']
    check_token, check_position = token_check(token), position_check(token, ["admin"])
    if check_token:
        return check_token
    if check_position:
        return check_position

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
    except Exception:
        return jsonify({"error": "Ошибка обработки заявки"}), 400


if __name__ == '__main__':
    if not os.path.isfile(DB_PATH):
        make_database()
    app.run(port=8080, host='0.0.0.0')
