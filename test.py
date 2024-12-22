import requests
import json

# URL вашего сервера
SERVER_URL = "http://127.0.0.1:8080"


def post_to_server():
    data = {
        "title": "Договор №2",
        "start_date": "2024-12-09",
        "end_date": "2024-12-20",
        "employees": "Сидоров"
    }
    requests.post(SERVER_URL + "/add", json=data)


# Функция для тестового запроса
def test_server():
    # Данные для тестового JSON-запроса
    params = {
        "start_date": "2024-01-01",
        "end_date": "2024-12-30"
    }

    try:
        # Отправка POST-запроса
        response = requests.post(SERVER_URL + "/get", json=params)

        # Проверка успешности запроса
        if response.status_code == 200:
            print("Успешное подключение к серверу!")
            print("Ответ сервера:")
            print(json.dumps(response.json(), indent=4, ensure_ascii=False))
        else:
            print(f"Ошибка {response.status_code}: {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"Ошибка подключения: {e}")


# Запуск проверки
if __name__ == "__main__":
    # post_to_server()
    test_server()
