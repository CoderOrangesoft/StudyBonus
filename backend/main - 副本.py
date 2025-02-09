import flask
from flask_cors import *
import sqlite3
import random
from werkzeug.security import generate_password_hash, check_password_hash

app = flask.Flask(__name__)
CORS(app)

class Server:
    port = 64015
    show_port = True

class Study_Resourse:
    unit_list = [
        '1-成长的节拍',
    ]
    question_list = [
        [
            '中学时代的重要性?',
            '我们应如何对待中学生活?',
            '梦想的重要性?'
        ]
    ]

# 数据库文件路径
DATABASE = 'users.db'

# 初始化数据库
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # 创建用户表，并添加 coin 字段，类型为 int
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                coin INTEGER DEFAULT -101,
                task INTEGER DEFAULT 1
            )
        ''')
        conn.commit()

# 初始化数据库（如果不存在）
init_db()

def check_auth(auth,username,password):
    if "'" in auth or ";" in auth or "--" in auth or "/*" in auth or '"' in auth:
        return False
    if '"' in username or "'" in username or ";" in username or "--" in username or "/*" in username:
        return False
    if '"' in password or "'" in password or ";" in password or "--" in password or "/*" in password:
        return False
    new_auth = generate_password_hash('iOrangesoft' + username + password)
    return new_auth == auth

def cor_ac(text,state=1):
    if state == 1:
        add_text = "你的操作行动已经拉响了COR_AC的安全警报"
    if state == 2:
        add_text = "你的操作行动已经拉响了COR_AC的安全响应，账户已被封禁"
    if state == 3:
        add_text = "你的操作行动已经被COR_AC阻止，请勿重复操作"
    if state == 4:
        add_text = "感谢你关于COR_AC的反馈，COR_AC将会持续改进"
    else:
        add_text = "COR_AC正在防护此次操作"
    return f'{"message":"{text}","message_COR_AC":"{add_text}"}'

@app.route('/')
def index():
    return f'STUDY_BONUS[{Server.port if Server.show_port else "Server"}]'

@app.route('/api/login', methods=['POST'])
def login_by_password():
    # 获取请求中的用户名和密码
    username = flask.request.json.get('username')
    password = flask.request.json.get('password')

    if not username or not password:
        return flask.jsonify({'message': '用户名和密码不能为空'}), 400

    # 连接数据库，验证用户
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # 查找该用户名对应的密码
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

    if result is None:
        return flask.jsonify({'message': '无效的用户名或密码'}), 401

    # 获取存储的密码
    stored_password = result[0]

    # 验证密码
    if not check_password_hash(stored_password, password):
        return flask.jsonify({'message': '无效的用户名或密码'}), 401

    auth = generate_password_hash('iOrangesoft' + username + password)
    
    response = flask.make_response(flask.jsonify({'message': '登录成功'}), 200)
    
    # 设置 Cookie，cookie 会存储 auth 哈希值
    response.set_cookie('auth_token', auth,httponly=True)
    response.set_cookie('username', username, httponly=True)
    response.set_cookie('password', password, httponly=True)
    return response

@app.route('/api/register', methods=['POST'])
def register():
    username = flask.request.json.get('username')
    password = flask.request.json.get('password')

    if not username or not password:
        return flask.jsonify({'message': '用户名和密码不能为空'}), 400

    # 对密码进行哈希加密
    hashed_password = generate_password_hash(password)

    if "'" in username or ";" in username or "--" in username or "/*" in username or '"' in username:
        return flask.jsonify(cor_ac('数据库出现错误',1)), 400
    if "'" in password or ";" in password or "--" in password or "/*" in password or '"' in password:
        return flask.jsonify(cor_ac('数据库出现错误',1)), 400

    # 将用户存储到数据库中
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        try:
            # 插入用户数据
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            return flask.jsonify({'message': '用户名已存在'}), 409

    return flask.jsonify({'message': '注册成功'}), 201

@app.route('/api/account/coin', methods=['GET'])
def get_account_coin():
    username = flask.request.headers.get('username')
    password = flask.request.headers.get('password')
    auth = flask.request.headers.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '用户名、密码和认证信息不能为空'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '无效的用户名或密码'}), 401
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT coin FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result == -101:
            return flask.jsonify({'message': '账户没有通过考试，请先进行入站考试'}), 402
        if result == -201:
            return flask.jsonify({'message': '账户已被封禁'}), 403
        return flask.jsonify({'message':result[0]}), 200
    
@app.route('/api/account/upgrade', methods=['POST'])
def upgrade_account_coin():
    username = flask.request.headers.get('username')
    password = flask.request.headers.get('password')
    auth = flask.request.headers.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '用户名、密码和认证信息不能为空'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '无效的用户名或密码'}), 401
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT coin FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result == -101:
            cursor.execute("UPDATE users SET coin = 0 WHERE username = ?", (username,))
            conn.commit()
            return flask.jsonify({'message': '账户通过考试成功'}), 200
        else:
            return flask.jsonify(cor_ac('无法重复考试',1)), 400

@app.route('/api/account/delete', methods=['DELETE'])
def delete_account():
    username = flask.request.headers.get('username')
    password = flask.request.headers.get('password')
    auth = flask.request.headers.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '用户名、密码和认证信息不能为空'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '无效的用户名或密码'}), 401
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        return flask.jsonify({'message': '账户已注销'}), 200
    
@app.route('/api/account/ban', methods=['POST'])
def ban_account():
    admin_password = flask.request.headers.get('admin_password')
    if admin_password != 'iOrangesoft':
        return flask.jsonify(cor_ac('该path已被删除',-1)), 404
    username = flask.request.json.get('username')
    if not username:
        return flask.jsonify({'message': '用户名不能为空'}), 400
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET coin = -201 WHERE username = ?", (username,))
        conn.commit()
        return flask.jsonify({'message': '账户已封禁'}), 200

@app.route('/api/account/unban', methods=['POST'])
def unban_account():
    admin_password = flask.request.headers.get('admin_password')
    if admin_password != 'iOrangesoft':
        return flask.jsonify(cor_ac('该path已被删除',-1)), 404
    username = flask.request.json.get('username')
    if not username:
        return flask.jsonify({'message': '用户名不能为空'}), 400
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET coin = 0 WHERE username = ?", (username,))
        conn.commit()
        return flask.jsonify({'message': '账户解封成功'}), 200

@app.route('/api/account/password_reset', methods=['POST'])
def reset_password():
    username = flask.request.headers.get('username')
    password = flask.request.headers.get('password')
    auth = flask.request.headers.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '用户名、密码和认证信息不能为空'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '无效的用户名或密码'}), 401
    new_password = flask.request.json.get('new_password')
    if not new_password:
        return flask.jsonify({'message': '新密码不能为空'}), 400
    if "'" in new_password or ";" in new_password or "--" in new_password or "/*" in new_password or '"' in new_password:
        return flask.jsonify(cor_ac('数据库出现错误',1)), 400
    hashed_password = generate_password_hash(new_password)
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
        conn.commit()
        return flask.jsonify({'message': '密码重置成功'}), 200

@app.route('/api/study/coin/add', methods=['POST'])
def study_coin_add():
    username = flask.request.headers.get('username')
    password = flask.request.headers.get('password')
    auth = flask.request.headers.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '用户名、密码和认证信息不能为空'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '无效的用户名或密码'}), 401
    coin = flask.request.json.get('coin')
    if not coin:
        return flask.jsonify({'message': 'coin不能为空'}), 400
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET coin = coin + ? WHERE username = ?", (coin, username))
        conn.commit()
        return flask.jsonify({'message': 'coin增加成功'}), 200
    
@app.route('/api/study/task', methods=['POST', 'GET'])
def study_task_finish():
    username = flask.request.headers.get('username')
    password = flask.request.headers.get('password')
    auth = flask.request.headers.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '用户名、密码和认证信息不能为空'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '无效的用户名或密码'}), 401
    if flask.request.method == 'POST':
        with sqlite3.connect(DATABASE) as conn:
            add_coin_random = random.randint(5,20)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET coin = coin + add_coin_random WHERE username = ?", (username,))
            cursor.execute("UPDATE users SET task = task + 1 WHERE username = ?", (username,))
            conn.commit()
            return flask.jsonify({'message': '任务完成成功'}), 200
    if flask.request.method == 'GET':
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT task FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return flask.jsonify({'message': result[0]}), 200

@app.route('/api/study/random_question_from_unit', methods=['GET'])
def study_random_question():
    unit = flask.request.args.get('unit')
    question = random.choice(Study_Resourse.question_list[unit-1])
    return flask.jsonify({'message': question,'from_unit':Study_Resourse.unit_list[unit-1]}), 200

@app.route('/api/study/random_question_from_all', methods=['GET'])
def study_random_question_from_all():
    unit = random.randint(1,len(Study_Resourse.unit_list))
    question = random.choice(Study_Resourse.question_list[unit-1])
    return flask.jsonify({'message': question,'from_unit':Study_Resourse.unit_list[unit-1]}), 200

if __name__ == '__main__':
    app.run(debug=True, port=Server.port)
