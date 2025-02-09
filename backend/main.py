import flask
from flask_cors import *
import sqlite3
import random
from werkzeug.security import generate_password_hash, check_password_hash

app = flask.Flask(__name__)
CORS(app, origins=["file://", "*"],supports_credentials=True)

class Server:
    port = 64015
    show_port = True

class Study_Resourse:
    unit_list = [
        '[七上]1-成长的节拍',
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
                task INTEGER DEFAULT 1,
                vip_level INTEGER DEFAULT 1,
                identity1 TEXT DEFAULT '学习探索者',
                secret_login_key_1 TEXT DEFAULT UNIQUE
                secret_login_key_2 TEXT DEFAULT UNIQUE
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
    new_auth = check_password_hash(auth,'iOrangesoft' + username + password)
    return new_auth

def cor_ac(text,state=1):
    if state == 1:
        add_text = "你的操作行动已经拉响了COR_AC的安全警报"
    elif state == 2:
        add_text = "你的操作行动已经拉响了COR_AC的安全响应，账户已被封禁"
    elif state == 3:
        add_text = "你的操作行动已经被COR_AC阻止，请勿重复操作"
    elif state == 4:
        add_text = "感谢你关于COR_AC的反馈，COR_AC将会持续改进"
    else:
        add_text = "COR_AC正在防护此次操作"
    return {"message":text,"message_COR_AC":add_text}

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
        return flask.jsonify({'message': '您的帐号拉响了安全警报'}), 401

    # 获取存储的密码
    stored_password = result[0]

    # 验证密码
    if not check_password_hash(stored_password, password):
        return flask.jsonify({'message': '您的帐号拉响了安全警报'}), 401

    auth = generate_password_hash('iOrangesoft' + username + password)
    
    response = flask.make_response(flask.jsonify({'message': '登录成功'}), 200)
    
    # 设置 Cookie，cookie 会存储 auth 哈希值
    response.set_cookie('auth', auth,httponly=True)
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
    username = flask.request.cookies.get('username')
    password = flask.request.cookies.get('password')
    auth = flask.request.cookies.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '请先登录'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '您的帐号拉响了安全警报'}), 401
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT coin FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result[0] == -101:
            return flask.jsonify({'message': '账户没有通过考试，请先进行入站考试'}), 402
        if result[0] == -201:
            return flask.jsonify({'message': '账户已被封禁'}), 403
        return flask.jsonify({'message':result[0]}), 200
    
@app.route('/api/account/upgrade', methods=['POST'])
def upgrade_account_coin():
    username = flask.request.cookies.get('username')
    password = flask.request.cookies.get('password')
    auth = flask.request.cookies.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '请先登录'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '您的帐号拉响了安全警报'}), 401
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT coin FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result[0] == -101:
            cursor.execute("UPDATE users SET coin = 0 WHERE username = ?", (username,))
            conn.commit()
            return flask.jsonify({'message': '账户通过考试成功'}), 200
        else:
            return flask.jsonify(cor_ac('无法重复考试',1)), 400
        
@app.route('/api/account/vip', methods=['POST'])
def upgrade_account_vip():
    username = flask.request.cookies.get('username')
    password = flask.request.cookies.get('password')
    auth = flask.request.cookies.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '请先登录'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '您的帐号拉响了安全警报'}), 401
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT vip_level FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        now_vip_level = result[0]
        if now_vip_level <= 5:
            upgrading_needs_coin = 10 * now_vip_level # 升级所需硬币的公式为 10 * 当前vip等级
        elif now_vip_level <= 10:
            upgrading_needs_coin = 20 * now_vip_level # 升级所需硬币的公式为 20 * 当前vip等级
        elif now_vip_level <= 30:
            upgrading_needs_coin = 50 * now_vip_level # 升级所需硬币的公式为 50 * 当前vip等级
        elif now_vip_level <= 50:
            upgrading_needs_coin = 70 * now_vip_level # 升级所需硬币的公式为 70 * 当前vip等级
        else:
            upgrading = 100 * now_vip_level # 升级所需硬币的公式为 100 * 当前vip等级
        now_coin = cursor.execute("SELECT coin FROM users WHERE username = ?", (username,)).fetchone()[0]
        if now_coin < upgrading_needs_coin:
            return flask.jsonify({'message': f'账户余额不足，还差{upgrading_needs_coin-now_coin}枚硬币'}), 402
        else:
            new_coin_count = now_coin - upgrading_needs_coin
            cursor.execute(f"UPDATE users SET coin = {new_coin_count} WHERE username = ?", (username,))
            cursor.execute(f"UPDATE users SET vip_level = vip_level + 1 WHERE username = ?", (username,))
            conn.commit()
            return flask.jsonify({'message': f'账户升级成功，当前vip等级为{now_vip_level+1}'}), 200

@app.route('/api/account/info', methods=['GET'])
def get_account_info():
    username = flask.request.cookies.get('username')
    password = flask.request.cookies.get('password')
    auth = flask.request.cookies.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': {'无法查看账户信息':'请先登录'}}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': {'无法查看账户信息':'您的帐号拉响了安全警报'}}), 401
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id,username,vip_level,coin,task,identity1 FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        show_result = {
            'id':result[0],
            'username':result[1],
            'vip_level':result[2],
            'coin':result[3],
            'task':result[4],
            'identity1':result[5]
        }
        return flask.jsonify({'message': show_result}), 200
    
@app.route('/api/account/others_info',methods=['GET'])
def get_account_others_info():
    id = flask.request.args.get('id')
    if not id:
        return flask.jsonify({'message': '用户id不能为空'}), 400
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id,username,vip_level,coin,identity1 FROM users WHERE id = ?", (id,))
        i = cursor.fetchone()
        if i[3] == -201:
            return flask.jsonify({'message': {
                '<font style="display:none">1-</font>用户序号':i[0],
                '<font style="display:none">2-</font>用户名称':'封禁中 -- '+i[1],
                '<font style="display:none">3-</font>会员等级':-2,
                '<font style="display:none">4-</font>身份':'被封禁的用户'
        }}), 200  # 处理被封禁用户的情况
        if not i:
            return flask.jsonify({'message': {
                '<font style="display:none">1-</font>用户序号':id,
                '<font style="display:none">2-</font>用户名称':'未知用户',
                '<font style="display:none">3-</font>会员等级':-1,
                '<font style="display:none">4-</font>身份':'未知用户'
        }}), 200  # 处理未找到用户的情况
        show_result = {
                '<font style="display:none">1-</font>用户序号':i[0],
                '<font style="display:none">2-</font>用户名称':i[1],
                '<font style="display:none">3-</font>会员等级':i[2],
                '<font style="display:none">4-</font>身份':i[4]
        }
        return flask.jsonify({'message': show_result}), 200

@app.route('/api/account/delete', methods=['DELETE'])
def delete_account():
    username = flask.request.cookies.get('username')
    password = flask.request.cookies.get('password')
    auth = flask.request.cookies.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '请先登录'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '您的帐号拉响了安全警报'}), 401
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
    username = flask.request.cookies.get('username')
    password = flask.request.cookies.get('password')
    auth = flask.request.cookies.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '请先登录'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '您的帐号拉响了安全警报'}), 401
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
    username = flask.request.cookies.get('username')
    password = flask.request.cookies.get('password')
    auth = flask.request.cookies.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '请先登录'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '您的帐号拉响了安全警报'}), 401
    with sqlite3.connect(DATABASE) as conn:
        add_coin_random = random.randint(5,10)
        cursor = conn.cursor()
        cursor.execute(f"UPDATE users SET coin = coin + {add_coin_random} WHERE username = ?", (username,))
        conn.commit()
        return flask.jsonify({'message': f'增加了{add_coin_random}枚硬币'}), 200
    
@app.route('/api/study/task', methods=['POST', 'GET'])
def study_task_finish():
    username = flask.request.cookies.get('username')
    password = flask.request.cookies.get('password')
    auth = flask.request.cookies.get('auth')
    if not username or not password or not auth:
        return flask.jsonify({'message': '请先登录'}), 400
    if not check_auth(auth, username, password):
        return flask.jsonify({'message': '您的帐号拉响了安全警报'}), 401
    if flask.request.method == 'POST':
        with sqlite3.connect(DATABASE) as conn:
            add_coin_random = random.randint(5,20)
            cursor = conn.cursor()
            cursor.execute(f"UPDATE users SET coin = coin + {add_coin_random} WHERE username = ?", (username,))
            cursor.execute("UPDATE users SET task = task + 1 WHERE username = ?", (username,))
            conn.commit()
            return flask.jsonify({'message': f'任务完成成功，增加了{add_coin_random}枚硬币'}), 200
    if flask.request.method == 'GET':
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT task FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return flask.jsonify({'message': result[0]}), 200

@app.route('/api/study/random_question_from_unit', methods=['GET'])
def study_random_question():
    unit = flask.request.args.get('unit')
    unit = int(unit)
    if unit > len(Study_Resourse.unit_list) or unit < 1:
        return flask.jsonify(cor_ac('请求参数验证失败-unit',1)), 400
    question_id = random.randint(1,len(Study_Resourse.question_list[unit-1]))
    question = Study_Resourse.question_list[unit-1][question_id-1]
    return flask.jsonify({'message': question,'from_unit':Study_Resourse.unit_list[unit-1],'question_id':question_id}), 200

@app.route('/api/study/random_question_from_all', methods=['GET'])
def study_random_question_from_all():
    unit = random.randint(1,len(Study_Resourse.unit_list))
    question_id = random.randint(1,len(Study_Resourse.question_list[unit-1]))
    question = Study_Resourse.question_list[unit-1][question_id-1]
    return flask.jsonify({'message': question,'from_unit':Study_Resourse.unit_list[unit-1],'question_id':question_id}), 200

@app.route('/api/study/get_all_question_by_unit')
def study_get_all_question_by_unit():
    unit = flask.request.args.get('unit')
    if not unit:
        return flask.jsonify(cor_ac('请求参数验证失败-unit',1)), 400
    if int(unit) > len(Study_Resourse.unit_list) or int(unit) < 1:
        return flask.jsonify(cor_ac('请求参数验证失败-unit',1)), 400
    question_list = Study_Resourse.question_list[int(unit)-1]
    return flask.jsonify({'message': question_list}), 200

@app.route('/api/study/get_unit_list')
def study_get_unit_list():
    return flask.jsonify({'message': Study_Resourse.unit_list}), 200

@app.route('/api/study/get_question_list_by_unit')
def study_get_question_list_by_unit():
    unit = flask.request.args.get('unit')
    if not unit:
        return flask.jsonify(cor_ac('请求参数验证失败-unit',1)), 400
    if int(unit) > len(Study_Resourse.unit_list) or int(unit) < 1:
        return flask.jsonify(cor_ac('请求参数验证失败-unit',1)), 400
    question_list = Study_Resourse.question_list[int(unit)-1]
    return flask.jsonify({'message': question_list}), 200

# @app.route('/api/study/get_all_question_by_all')
# def study_get_all_question_by_all():
#     question_list = []
#     for unit in Study_Resourse.unit_list:
#         question_list.extend(Study_Resourse.question_list[int(unit)-1])
#     return flask.jsonify({'message': question_list}), 200

if __name__ == '__main__':
    app.run(debug=True, port=Server.port)
