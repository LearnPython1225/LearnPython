from flask import Flask, render_template, redirect, url_for, request, session, jsonify,flash, send_from_directory, Response
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

from pathlib import Path

import requests

from werkzeug.security import generate_password_hash, check_password_hash
import openai
import os

import markdown
import subprocess
from supabase import create_client, Client


from functools import wraps
import time
from flask import abort, make_response

import tempfile

import uuid
import json
from datetime import datetime
from flask import Flask, request, jsonify
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime
import base64
import hashlib
import hmac
import logging
from flask import jsonify, request

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer




def get_tier_access(user_email):
    """从 Supabase 获取用户解锁的页面列表"""
    # 从 Supabase 查询数据
    response = supabase.table('paypal_orders').select('item_number').eq('payer_email', user_email).execute()

    # 检查 response.data 是否存在，并提取 item_number
    if response.data:
        tier = [record['item_number'] for record in response.data if 'item_number' in record]
        print(f"This is the supabase output: {tier}")
        return list(set(tier))

    # 如果没有数据，返回空列表
    print("No data found for the given email.")
    return []


def check_daily_limit(max_queries=20):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_email = session.get('email')  # 获取当前登录用户的email
            if not user_email:
                return jsonify({"error": "未授权"}), 401
            
            # 获取当前用户信息
            response = supabase.table('users').select('query_count', 'last_query_date').eq('email', user_email).execute()
            user = response.data[0] if response.data else None
            
            if not user:
                return jsonify({"error": "用户不存在"}), 404
            
            today = datetime.utcnow().date()
            query_count = user.get('query_count', 0)
            last_query_date = user.get('last_query_date')
            
            # 如果是新的一天，重置查询计数
            if last_query_date != str(today):
                query_count = 0
                supabase.table('users').update({'query_count': 0, 'last_query_date': str(today)}).eq('email', user_email).execute()
            
            # 检查查询次数是否超限
            if query_count >= max_queries:
                return jsonify({"error": "You have reached the daily usage limit."}), 429
            
            # 增加查询次数
            supabase.table('users').update({'query_count': query_count + 1}).eq('email', user_email).execute()
            
            return f(*args, **kwargs)
        return wrapped
    return decorator






# Load .env file
load_dotenv()

# Initialize logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
# Add a handler (e.g., to a file or console) as needed

# 加载 JSON 文件
with open('content.json', 'r') as file:
    content = json.load(file)

with open('content2.json', 'r') as file:
    content2 = json.load(file)

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.urandom(24)  # 替换为一个安全的密钥
csrf = CSRFProtect(app)

# Use environment variables
app.secret_key = os.getenv('SECRET_KEY', 'fallback_secret_key')
openai.api_key = os.getenv('OPENAI_API_KEY')


# Supabase setup
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_API_KEY')
supabase: Client = create_client(supabase_url, supabase_key)

# WEbhook ID
webhook = os.getenv('WEBHOOK_ID')


# User model (for reference, not used with Supabase)
class User:
    def __init__(self, id, username, email, password_hash, unlocked_phase):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.unlocked_phase = unlocked_phase

# Replace database operations with Supabase operations
def get_user_by_email(email):
    response = supabase.table('users').select('*').eq('email', email).execute()
    if response.data:
        user_data = response.data[0]
        return User(
            user_data['id'],
            user_data['username'],
            user_data['email'],
            user_data['password_hash'],
            user_data['unlocked_phase']
        )
    return None

def create_user(email, username, password_hash):
    new_user = {
        'email': email,
        'username': username,
        'password_hash': password_hash,
        'unlocked_phase': 1
    }
    response = supabase.table('users').insert(new_user).execute()
    return response.data[0] if response.data else None

def update_user_phase(email, new_phase):
    supabase.table('users').update({'unlocked_phase': new_phase}).eq('email', email).execute()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def home():
    logged_in = session.get('logged_in', False)
    return render_template('index.html', logged_in=logged_in)

@app.route('/learn')
def learn():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    chp = request.args.get('chp', 'default')  # 获取查询参数，默认值为 'default'
    

    # 获取章节内容，如果未匹配则返回默认
    chapter_content = content.get(chp, {'title': 'Default Chapter', 'des': 'No content found.', 'keypoint1': 'None', 'keypoint2': 'None', 'keypoint3': 'None', 'example': '', 'task1': 'None', 'task2': 'None','phases':'None'})
    return render_template('learn.html', content=chapter_content)

@app.route('/learn2')
def learn2():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    chp = request.args.get('chp', 'default')  # 获取查询参数，默认值为 'default'
    

    # 获取章节内容，如果未匹配则返回默认
    chapter_content2 = content2.get(chp, {'title': 'Default Chapter', 'des': 'No content found.', 'keypoint1': 'None', 'keypoint2': 'None', 'keypoint3': 'None', 'keypoint4': 'None', 'keypoint5': 'None', 'keypoint6': 'None', 'example': '', 'task1': 'None', 'task2': 'None','stages':'None'})
    return render_template('learn2.html', content2=chapter_content2)


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    if not email or not username or not password:
        return jsonify({"status": "error", "message": "Email, username or password missing"}), 400

    if get_user_by_email(email):
        return jsonify({"status": "error", "message": "User already registered"}), 400

    password_hash = hash_password(password)
    new_user = create_user(email, username, password_hash)

    if new_user:
        return jsonify({"status": "success", "message": "Registration successful"}), 200
    else:
        return jsonify({"status": "error", "message": "Registration failed"}), 500
    
csrf.exempt(register)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data received"}), 400

    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"status": "error", "message": "Email or password missing"}), 400

    user = get_user_by_email(email)
    if user and user.password_hash == hash_password(password):
        session['logged_in'] = True
        session['email'] = user.email
        session['username'] = user.username
        session['unlocked_phase'] = user.unlocked_phase
        return jsonify({"status": "success", "message": "Login successful"}), 200

    return jsonify({"status": "error", "message": "Invalid email or password"}), 401

csrf.exempt(login)

@app.route('/term_and_condition', methods=['GET'])
def term_and_condition():
    return render_template('term_and_condition.html')




@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')


###############################################
# RESET PASSWORD SECTION
###############################################
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask import render_template, request, redirect, url_for, flash

mail_password = os.getenv('MAIL_PASSWORD')

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'learnpython1225@gmail.com'
app.config['MAIL_PASSWORD'] = mail_password
mail = Mail(app)



# 用于加解密 token
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    """
    显示“输入邮箱”表单，让用户输入 email。
    如果此 email 存在于数据库，就发一封带重置链接的邮件。
    """
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash('Please enter your email address.', 'error')
            return redirect(url_for('reset'))

        user = get_user_by_email(email)
        if user:
            # 1) 生成 token
            token = s.dumps(email, salt='email-reset')

            # 2) 生成重置链接
            reset_url = url_for('reset_with_token', token=token, _external=True)

            # 3) 发送邮件
            msg = Message('Password Reset Request',
                          sender='learnpython1225@gmail.com',
                          recipients=[email])
            msg.body = f'Hello,\n\nYou recently requested to reset your password. Click on the link below to change your password.\n{reset_url}\n\nIf you did not request this, ignore this email.\n\nThanks!\nLearnPython Team'
            mail.send(msg)
            flash('A reset password link has been sent to your email. Please check your inbox.', 'success')
        else:
            flash('This email address does not exist.', 'error')
        return redirect(url_for('reset'))

    # GET 请求 => 显示 reset.html 让用户填写 email
    return render_template('reset.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    """
    用户点邮件中链接 => 带着token => 填新密码 => 提交 => 更新数据库
    """
    try:
        # 解析 token
        email = s.loads(token, salt='email-reset', max_age=900)  # 15 min valid
    except:
        flash('This link is invalid or has expired!', 'error')
        return redirect(url_for('reset'))

    user = get_user_by_email(email)
    if not user:
        flash('Invalid reset link.', 'error')
        return redirect(url_for('reset'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Please enter a new password and confirm it.', 'error')
            return redirect(url_for('reset_with_token', token=token))

        if new_password != confirm_password:
            flash('The passwords entered do not match.', 'error')
            return redirect(url_for('reset_with_token', token=token))

        hashed_password = hash_password(new_password)
        # 更新数据库
        supabase.table('users').update({'password_hash': hashed_password}).eq('email', email).execute()
        flash('Your password has been reset. Please log in using your new password!', 'success')
        return redirect(url_for('login_page'))

    # GET => 显示一个表单，让用户输入 new_password, confirm_password
    return render_template('reset_with_token.html', token=token)





@app.route('/unlock')
def unlock():
    if not session.get('logged_in'):
        return redirect(url_for('login'))  # 未登录用户重定向到登录页面
    
    try:
        # 获取用户的访问权限
        tiers = get_tier_access(session.get('email'))

        # 检查是否具有访问权限
        if 'Additional Learning Materials' in tiers or 'Standard Tier' in tiers or 'Full Access Plan' in tiers:
             return render_template('unlock.html')
        else:
            return redirect(url_for('home') + '#pricing')  # 没有权限的用户重定向到主页
    except Exception as e:
        # 如果发生异常，记录错误并返回 404
        print(f'Error rendering unlock.html: {str(e)}')
        return f"Error: {str(e)}", 404
    
@app.route('/addtional')
def addtional():
    if not session.get('logged_in'):
        return redirect(url_for('login'))  # 未登录用户重定向到登录页面
    
    try:
        # 获取用户的访问权限
        tiers = get_tier_access(session.get('email'))

        # 检查是否具有访问权限
        if 'Additional Learning Materials' in tiers or 'Full Access Plan' in tiers:
             return render_template('addtional.html')
        else:
            return redirect(url_for('home') + '#pricing')  # 没有权限的用户重定向到主页
    except Exception as e:
        # 如果发生异常，记录错误并返回 404
        print(f'Error rendering addtional.html: {str(e)}')
        return f"Error: {str(e)}", 404



@app.route('/standard')
def standard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('standard.html')

@app.route('/learning_materials')
def learning_materials():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('learning_materials.html')

@app.route('/full_access_plan')
def full_access_plan():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('full_access_plan.html')




@app.route('/phase/<int:phase_number>')
def phase(phase_number):
    if not session.get('logged_in'):
        return redirect(url_for('login'))  # 未登录用户重定向到登录页面

    try:
        # 获取用户的访问权限
        tiers = get_tier_access(session.get('email'))

        # 检查是否具有访问权限
        if 'Standard Tier' in tiers or 'Full Access Plan' in tiers:
            return render_template(f'phase/phase{phase_number}.html')
        else:
            return redirect(url_for('home') + '#pricing')  # 没有权限的用户重定向到主页
    except Exception as e:
        # 如果发生异常，记录错误并返回 404
        print(f'Error rendering phase{phase_number}.html: {str(e)}')
        return f"Error: {str(e)}", 404
    
@app.route('/stage/<int:stage_number>')
def stage(stage_number):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        # 获取用户的访问权限
        tiers = get_tier_access(session.get('email'))

        # 检查是否具有访问权限
        if 'Standard Tier' in tiers or 'Full Access Plan' in tiers:
            return render_template(f'stage/stage{stage_number}.html')
        else:
            return redirect(url_for('home') + '#pricing')  # 没有权限的用户重定向到主页
    except Exception as e:
        # 如果发生异常，记录错误并返回 404
        print(f'Error rendering stage{stage_number}.html: {str(e)}')
        return f"Error: {str(e)}", 404

@app.route('/chatgpt', methods=['POST'])
@check_daily_limit(max_queries=20)
def chatgpt():
    data = request.get_json()
    user_message = data.get('message', '').strip()

    if len(user_message) == 0:
        return jsonify({"status": "error", "message": "Message is required"}), 400
    if len(user_message) > 500:
        return jsonify({"status": "error", "message": "Your question is too long. Please shorten it."}), 400

    messages = [
        {"role": "system","content": \
            "You are a helpful assistant specializing in Python programming. \
            Your role is to assist the user with Python-related questions, including syntax, libraries, debugging, best practices, and more. \
            Always ensure your responses are detailed, accurate, and complete. \
            If the user's question is unrelated to Python, politely remind them to focus on Python topics. \
            If the user's query is too long or complex, divide your response into smaller, logical parts and indicate 'Continued...' when necessary to ensure completeness. \
            If the question is unclear, ask the user for additional context or examples to better assist them. Your goal is to provide professional, clear, and thorough Python assistance in every response. \
            Explain Python decorators in detail. You must complete your reply in 200 tokens or less, but ensure the response is complete and concise." 
                
}
    ]

    messages.append({"role":"user","content":user_message})

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=250,
            temperature=0.5,
        )

        reply = response['choices'][0]['message']['content'].strip()
        print(f"ChatGPT: {reply}")

        reply_html = markdown.markdown(reply)
        
        return jsonify({"status": "success", "reply": reply_html}), 200

    except openai.error.OpenAIError as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
csrf.exempt(chatgpt)


def rate_limit(max_requests=10, time_window=60):
    def decorator(f):
        requests = {}
        
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_id = session.get('user_id', request.remote_addr)
            now = time.time()
            
            # Clean old requests
            requests[user_id] = [t for t in requests.get(user_id, []) 
                               if now - t < time_window]
            
            if len(requests[user_id]) >= max_requests:
                return make_response('Rate limit exceeded', 429)
                
            requests[user_id].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator




# Update the run_code route with security measures
@app.route('/run_code', methods=['POST'])
def run_code():
    # 检查用户是否已登录
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized"}), 401

    # 获取用户提交的代码
    data = request.get_json()
    code = data.get('code', '')

    # 禁止危险操作（例如文件读写、系统命令）
    blacklist = [
        'import os', 'import turtle', 'import sys', 'import subprocess', '__import__',
        'eval(', 'exec(', 'open(', 'write(', 'read('
    ]
    if any(keyword in code for keyword in blacklist):
        return jsonify({"error": "Forbidden keyword in code"}), 403

    # 限制代码长度
    if len(code) > 1000:
        return jsonify({"error": "Code too long"}), 413

    # 将代码发送到沙盒服务
    try:
        # 沙盒服务的 URL (Render 的沙盒 Web 服务地址)
        sandbox_service_url = "https://sandbox-service.onrender.com/execute"

        # 向沙盒服务发送 POST 请求
        response = requests.post(
            sandbox_service_url,
            json={"code": code},
            timeout=10
        )

        # 检查沙盒服务的响应
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({"error": "Sandbox error", "details": response.json()}), response.status_code

    except requests.exceptions.Timeout:
        return jsonify({"error": "Execution timeout"}), 408
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500
    

import os
import requests
from flask import Flask, request, jsonify
from datetime import datetime
import logging
from supabase import create_client, Client


import requests

# 配置 PayPal 环境
PAYPAL_VERIFY_URL = "https://ipnpb.paypal.com/cgi-bin/webscr"  # 生产环境
# PAYPAL_VERIFY_URL = "https://ipnpb.sandbox.paypal.com/cgi-bin/webscr"  # 沙盒环境

@app.before_request
def log_request():
    """记录每个请求的数据"""
    app.logger.info(f"IP: {request.remote_addr}, Path: {request.path}, Data: {request.form}")

def verify_ipn(ipn_data):
    """验证 IPN 数据"""
    params = ipn_data.copy()
    params['cmd'] = '_notify-validate'
    try:
        response = requests.post(PAYPAL_VERIFY_URL, data=params, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        }, timeout=10)
        if response.text == 'VERIFIED':
            return True
        else:
            logger.warning(f"IPN Verification failed. Response: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error verifying IPN: {e}")
        return False


def clean_order_data(order_data):
    """清理订单数据，确保字段格式正确"""
    for key, value in order_data.items():
        if isinstance(value, str) and value.strip() == '':
            order_data[key] = None  # 将空字符串替换为 None
        elif isinstance(value, (float, int)) and value is None:
            order_data[key] = 0  # 将 None 替换为默认值
    return order_data


def save_to_database(order_data):
    """保存订单数据到数据库"""
    try:
        existing = supabase.table('paypal_orders').select('*').eq('order_id', order_data['order_id']).execute()
        if len(existing.data) == 0:
            # 插入新记录
            result = supabase.table('paypal_orders').insert(order_data).execute()
            if result.data:
                logger.info(f"Inserted new order record: {result.data[0]['id']}")
            else:
                logger.warning("Insert returned empty data")
        else:
            # 更新现有记录
            update_fields = order_data.copy()
            update_fields.pop('created_at', None)  # 保留原创建时间
            result = supabase.table('paypal_orders').update(update_fields).eq('order_id', order_data['order_id']).execute()
            if result.data:
                logger.info(f"Updated existing order record: {result.data[0]['id']}")
            else:
                logger.warning("Update returned empty data")
    except Exception as e:
        logger.error(f"Error saving order to database: {e}", exc_info=True)
        raise


@app.route('/paypal/ipn', methods=['POST'])
def paypal_ipn():
    """
    处理 PayPal 的 IPN 请求
    """

    try:
        ipn_data = request.form.to_dict()

        # 验证 IPN
        if not verify_ipn(ipn_data):
            logger.warning("IPN verification failed")
            return "IPN Verification Failed", 400

        # 检查支付状态
        if ipn_data.get('payment_status') != 'Completed':
            logger.info(f"Ignored payment_status: {ipn_data.get('payment_status')}")
            return "Not a completed payment", 200
        

        # 构造订单数据
        order_data = {
            "order_id": ipn_data.get('txn_id'),
            "order_status": ipn_data.get('payment_status'),
            "order_intent": "CAPTURE",
            "order_create_time": ipn_data.get('payment_date'),
            "order_update_time": datetime.utcnow().isoformat(),
            "payer_id": ipn_data.get('payer_id'),
            "payer_email": ipn_data.get('payer_email'),
            "payer_name": f"{ipn_data.get('first_name', '')} {ipn_data.get('last_name', '')}".strip(),
            "payer_status": ipn_data.get('payer_status'),
            "currency_code": ipn_data.get('mc_currency'),
            "amount": ipn_data.get('mc_gross'),
            "capture_id": ipn_data.get('txn_id'),
            "capture_status": "COMPLETED",
            "net_amount": float(ipn_data.get('mc_gross', 0)) - float(ipn_data.get('mc_fee', 0)),
            "paypal_fee": ipn_data.get('mc_fee'),
            "shipping_method": ipn_data.get('shipping_method'),
            "shipping_amount": ipn_data.get('mc_shipping'),
            "shipping_discount": ipn_data.get('shipping_discount'),
            "item_name": ipn_data.get('item_name1'),
            "item_number": ipn_data.get('item_number1'),
            "quantity": ipn_data.get('quantity1'),
            "custom_field": ipn_data.get('custom'),
            "transaction_type": ipn_data.get('txn_type'),
            "payment_type": ipn_data.get('payment_type'),
            "discount_amount": ipn_data.get('discount'),
            "insurance_amount": ipn_data.get('insurance_amount'),
            "receipt_id": ipn_data.get('receipt_id'),
            "transaction_subject": ipn_data.get('transaction_subject'),
            "ipn_track_id": ipn_data.get('ipn_track_id'),
            "shipping_address_recipient_name": ipn_data.get('address_name'),
            "shipping_address_line_1": ipn_data.get('address_street'),
            "shipping_address_admin_area_2": ipn_data.get('address_city'),
            "shipping_address_admin_area_1": ipn_data.get('address_state'),
            "shipping_address_postal_code": ipn_data.get('address_zip'),
            "shipping_address_country_code": ipn_data.get('residence_country'),
            "resource": ipn_data,
            "created_at": datetime.utcnow().isoformat(),
            "resource": ipn_data,
            "created_at": datetime.utcnow().isoformat()
        }
        
        order_data = clean_order_data(order_data)
        save_to_database(order_data)

        logger.info(f"IPN processed for order_id={order_data['order_id']}")
        return "OK", 200

    except Exception as e:
        logger.error(f"Error processing IPN: {e}", exc_info=True)
        return "Internal Server Error", 500


csrf.exempt(paypal_ipn)


print(f"Supabase connection status: {'success' if supabase else 'failed'}")




@app.route('/get_user_profile', methods=['GET'])
def get_user_profile():
    if not session.get('logged_in'):
        return jsonify({"success": False, "message": "User not logged in"}), 401

    user_email = session.get('email')
    response = supabase.table('users').select('username, email, query_count').eq('email', user_email).execute()
    tier_response = supabase.table('paypal_orders').select('item_number').eq('payer_email', user_email).execute()

    # 定义优先级
    priority_order = ['Full Access Plan', 'Standard Tier', 'Additional Learning Materials']

    if response.data:
        users = response.data[0]  # 获取用户数据
        tier_data = tier_response.data  # 获取支付数据

        # 找到优先级最高的 item_number
        highest_priority_tier = None
        for priority in priority_order:
            for record in tier_data:
                if record['item_number'].strip() == priority:
                    highest_priority_tier = record
                    break  # 找到最高优先级的 item_number 后退出循环
            if highest_priority_tier:
                break

        # 更新用户数据
        if highest_priority_tier:
            users.update(highest_priority_tier)  # 添加优先级最高的 item_number
            

        return jsonify({"success": True, "user": users}), 200
    else:
        return jsonify({"success": False, "message": "User not found"}), 404
    
@app.route('/<filename>')
def serve_root_files(filename):
    return send_from_directory('.', filename)


@app.route('/sitemap.xml')
def serve_sitemap():
    try:
        # Get absolute path and verify it's within app directory
        sitemap_path = Path(app.root_path) / 'sitemap.xml'
        if not sitemap_path.is_file():
            abort(404)
            
        with open(sitemap_path, 'r') as file:
            sitemap_content = file.read()
            
        return Response(
            sitemap_content, 
            mimetype='application/xml',
            headers={'Content-Type': 'application/xml; charset=utf-8'}
        )
    except Exception as e:
        app.logger.error(f"Error serving sitemap: {e}")
        abort(500)

if __name__ == '__main__':
    app.run(debug=False)



    
   
