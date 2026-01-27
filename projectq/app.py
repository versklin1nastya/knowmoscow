import sys
print("Python executable:", sys.executable)
print("Python version:", sys.version)
import json
import secrets
import os
import qrcode
import io
import base64
from flask import Flask, request, render_template, redirect, url_for, flash, session, abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database (1) (1).db')
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def load_places():
    with open(os.path.join(DATA_DIR, 'places.json'), encoding='utf-8') as f:
        return json.load(f)


def load_tests():
    with open(os.path.join(DATA_DIR, 'tests.json'), encoding='utf-8') as f:
        raw = json.load(f)
        return {int(k): v for k, v in raw.items()}


places = load_places()
tests = load_tests()


def generate_invite_code():
    return secrets.token_urlsafe(16)


@app.route("/")
def Mainpage():
    return render_template("Mainpage.html")


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name')
        surname = request.form.get('surname')
        login = request.form.get('login')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (name, surname, login, email, password) VALUES (?,?,?,?,?)',
                       (name, surname, login, email, hashed_password))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        session['user_id'] = user_id
        return redirect(url_for("Mainpage"))
    return render_template("login.html")


@app.route("/enter", methods=['GET', 'POST'])
def enter():
    if request.method == 'POST':
        login = request.form.get('login')
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE login=? AND email=?', (login, email))
        user = cursor.fetchone()
        conn.close()
        if user:
            if check_password_hash(user[5], password):
                session['user_id'] = user[0]
                flash("Вход выполнен успешно!", "success")
                return redirect(url_for("Mainpage"))
            else:
                flash("Неправильный пароль.", "error")
        else:
            flash("Неправильный логин или email.", "error")
    return render_template("enter.html")


@app.route("/account")
def account():
    if 'user_id' not in session:
        flash("Вы не авторизованы.", "error")
        return redirect(url_for('Mainpage'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT name, surname, login, email FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    if user:
        return render_template('account.html', user=user)
    else:
        flash("Профиль не найден.", "error")
        return redirect(url_for('Mainpage'))


@app.route('/information')
def information():
    id = request.args.get('id')
    if id and id in places:
        place = places[id]
        return render_template('information.html', title=place['title'], description=place['description'])
    else:
        return 'Информация не найдена', 404


@app.route('/test', methods=['GET', 'POST'])
def test_route():
    test_id = request.args.get('id')
    try:
        test_id = int(test_id)
    except (ValueError, TypeError):
        return "Ошибка: Неверный ID теста", 400
    test_data = tests.get(test_id)
    if test_data is None:
        return "Ошибка: тест не найден", 404
    if request.method == 'POST':
        answers = {}
        correct_answers = 0
        total_questions = len(test_data['questions'])
        for question in test_data['questions']:
            question_text = question['question']
            user_answer = request.form.get(question_text)
            answers[question_text] = user_answer
            if user_answer == question['correct']:
                correct_answers += 1
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('enter'))
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT login FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return redirect(url_for('enter'))
        user_login = user['login']
        try:
            cursor.execute('''INSERT INTO results (test_id, user_login, user_answers, correct_answers, total_questions)
                              VALUES (?, ?, ?, ?, ?)''',
                           (test_id, user_login, json.dumps(answers), correct_answers, total_questions))
            conn.commit()
            flash(f"Тест пройден! Правильных ответов: {correct_answers}/{total_questions}", "success")
        except sqlite3.Error as e:
            print(f"Ошибка при сохранении результатов: {e}")
            conn.rollback()
            flash("Ошибка при сохранении результатов.", "error")
        finally:
            conn.close()
        return redirect(url_for('rating'))
    return render_template('test.html', test=test_data)


@app.route('/rating')
def rating():
    if 'user_id' not in session:
        return redirect(url_for('enter'))
    user_id = session['user_id']
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT login FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return redirect(url_for('enter'))
    user_login = user['login']
    cursor.execute('''
        SELECT test_id, MAX(correct_answers) as correct_answers, total_questions
        FROM results
        WHERE user_login = ?
        GROUP BY test_id
    ''', (user_login,))
    user_results = cursor.fetchall()
    conn.close()
    return render_template('rating.html', user_results=user_results, tests=tests)


@app.route('/achievement')
def achievement():
    if 'user_id' not in session:
        return redirect(url_for('enter'))
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT
            user_login,
            SUM(correct_answers) AS total_correct_answers,
            COUNT(DISTINCT test_id) AS tests_taken
        FROM results
        GROUP BY user_login
        ORDER BY total_correct_answers DESC
    ''')
    user_achievements = cursor.fetchall()
    conn.close()
    ranked_achievements = []
    rank = 1
    for i, user_achievement in enumerate(user_achievements):
        ranked_achievements.append({
            'rank': rank,
            'user_login': user_achievement['user_login'],
            'total_correct_answers': user_achievement['total_correct_answers'],
            'tests_taken': user_achievement['tests_taken']
        })
        if i + 1 < len(user_achievements) and user_achievements[i + 1]['total_correct_answers'] < user_achievement[
            'total_correct_answers']:
            rank += 1
    return render_template('achievement.html', ranked_achievements=ranked_achievements)


@app.route('/groups')
def groups():
    if 'user_id' not in session:
        return redirect(url_for('enter'))
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT g.*
        FROM groups g
        JOIN user_groups ug ON g.id = ug.group_id
        WHERE ug.user_id = ?
    """, (user_id,))
    user_groups = cursor.fetchall()
    conn.close()
    return render_template('groups.html', user_groups=user_groups)


@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'user_id' not in session:
        return redirect(url_for('enter'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        owner_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            invite_code = generate_invite_code()
            cursor.execute("INSERT INTO groups (name, description, owner_id, invite_code) VALUES (?, ?, ?, ?)",
                           (name, description, owner_id, invite_code))
            conn.commit()
            group_id = cursor.lastrowid
            cursor.execute("SELECT * FROM user_groups WHERE user_id = ? AND group_id = ?", (owner_id, group_id))
            existing_membership = cursor.fetchone()
            if not existing_membership:
                cursor.execute("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", (owner_id, group_id))
                conn.commit()
            return redirect(url_for('group_page', group_id=group_id))
        except sqlite3.Error as e:
            print(f"Ошибка базы данных: {e}")
            conn.rollback()
            return render_template('create_group.html', error="Ошибка создания группы")
        finally:
            conn.close()
    return render_template('create_group.html')


@app.route('/edit_group/<int:group_id>', methods=['GET', 'POST'])
def edit_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('enter'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM groups WHERE id = ?", (group_id,))
    group = cursor.fetchone()
    if not group or group['owner_id'] != session['user_id']:
        conn.close()
        flash("У вас нет прав на редактирование этой группы", "error")
        return redirect(url_for('group_page', group_id=group_id))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']

        try:
            cursor.execute("UPDATE groups SET name = ?, description = ? WHERE id = ?", (name, description, group_id))
            conn.commit()
            return redirect(url_for('group_page', group_id=group_id))

        except sqlite3.Error as e:
            print(f"Ошибка базы данных при обновлении группы {group_id}: {e}")
            conn.rollback()
            return render_template('edit_group.html', group=group, error="Ошибка сохранения изменений")
        finally:
            conn.close()
    return render_template('edit_group.html', group=group)


@app.route('/group/<int:group_id>/invite_code')
def show_invite_code(group_id):
    """Отображает код приглашения и QR-код для владельца группы."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM groups WHERE id = ? AND owner_id = ?", (group_id, user_id))
    group = cursor.fetchone()
    conn.close()
    if not group:
        return "У вас нет прав на просмотр этого кода приглашения."

    invite_link = url_for('join_group', invite_code=group['invite_code'], _external=True)


    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(invite_link)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#bb00c2", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return render_template(
        'invite_code.html',
        invite_code=group['invite_code'],
        invite_link=invite_link,
        group_name=group['name'],
        group_id=group_id,
        qr_code_base64=qr_code_base64
    )


@app.route('/join_group/<invite_code>')
def join_group(invite_code):
    if 'user_id' not in session:
        return redirect(url_for('enter'))
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM groups WHERE invite_code = ?", (invite_code,))
    group = cursor.fetchone()
    if not group:
        conn.close()
        return "Неверный код приглашения."
    group_id = group['id']
    cursor.execute("SELECT * FROM user_groups WHERE user_id = ? AND group_id = ?", (user_id, group_id))
    existing_membership = cursor.fetchone()
    if existing_membership:
        conn.close()
        return "Вы уже состоите в этой группе."
    try:
        cursor.execute("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", (user_id, group_id))
        conn.commit()
        return redirect(url_for('group_page', group_id=group_id))
    except sqlite3.IntegrityError as e:
        print(f"Unexpected IntegrityError: {e}")
        conn.rollback()
        return "Произошла неожиданная ошибка при попытке добавить вас в группу."
    finally:
        conn.close()


@app.route('/assign_test/<int:group_id>', methods=['GET', 'POST'])
def assign_test(group_id):
    if 'user_id' not in session:
        return redirect(url_for('enter'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT owner_id FROM groups WHERE id = ?", (group_id,))
    group = cursor.fetchone()
    if not group or group['owner_id'] != session['user_id']:
        conn.close()
        return "У вас нет прав на назначение тестов этой группе."
    tests_list = list(tests.keys())
    conn.close()
    if request.method == 'POST':
        test_id = int(request.form['test_id'])
        if test_id not in tests:
            return "Тест с указанным ID не найден."
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO group_tests (group_id, test_id) VALUES (?, ?)", (group_id, test_id))
            conn.commit()
            return redirect(url_for('group_page', group_id=group_id))
        except sqlite3.Error as e:
            print(f"Ошибка базы данных: {e}")
            conn.rollback()
            return "Ошибка назначения теста."
        finally:
            conn.close()
    return render_template('assign_test.html', group_id=group_id, tests_list=tests_list, tests=tests)


@app.route('/group/<int:group_id>/results')
def view_test_results(group_id):
    if 'user_id' not in session:
        return redirect(url_for('enter'))

    user_id = session['user_id']
    conn = None
    results = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT owner_id FROM groups WHERE id = ?", (group_id,))
        group = cursor.fetchone()

        if not group:
            abort(404, description=f"Группа с ID {group_id} не найдена.")

        if group['owner_id'] != user_id:
            abort(403, description="У вас нет прав на просмотр результатов тестов в этой группе.")
        results_query = """
        SELECT 
            u.login, 
            tr.correct_answers 
        FROM results tr
        JOIN users u ON tr.user_id = u.id
        WHERE tr.group_id = ?
        ORDER BY tr.correct_answers DESC
        """
        cursor.execute(results_query, (group_id,))
        results = cursor.fetchall()
    except Exception as e:
        print(f"Database error: {e}")
        abort(500, description="Ошибка при получении результатов из базы данных.")

    finally:
        if conn:
            conn.close()
    return render_template(
        'test_results.html',
        group_id=group_id,
        results=results
    )


@app.route('/group/<int:group_id>')
def group_page(group_id):
    if 'user_id' not in session:
        return redirect(url_for('enter'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM groups WHERE id = ?", (group_id,))
    group = cursor.fetchone()
    if not group:
        conn.close()
        return "Группа не найдена"
    cursor.execute("SELECT test_id FROM group_tests WHERE group_id = ?", (group_id,))
    assigned_test_ids = [row['test_id'] for row in cursor.fetchall()]
    conn.close()
    assigned_tests = {test_id: tests[test_id] for test_id in assigned_test_ids if test_id in tests}
    return render_template('group_page.html', group=group, tests=assigned_tests)


@app.route('/group/<int:group_id>/members')
def group_members(group_id):
    if 'user_id' not in session:
        return redirect(url_for('enter'))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM groups WHERE id = ?", (group_id,))
    group = cursor.fetchone()
    if not group:
        conn.close()
        return "Группа не найдена"
    cursor.execute("SELECT user_id FROM user_groups WHERE group_id = ?", (group_id,))
    user_ids = [row['user_id'] for row in cursor.fetchall()]
    members = []
    for user_id in user_ids:
        cursor.execute("SELECT id, login FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            members.append(user)
    conn.close()
    return render_template('group_members.html', group=group, members=members)


if __name__ == '__main__':
    app.run(debug=True)