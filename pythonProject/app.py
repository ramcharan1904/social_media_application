from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import bcrypt
import os
import re
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 5  # 5MB max size

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()

    # Backup data from existing tables
    c.execute('SELECT * FROM posts')
    posts_data = c.fetchall()

    # Drop existing tables
    c.execute('DROP TABLE IF EXISTS posts')
    c.execute('DROP TABLE IF EXISTS likes')
    c.execute('DROP TABLE IF EXISTS comments')
    c.execute('DROP TABLE IF EXISTS groups')
    c.execute('DROP TABLE IF EXISTS group_members')
    c.execute('DROP TABLE IF EXISTS followers')

    # Create new tables
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            profile_image TEXT,
            bio TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            image TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            post_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (post_id) REFERENCES posts(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            post_id INTEGER,
            comment TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (post_id) REFERENCES posts(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            created_by INTEGER,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER,
            user_id INTEGER,
            FOREIGN KEY (group_id) REFERENCES groups(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS followers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            follower_id INTEGER,
            followed_id INTEGER,
            FOREIGN KEY (follower_id) REFERENCES users(id),
            FOREIGN KEY (followed_id) REFERENCES users(id)
        )
    ''')

    # Restore data into new table
    for post in posts_data:
        c.execute('INSERT INTO posts (user_id, content, image, timestamp) VALUES (?, ?, ?, ?)', (post[1], post[2], post[3], post[4]))

    conn.commit()
    conn.close()

def get_user_by_id(user_id):
    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    return user

def check_if_following(follower_id, followed_id):
    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('SELECT 1 FROM followers WHERE follower_id = ? AND followed_id = ?', (follower_id, followed_id))
    is_following = c.fetchone() is not None
    conn.close()
    return is_following

def follow_user(follower_id, followed_id):
    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('INSERT INTO followers (follower_id, followed_id) VALUES (?, ?)', (follower_id, followed_id))
    conn.commit()
    conn.close()

def unfollow_user(follower_id, followed_id):
    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('DELETE FROM followers WHERE follower_id = ? AND followed_id = ?', (follower_id, followed_id))
    conn.commit()
    conn.close()

def get_posts_by_user_id(user_id):
    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('SELECT * FROM posts WHERE user_id = ?', (user_id,))
    posts = c.fetchall()
    conn.close()
    return posts

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not (first_name and last_name and email and password and confirm_password):
            flash('All fields are required!', 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))

        # Password validation
        password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$')
        if not password_pattern.match(password):
            flash('Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, and one number.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            conn = sqlite3.connect('socialmedia.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)', (first_name, last_name, email, hashed_password))
            conn.commit()
            conn.close()
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists!', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = sqlite3.connect('socialmedia.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[4]):
            session['user_id'] = user[0]
            flash('Login successful!', 'success')
            return redirect(url_for('newsfeed'))
        else:
            flash('Login failed! Check your email and password.', 'danger')

    return render_template('login.html')

@app.route('/newsfeed')
def newsfeed():
    if 'user_id' not in session:
        flash('Please login to view the newsfeed.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()

    # Retrieve posts along with like and comment counts
    c.execute('''
        SELECT p.id, u.first_name, u.last_name, p.content, p.image,
               (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
               (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.timestamp DESC
    ''')
    posts = c.fetchall()
    conn.close()

    return render_template('newsfeed.html', posts=posts)

@app.route('/post', methods=['POST'])
def post():
    if 'user_id' not in session:
        flash('Please login to post.', 'danger')
        return redirect(url_for('login'))

    content = request.form.get('content')
    user_id = session['user_id']
    image = None

    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            image = filename

    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('INSERT INTO posts (user_id, content, image) VALUES (?, ?, ?)', (user_id, content, image))
    conn.commit()
    conn.close()

    return redirect(url_for('newsfeed'))

@app.route('/like/<int:post_id>', methods=['POST'])
def like(post_id):
    if 'user_id' not in session:
        flash('Please login to like posts.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('INSERT INTO likes (user_id, post_id) VALUES (?, ?)', (user_id, post_id))
    conn.commit()
    conn.close()

    return redirect(url_for('newsfeed'))

@app.route('/comment/<int:post_id>', methods=['POST'])
def comment(post_id):
    if 'user_id' not in session:
        flash('Please login to comment on posts.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    comment_text = request.form.get('comment')

    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('INSERT INTO comments (user_id, post_id, comment) VALUES (?, ?, ?)', (user_id, post_id, comment_text))
    conn.commit()
    conn.close()

    return redirect(url_for('newsfeed'))

@app.route('/comments/<int:post_id>')
def comments(post_id):
    if 'user_id' not in session:
        flash('Please login to view comments.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()

    # Get the post details and counts
    c.execute('''
        SELECT (SELECT COUNT(*) FROM likes WHERE post_id = ?) as like_count,
               (SELECT COUNT(*) FROM comments WHERE post_id = ?) as comment_count
    ''', (post_id, post_id))
    counts = c.fetchone()
    like_count, comment_count = counts if counts else (0, 0)

    # Get comments
    c.execute('''
        SELECT users.first_name, users.last_name, comments.comment, comments.timestamp
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = ?
        ORDER BY comments.timestamp DESC
    ''', (post_id,))
    comments = c.fetchall()
    conn.close()

    return render_template('comments.html', post_id=post_id, comments=comments, like_count=like_count, comment_count=comment_count)

@app.route('/search_users', methods=['GET', 'POST'])
def search_users():
    if 'user_id' not in session:
        flash('Please login to search for users.', 'danger')
        return redirect(url_for('login'))

    search_query = ''
    users = []

    if request.method == 'POST':
        search_query = request.form['search_query']
        conn = sqlite3.connect('socialmedia.db')
        c = conn.cursor()
        c.execute('''
            SELECT id, first_name, last_name, email
            FROM users
            WHERE first_name LIKE ? OR last_name LIKE ? OR email LIKE ?
        ''', (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
        users = c.fetchall()
        conn.close()

    return render_template('search_users.html', users=users, search_query=search_query)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'user_id' not in session:
        flash('Please login to create a group.', 'danger')
        return redirect(url_for('login'))

    group_name = request.form['group_name']

    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('INSERT INTO groups (name, created_by) VALUES (?, ?)', (group_name, session['user_id']))
    conn.commit()
    conn.close()

    flash('Group created successfully!', 'success')
    return redirect(url_for('groups'))

@app.route('/groups')
def groups():
    if 'user_id' not in session:
        flash('Please login to view groups.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    c.execute('''
        SELECT groups.id, groups.name, users.first_name, users.last_name
        FROM groups
        JOIN users ON groups.created_by = users.id
    ''')
    groups = c.fetchall()
    conn.close()

    return render_template('groups.html', groups=groups)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        flash('Please login to update your profile.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    bio = request.form.get('bio')
    profile_image = None

    if 'profile_image' in request.files:
        file = request.files['profile_image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_image = filename

    conn = sqlite3.connect('socialmedia.db')
    c = conn.cursor()
    if profile_image:
        c.execute('UPDATE users SET bio = ?, profile_image = ? WHERE id = ?', (bio, profile_image, user_id))
    else:
        c.execute('UPDATE users SET bio = ? WHERE id = ?', (bio, user_id))
    conn.commit()
    conn.close()

    return redirect(url_for('user_profile', user_id=user_id))



@app.route('/user_profile/<int:user_id>', methods=['GET', 'POST'])
def user_profile(user_id):
    # Check if the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Get the user details
    user = get_user_by_id(user_id)
    if not user:
        return "User not found", 404

    # Check if the current user is following this user
    is_following = check_if_following(session['user_id'], user_id)

    if request.method == 'POST':
        if 'follow' in request.form:
            follow_user(session['user_id'], user_id)
        elif 'unfollow' in request.form:
            unfollow_user(session['user_id'], user_id)
        return redirect(url_for('user_profile', user_id=user_id))

    # Get user posts only if the current user is following the user
    posts = []
    if is_following:
        posts = get_posts_by_user_id(user_id)

    return render_template('user_profile.html', user=user, posts=posts, is_following=is_following)

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    init_db()
    app.run(debug=True)
