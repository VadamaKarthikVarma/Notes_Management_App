from flask import Flask, render_template, request, redirect, session, flash, url_for
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail,Message
import secrets

app = Flask(__name__)
app.secret_key = "seCrect_kee"  # Change this for production

# Mail Configuration

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'vedha0316.10@gmail.com'
app.config['MAIL_PASSWORD'] = 'xjkv ndhk gzzl goom'
app.config['MAIL_DEFAULT_SENDER'] = ('Notes App','vedha0316.10@gmail.com')
mail=Mail(app)


# Database Connection 

def get_db_connection():
    """
    Create and return a new MySQL connection.
    """
    conn = mysql.connector.connect(
        host="localhost",
        user="root",       # Change if different
        password="root",  # Your MySQL password
        database="notesdb" # Must match DB name created below
    )
    return conn


# Home (redirect)

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect('/viewall')
    return redirect('/login')


# Register Route

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not username or not email or not password:
            flash("Please fill all fields.", "danger")
            return redirect('/register')

        hashed_pw = generate_password_hash(password)
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            flash("Username already exists.", "danger")
            cur.close()
            conn.close()
            return redirect('/register')

        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, hashed_pw))
        conn.commit()
        cur.close()
        conn.close()
        flash("Registration successful! You can now log in.", "success")
        return redirect('/login')

    return render_template('register.html')


# Login Route

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if not username or not password:
            flash("Enter username and password.", "danger")
            return redirect('/login')

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f"Welcome, {user['username']}!", "success")
            return redirect('/viewall')
        else:
            flash("Invalid username or password.", "danger")
            return redirect('/login')

    return render_template('login.html')


# Logout

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect('/login')


# Add Note (CREATE)

@app.route('/addnote', methods=['GET', 'POST'])
def addnote():
    if 'user_id' not in session:
        flash("Please login first.", "warning")
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()

        if not title or not content:
            flash("Title and content cannot be empty.", "danger")
            return redirect('/addnote')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO notes (title, content, user_id) VALUES (%s, %s, %s)",
                    (title, content, session['user_id']))
        conn.commit()
        cur.close()
        conn.close()
        flash("Note added successfully.", "success")
        return redirect('/viewall')

    return render_template('addnote.html')

# View All Notes (READ ALL + SEARCH)
@app.route('/viewall', methods=['GET', 'POST'])
def viewall():
    if 'user_id' not in session:
        return redirect('/login')

    search_query = ""
    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # Get total count of notes for this user (used to decide messaging)
    cur.execute("SELECT COUNT(*) AS cnt FROM notes WHERE user_id = %s", (user_id,))
    total_count_row = cur.fetchone()
    has_any_notes = (total_count_row and total_count_row['cnt'] > 0)

    notes = []
    search_performed = False

    if request.method == 'POST':
        search_performed = True
        search_query = request.form['search'].strip()
        cur.execute("""
            SELECT id, title, content, created_at 
            FROM notes 
            WHERE user_id = %s AND (title LIKE %s OR content LIKE %s)
            ORDER BY created_at DESC
        """, (user_id, f"%{search_query}%", f"%{search_query}%"))
        notes = cur.fetchall()
    else:
        cur.execute("SELECT id, title, content, created_at FROM notes WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        notes = cur.fetchall()

    cur.close()
    conn.close()
    return render_template(
        'viewnotes.html',
        notes=notes,
        search_query=search_query,
        search_performed=search_performed,
        has_any_notes=has_any_notes
    )


# View Single Note (READ ONE)

@app.route('/viewnotes/<int:note_id>')
def viewnotes(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
    note = cur.fetchone()
    cur.close()
    conn.close()

    if not note:
        flash("You don't have access to this note.", "danger")
        return redirect('/viewall')

    return render_template('singlenote.html', note=note)


# Update Note (UPDATE)

@app.route('/updatenote/<int:note_id>', methods=['GET', 'POST'])
def updatenote(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
    note = cur.fetchone()

    if not note:
        flash("You are not authorized to edit this note.", "danger")
        cur.close()
        conn.close()
        return redirect('/viewall')

    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        if not title or not content:
            flash("Title and content cannot be empty.", "danger")
            return redirect(url_for('updatenote', note_id=note_id))

        cur.execute("UPDATE notes SET title=%s, content=%s WHERE id=%s AND user_id=%s",
                    (title, content, note_id, session['user_id']))
        conn.commit()
        flash("Note updated successfully.", "success")
        cur.close()
        conn.close()
        return redirect('/viewall')

    cur.close()
    conn.close()
    return render_template('updatenote.html', note=note)

# Delete Note (DELETE)

@app.route('/deletenote/<int:note_id>', methods=['POST'])
def deletenote(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
    conn.commit()
    cur.close()
    conn.close()
    flash("Note deleted successfully.", "info")
    return redirect('/viewall')

# Global Search (Notes + Users)

@app.route('/search', methods=['POST'])
def search():
    if 'user_id' not in session:
        return redirect('/login')

    query = request.form['query'].strip()
    if not query:
        flash("Please enter something to search.", "warning")
        return redirect('/viewall')

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # Search both user's own notes and all usernames (students)
    cur.execute("""
        SELECT id, title, content, created_at 
        FROM notes 
        WHERE user_id = %s AND (title LIKE %s OR content LIKE %s)
    """, (session['user_id'], f"%{query}%", f"%{query}%"))
    notes = cur.fetchall()

    cur.execute("""
        SELECT username, email 
        FROM users 
        WHERE username LIKE %s
    """, (f"%{query}%",))
    students = cur.fetchall()

    cur.close()
    conn.close()

    if not notes and not students:
        flash("No matching results found.", "info")

    return render_template('search_results.html', query=query, notes=notes, students=students)

# About Page

@app.route('/about')
def about():
    return render_template('about.html')


# Contact Page


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        message = request.form['message'].strip()

        if not name or not email or not message:
            flash("Please fill out all fields before submitting.", "danger")
            return redirect('/contact')

        # ✅ Create email message
        msg = Message(
            subject=f"New Contact Message from {name}",
            recipients=['chikineshailesh@gmail.com'],  # <-- your email
            body=f"""
You have received a new message via your Notes Management System contact form.

From: {name}
Email: {email}

Message:
{message}
            """
        )

        try:
            mail.send(msg)
            flash("✅ Your message has been sent successfully!", "success")
        except Exception as e:
            print("Error sending email:", e)
            flash("⚠️ Failed to send the message. Please try again later.", "danger")

        return redirect('/contact')

    return render_template('contact.html')

# Forgot Password - Request Reset

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()

        if not email:
            flash("Please enter your email.", "warning")
            return redirect('/forgot')

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            token = secrets.token_urlsafe(16)
            cur.execute("UPDATE users SET reset_token = %s WHERE email = %s", (token, email))
            conn.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Hi {user['username']},\n\nClick this link to reset your password:\n{reset_link}\n\nIf you didn't request this, ignore this email."
            mail.send(msg)

            flash("A password reset link has been sent to your email.", "info")
        else:
            flash("No account found with that email.", "danger")

        cur.close()
        conn.close()
        return redirect('/login')

    return render_template('forgot_password.html')

# Reset Password - Form

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE reset_token = %s", (token,))
    user = cur.fetchone()

    if not user:
        flash("Invalid or expired reset link.", "danger")
        cur.close()
        conn.close()
        return redirect('/login')

    if request.method == 'POST':
        new_password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()

        if not new_password or not confirm_password:
            flash("Please fill all fields.", "danger")
        elif new_password != confirm_password:
            flash("Passwords do not match.", "danger")
        else:
            hashed_pw = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password = %s, reset_token = NULL WHERE id = %s", (hashed_pw, user['id']))
            conn.commit()
            flash("Password updated successfully! You can now log in.", "success")
            cur.close()
            conn.close()
            return redirect('/login')

    cur.close()
    conn.close()
    return render_template('reset_password.html', token=token)

# Run App
if __name__ == '__main__':
    app.run(debug=True)
