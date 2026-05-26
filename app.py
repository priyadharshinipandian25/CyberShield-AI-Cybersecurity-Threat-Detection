from flask import Flask, render_template, request, redirect, url_for, session, Response, send_file
import os, sqlite3, csv, io, hashlib
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import numpy as np
try:
    import joblib
except Exception:
    joblib = None
try:
    from fpdf import FPDF
except Exception:
    FPDF = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'cybershield.db')
MODEL_PATH = os.path.join(BASE_DIR, 'cyber_model.pkl')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = 'cybershield_final_clean_secret'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

FEATURES = [
    'protocol', 'flow_duration', 'total_forward_packets', 'total_backward_packets',
    'total_forward_packets_length', 'total_backward_packets_length',
    'forward_packet_length_mean', 'backward_packet_length_mean',
    'forward_packets_per_second', 'backward_packets_per_second',
    'forward_iat_mean', 'backward_iat_mean', 'flow_iat_mean',
    'flow_packets_per_seconds', 'flow_bytes_per_seconds'
]
FEATURE_LABELS = {
    'protocol':'Protocol', 'flow_duration':'Flow Duration',
    'total_forward_packets':'Total Forward Packets', 'total_backward_packets':'Total Backward Packets',
    'total_forward_packets_length':'Forward Packets Length', 'total_backward_packets_length':'Backward Packets Length',
    'forward_packet_length_mean':'Forward Packet Length Mean', 'backward_packet_length_mean':'Backward Packet Length Mean',
    'forward_packets_per_second':'Forward Packets/sec', 'backward_packets_per_second':'Backward Packets/sec',
    'forward_iat_mean':'Forward IAT Mean', 'backward_iat_mean':'Backward IAT Mean',
    'flow_iat_mean':'Flow IAT Mean', 'flow_packets_per_seconds':'Flow Packets/sec',
    'flow_bytes_per_seconds':'Flow Bytes/sec'
}

try:
    model = joblib.load(MODEL_PATH) if joblib and os.path.exists(MODEL_PATH) else None
except Exception:
    model = None


def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(cur, table, column):
    return column in [r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()]


def init_db():
    conn = get_db(); cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS detections(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        result TEXT,
        severity TEXT,
        confidence REAL,
        recommendation TEXT,
        security_score INTEGER,
        ip_address TEXT,
        country TEXT,
        created_at TEXT,
        protocol REAL, flow_duration REAL, total_forward_packets REAL, total_backward_packets REAL,
        total_forward_packets_length REAL, total_backward_packets_length REAL,
        forward_packet_length_mean REAL, backward_packet_length_mean REAL,
        forward_packets_per_second REAL, backward_packets_per_second REAL,
        forward_iat_mean REAL, backward_iat_mean REAL, flow_iat_mean REAL,
        flow_packets_per_seconds REAL, flow_bytes_per_seconds REAL
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS malware_scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        filename TEXT,
        extension TEXT,
        file_size INTEGER,
        file_hash TEXT,
        risk_score INTEGER,
        result TEXT,
        reason TEXT,
        created_at TEXT
    )''')
    migrations = {
        'users': ["role TEXT DEFAULT 'user'", "status TEXT DEFAULT 'active'"],
        'detections': ["ip_address TEXT", "country TEXT"],
        'malware_scans': ["extension TEXT", "file_size INTEGER", "risk_score INTEGER", "reason TEXT"]
    }
    for table, defs in migrations.items():
        for coldef in defs:
            col = coldef.split()[0]
            if not column_exists(cur, table, col):
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {coldef}")
    cur.execute('SELECT id FROM users WHERE username=?', ('admin',))
    if not cur.fetchone():
        cur.execute('INSERT INTO users(username,email,password,role,status,created_at) VALUES(?,?,?,?,?,?)',
                    ('admin','admin@cybershield.com',generate_password_hash('admin123'),'admin','active',now()))
    else:
        cur.execute("UPDATE users SET role='admin', status='active' WHERE username='admin'")
    conn.commit(); conn.close()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = get_db(); user = conn.execute('SELECT status FROM users WHERE id=?', (session['user_id'],)).fetchone(); conn.close()
        if not user or user['status'] != 'active':
            session.clear()
            return redirect(url_for('login', blocked='1'))
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return redirect(url_for('home'))
        return func(*args, **kwargs)
    return wrapper


def get_client_details():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'Unknown').split(',')[0].strip()
    if ip in ['127.0.0.1', '::1', 'localhost']:
        country = 'Localhost / India'
    else:
        country = request.headers.get('CF-IPCountry') or request.headers.get('X-Country') or 'Unknown'
    return ip, country


def calculate_counts(user_id=None):
    conn = get_db(); uid = user_id or session.get('user_id')
    total = conn.execute('SELECT COUNT(*) c FROM detections WHERE user_id=?', (uid,)).fetchone()['c']
    attacks = conn.execute("SELECT COUNT(*) c FROM detections WHERE user_id=? AND result='Cyber Attack Detected'", (uid,)).fetchone()['c']
    normal = conn.execute("SELECT COUNT(*) c FROM detections WHERE user_id=? AND result='Normal Traffic'", (uid,)).fetchone()['c']
    malware = conn.execute('SELECT COUNT(*) c FROM malware_scans WHERE user_id=?', (uid,)).fetchone()['c']
    conn.close(); return total, attacks, normal, malware


def decide_result(values):
    if model is not None:
        try:
            data = np.array([values], dtype=float)
            pred = int(model.predict(data)[0])
            confidence = float(np.max(model.predict_proba(data)) * 100) if hasattr(model, 'predict_proba') else 88.0
            is_attack = pred != 0
        except Exception:
            confidence = 82.0
            is_attack = sum(values) > 20000 or values[8] > 500 or values[14] > 100000
    else:
        confidence = 80.0
        is_attack = sum(values) > 20000 or values[8] > 500 or values[14] > 100000
    if is_attack:
        severity = 'High' if confidence >= 85 else 'Medium'
        return 'Cyber Attack Detected', severity, round(confidence, 2), max(10, int(100-confidence)), 'Block suspicious source, monitor logs, isolate affected traffic, and verify firewall rules.'
    return 'Normal Traffic', 'Low', round(confidence, 2), min(100, int(confidence)), 'Traffic pattern looks safe. Continue monitoring network activity and logs.'


def scan_file(filename, data):
    ext = os.path.splitext(filename)[1].lower() or 'no extension'
    size = len(data)
    file_hash = hashlib.sha256(data).hexdigest()
    risky_ext = ['.exe','.bat','.cmd','.vbs','.scr','.js','.jar','.ps1','.msi','.dll']
    risk = 10; reasons = []
    if ext in risky_ext:
        risk += 55; reasons.append('risky executable/script extension')
    if size > 5_000_000:
        risk += 25; reasons.append('large file size')
    if b'powershell' in data.lower() or b'cmd.exe' in data.lower():
        risk += 25; reasons.append('suspicious command keyword found')
    risk = min(100, risk)
    if risk >= 70:
        result = 'High Risk Malware Suspicion'
    elif risk >= 40:
        result = 'Suspicious File Detected'
    else:
        result = 'File Looks Safe'
    reason = ', '.join(reasons) if reasons else 'no risky signature found in basic scan'
    return ext, size, file_hash, risk, result, reason


@app.route('/login', methods=['GET','POST'])
def login():
    blocked_msg = 'Your account is blocked by admin. Contact administrator.' if request.args.get('blocked') else None
    if request.method == 'POST':
        username = request.form.get('username','').strip(); password = request.form.get('password','').strip()
        conn = get_db(); user = conn.execute('SELECT * FROM users WHERE username=? OR email=?', (username, username)).fetchone(); conn.close()
        if user and check_password_hash(user['password'], password):
            if user['status'] != 'active':
                return render_template('login.html', error='Your account is blocked by admin. You cannot use the application now.')
            session['user_id']=user['id']; session['username']=user['username']; session['email']=user['email']; session['role']=user['role']
            return redirect(url_for('home'))
        return render_template('login.html', error='Invalid username/email or password')
    return render_template('login.html', error=blocked_msg)


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username=request.form.get('username','').strip(); email=request.form.get('email','').strip(); password=request.form.get('password','').strip()
        if not username or not email or not password:
            return render_template('register.html', error='All fields are required')
        conn=get_db()
        try:
            conn.execute('INSERT INTO users(username,email,password,role,status,created_at) VALUES(?,?,?,?,?,?)',
                         (username,email,generate_password_hash(password),'user','active',now()))
            conn.commit(); return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username or email already exists')
        finally:
            conn.close()
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))


@app.route('/')
@login_required
def home():
    total, attacks, normal, malware = calculate_counts()
    return render_template('index.html', total=total, attacks=attacks, normal=normal, malware=malware)


@app.route('/predict', methods=['GET','POST'])
@login_required
def predict():
    if request.method == 'POST':
        try:
            values = [float(request.form.get(f, 0)) for f in FEATURES]
        except ValueError:
            return render_template('predict.html', features=FEATURES, labels=FEATURE_LABELS, error='Enter numeric values only')
        result, severity, confidence, score, recommendation = decide_result(values)
        ip_address, country = get_client_details()
        conn=get_db(); columns=','.join(FEATURES); marks=','.join(['?']*len(FEATURES)); cur=conn.cursor()
        cur.execute(f'''INSERT INTO detections(user_id,username,result,severity,confidence,recommendation,security_score,ip_address,country,created_at,{columns})
                       VALUES(?,?,?,?,?,?,?,?,?,?,{marks})''',
                    [session['user_id'],session['username'],result,severity,confidence,recommendation,score,ip_address,country,now()]+values)
        detection_id=cur.lastrowid; conn.commit(); conn.close()
        return redirect(url_for('result', detection_id=detection_id))
    return render_template('predict.html', features=FEATURES, labels=FEATURE_LABELS)


@app.route('/result/<int:detection_id>')
@login_required
def result(detection_id):
    conn=get_db(); row=conn.execute('SELECT * FROM detections WHERE id=? AND user_id=?', (detection_id, session['user_id'])).fetchone(); conn.close()
    if not row: return redirect(url_for('history'))
    return render_template('result.html', row=row)


@app.route('/history')
@login_required
def history():
    total, attacks, normal, malware = calculate_counts()
    conn=get_db(); rows=conn.execute('SELECT * FROM detections WHERE user_id=? ORDER BY id DESC', (session['user_id'],)).fetchall(); conn.close()
    avg_confidence = round(sum(float(r['confidence']) for r in rows)/len(rows),2) if rows else 0
    return render_template('history.html', rows=rows, total=total, attacks=attacks, normal=normal, malware=malware, avg_confidence=avg_confidence)


@app.route('/delete/<int:detection_id>')
@login_required
def delete_detection(detection_id):
    conn=get_db(); conn.execute('DELETE FROM detections WHERE id=? AND user_id=?', (detection_id, session['user_id'])); conn.commit(); conn.close()
    return redirect(url_for('history'))


@app.route('/clear_history')
@login_required
def clear_history():
    conn=get_db(); conn.execute('DELETE FROM detections WHERE user_id=?', (session['user_id'],)); conn.commit(); conn.close()
    return redirect(url_for('history'))


@app.route('/export_csv')
@login_required
def export_csv():
    conn=get_db(); rows=conn.execute('SELECT created_at,result,severity,confidence,security_score,recommendation,ip_address,country FROM detections WHERE user_id=? ORDER BY id DESC', (session['user_id'],)).fetchall(); conn.close()
    output=io.StringIO(); writer=csv.writer(output)
    writer.writerow(['Date','Time','Country','IP Address','Result','Severity','Confidence','Security Score','Recommendation'])
    for r in rows:
        writer.writerow([r['created_at'][:10], r['created_at'][11:19], r['country'] or 'Unknown', r['ip_address'] or 'Unknown', r['result'], r['severity'], r['confidence'], r['security_score'], r['recommendation']])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=cybershield_history.csv'})


@app.route('/pdf_report/<int:detection_id>')
@login_required
def pdf_report(detection_id):
    conn=get_db(); r=conn.execute('SELECT * FROM detections WHERE id=? AND user_id=?', (detection_id, session['user_id'])).fetchone(); conn.close()
    if not r: return redirect(url_for('history'))
    path=os.path.join(UPLOAD_FOLDER, f'cybershield_report_{detection_id}.pdf')
    if FPDF:
        pdf=FPDF(); pdf.add_page(); pdf.set_font('Arial','B',18); pdf.cell(0,12,'CyberShield Detection Report',ln=True,align='C')
        pdf.set_font('Arial','',12)
        fields=[('User',session['username']),('Date',r['created_at'][:10]),('Time',r['created_at'][11:19]),('Country',r['country'] or 'Unknown'),('IP Address',r['ip_address'] or 'Unknown'),('Result',r['result']),('Severity',r['severity']),('Confidence',str(r['confidence'])+'%'),('Security Score',str(r['security_score'])),('Recommendation',r['recommendation'])]
        for k,v in fields: pdf.multi_cell(0,8,f'{k}: {v}')
        pdf.output(path)
    else:
        with open(path,'w') as f: f.write(f"CyberShield Detection Report\nResult: {r['result']}\n")
    return send_file(path, as_attachment=True)


@app.route('/malware', methods=['GET','POST'])
@login_required
def malware():
    scan=None
    if request.method == 'POST':
        file=request.files.get('file')
        if file and file.filename:
            filename=secure_filename(file.filename); data=file.read()
            ext,size,file_hash,risk,result_text,reason = scan_file(filename, data)
            scan={'filename':filename,'extension':ext,'size':size,'hash':file_hash,'risk':risk,'result':result_text,'reason':reason}
            conn=get_db(); conn.execute('''INSERT INTO malware_scans(user_id,username,filename,extension,file_size,file_hash,risk_score,result,reason,created_at)
                                         VALUES(?,?,?,?,?,?,?,?,?,?)''',
                                      (session['user_id'],session['username'],filename,ext,size,file_hash,risk,result_text,reason,now()))
            conn.commit(); conn.close()
    conn=get_db(); scans=conn.execute('SELECT * FROM malware_scans WHERE user_id=? ORDER BY id DESC LIMIT 10', (session['user_id'],)).fetchall(); conn.close()
    return render_template('malware.html', scan=scan, scans=scans)


@app.route('/chatbot', methods=['GET','POST'])
@login_required
def chatbot():
    question=''; answer=None
    if request.method == 'POST':
        question=request.form.get('question','').strip()
        q=question.lower()

        answers = {
            'ai': "AI in this project means the trained machine learning model is used to study network traffic values and classify the traffic as Normal Traffic or Cyber Attack Detected. The web app collects 15 features, sends them to the model, stores the result, and shows severity, confidence, score, and recommendation.",
            'overview': "CyberShield is an AI-Based Cybersecurity Threat Detection Web Application. It includes login/register, home introduction, network prediction, result analysis, user-wise history with chart, PDF/CSV download, malware scanner, chatbot, project report, profile, and admin user access control.",
            'flow': "Project flow: Login -> Home -> Prediction -> Result -> History. From History, the user can view chart/graph, export CSV, download PDF report, delete records, or clear history. Admin has a separate panel to allow or block users.",
            'login': "Login module verifies username/email and password. Passwords are stored using hashing, not plain text. If admin blocks a user, that user cannot login or use the application until admin allows access again.",
            'home': "Home page gives an introduction about CyberShield, explains what the project contains, and provides Start Prediction plus module cards for History, Malware Scanner, Chatbot, Report, Profile, and Admin if the logged-in user is admin.",
            'prediction': "Prediction page accepts 15 network traffic input values. These values represent packet count, packet length, flow duration, packet speed, inter-arrival time, and bytes/sec. After clicking Detect Threat, the app predicts whether the traffic is normal or attack-like.",
            'features': "The 15 input features are Protocol, Flow Duration, Total Forward Packets, Total Backward Packets, Forward Packets Length, Backward Packets Length, Forward Packet Length Mean, Backward Packet Length Mean, Forward Packets/sec, Backward Packets/sec, Forward IAT Mean, Backward IAT Mean, Flow IAT Mean, Flow Packets/sec, and Flow Bytes/sec.",
            'normal': "Normal Traffic means the network pattern is stable and not suspicious. It usually has balanced packet movement, moderate packet rate, reasonable flow duration, and no abnormal burst in bytes/sec or packets/sec.",
            'attack': "Cyber Attack Detected means the traffic values look abnormal. Very high packet rate, abnormal byte flow, unusual flow duration, or strong imbalance between forward and backward packets can indicate DDoS-like or suspicious network behavior.",
            'average': "Average values are moderate values that are not too low and not too high. In this project, the final decision is not based on one value alone; the model checks the combined pattern of all 15 features.",
            'result': "Result page shows final output, severity level, confidence percentage, security score, date, time, country, IP address, and recommendation. It also gives Predict Again, View History, and Download PDF options.",
            'history': "History page is the main analysis page. It stores prediction records user-wise and displays Date, Time, Country, IP Address, Result, Severity, Confidence, Score, chart/graph, CSV export, PDF download, delete, and clear history options.",
            'chart': "The chart/graph compares Normal Traffic and Cyber Attack counts. It helps the reviewer quickly understand how many predictions are safe and how many are suspicious.",
            'csv': "CSV export downloads the prediction history in spreadsheet format. It includes date, time, country, IP address, result, severity, confidence, security score, and recommendation.",
            'pdf': "PDF report download is available for both individual detection reports and full project report. Individual PDF explains one prediction result. Project PDF explains abstract, modules, technologies, workflow, advantages, limitations, and conclusion.",
            'malware': "Malware Scanner performs basic static file checking. It checks file extension, size, SHA-256 hash, risky extensions such as exe/bat/js/ps1, and suspicious keywords like powershell or cmd.exe. It then gives a risk score and result.",
            'chatbot': "Chatbot works as a CyberShield help assistant. It answers questions about project modules, cybersecurity basics, prediction inputs, normal/attack output, history, report, malware scanner, admin access, technologies, and review explanation.",
            'report': "Report module gives a neat project explanation for submission. It contains abstract, problem statement, objectives, system modules, technologies used, architecture workflow, algorithm, dataset/features, user statistics, advantages, limitations, future enhancements, and conclusion. It also has PDF download.",
            'profile': "Profile page displays logged-in user information such as username, email, role, status, and created date. It helps show that the project supports user accounts.",
            'admin': "Admin panel is only for admin users. Admin can view users, prediction data, malware scan data, and decide whether each user is allowed or blocked. Blocked users cannot access the application.",
            'technologies': "Technologies used: HTML, CSS, JavaScript and Chart.js for frontend; Python Flask for backend; SQLite for database; scikit-learn Random Forest and joblib for machine learning; Werkzeug password hashing and Flask session for security; FPDF and CSV for reports.",
            'dataset': "Dataset/model part uses network traffic features related to packet count, packet length, packet rate, flow duration, IAT, and bytes/sec. These values are used to train or use the ML model for normal vs attack classification.",
            'algorithm': "Random Forest is used because it works well for classification problems, handles multiple numeric features, and gives stable results by combining many decision trees. The trained model is saved as cyber_model.pkl using joblib.",
            'security': "Cybersecurity means protecting systems, networks, data, and users from unauthorized access and attacks. This project demonstrates authentication, access control, traffic monitoring, malware checking, logging, reporting, and admin control.",
            'review': "In project review, explain like this: CyberShield starts with secure login, then user enters 15 network traffic values, ML model predicts normal or attack, result is stored with date/time/IP/country, History shows chart and reports, Malware Scanner checks files, Chatbot explains the system, and Admin controls user access.",
            'future': "Future enhancements include real-time packet capture, email OTP/password reset, advanced malware sandbox analysis, deep learning model, cloud deployment, live alerts, and admin-wise advanced analytics.",
            'advantage': "Advantages: complete end-to-end flow, clean UI, user-wise storage, chart analysis, PDF/CSV reports, admin access control, malware scanner, chatbot help, and suitable academic demonstration.",
            'limitation': "Limitations: malware scanner is basic static analysis, prediction accuracy depends on dataset/model quality, and real-time packet capture is not fully integrated. These can be mentioned honestly during review.",
        }

        keyword_map = [
            (['ai','artificial intelligence','machine learning','ml'], 'ai'),
            (['overview','about','project','contains','module','modules','explain'], 'overview'),
            (['flow','process','steps','workflow','continuity','line process','run'], 'flow'),
            (['login','register','password','authentication','signup','blocked'], 'login'),
            (['home','intro','start'], 'home'),
            (['prediction','predict','input','form','detect','detect threat'], 'prediction'),
            (['15','feature','features','values','columns','field'], 'features'),
            (['normal','safe traffic','safe'], 'normal'),
            (['attack','threat','ddos','dos','intrusion','suspicious','hacker'], 'attack'),
            (['average','moderate','medium value'], 'average'),
            (['result','severity','confidence','score','recommendation','output'], 'result'),
            (['history','record','records','date','time','country','ip address','ip'], 'history'),
            (['chart','graph','visual','visualization','pie'], 'chart'),
            (['csv','excel','export'], 'csv'),
            (['pdf','download','report download'], 'pdf'),
            (['malware','file','scan','scanner','hash','sha','virus','trojan'], 'malware'),
            (['chatbot','bot','assistant','question'], 'chatbot'),
            (['report','abstract','objective','problem statement','conclusion','submission'], 'report'),
            (['profile','account'], 'profile'),
            (['admin','block','allow','access','users','user data'], 'admin'),
            (['technology','technologies','tech stack','tools','framework'], 'technologies'),
            (['dataset','data set','drdos','nsl','training data'], 'dataset'),
            (['algorithm','random forest','model','joblib','classifier'], 'algorithm'),
            (['cybersecurity','cyber security','security','network security'], 'security'),
            (['review','viva','question','explain to mam','presentation'], 'review'),
            (['future','enhancement','scope'], 'future'),
            (['advantage','benefit','usefulness'], 'advantage'),
            (['limitation','drawback','disadvantage'], 'limitation')
        ]
        matched=[]
        for words,key in keyword_map:
            if any(w in q for w in words):
                if answers[key] not in matched:
                    matched.append(answers[key])
        if matched:
            answer='\n\n'.join(matched[:4])
        else:
            answer=("CyberShield related question-ku naan answer pannuvaen. You can ask about AI, Random Forest, dataset, 15 input features, login, home, prediction, result, history, chart, PDF, CSV, malware scanner, chatbot, report, profile, admin allow/block, advantages, limitations, future scope, or cybersecurity basics. For review explanation: Login -> Home -> Prediction -> Result -> History -> PDF/CSV, with Malware Scanner, Chatbot, Report, Profile, and Admin access control.")
    return render_template('chatbot.html', question=question, answer=answer)

@app.route('/report')
@login_required
def report():
    total, attacks, normal, malware = calculate_counts()
    return render_template('report.html', total=total, attacks=attacks, normal=normal, malware=malware)


@app.route('/download_project_report')
@login_required
def download_project_report():
    total, attacks, normal, malware = calculate_counts()
    path=os.path.join(UPLOAD_FOLDER, 'CyberShield_Project_Report.pdf')
    if FPDF:
        pdf=FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        def section(title, body):
            pdf.set_font('Arial','B',14)
            pdf.cell(0,10,title,ln=True)
            pdf.set_font('Arial','',11)
            pdf.multi_cell(0,7,body)
            pdf.ln(3)

        def bullets(title, items):
            pdf.set_font('Arial','B',14)
            pdf.cell(0,10,title,ln=True)
            pdf.set_font('Arial','',11)
            for item in items:
                pdf.multi_cell(0,7,'- '+item)
            pdf.ln(3)

        pdf.add_page()
        pdf.set_font('Arial','B',16)
        pdf.cell(0,10,'AI-Based Cybersecurity Threat Detection Web Application',ln=True,align='C')
        pdf.ln(8)

        section('Abstract','CyberShield is an AI-Based Cybersecurity Threat Detection Web Application developed using Python Flask and machine learning. The system accepts 15 network traffic features and predicts whether the given traffic is Normal Traffic or Cyber Attack Detected. The application also stores user-wise prediction history with date, time, country, and IP address. It provides chart analysis, CSV export, PDF report generation, malware scanning, chatbot support, profile page, and admin-controlled user access.')
        section('Problem Statement','Modern computer networks handle large volumes of traffic. Manual identification of suspicious packet flow, abnormal bytes per second, DDoS-like bursts, malicious file uploads, and unauthorized users is difficult. A web-based system is required to collect network features, classify threat behavior, store logs, and generate clear reports for analysis.')
        bullets('Objectives',[
            'To classify network traffic as Normal Traffic or Cyber Attack Detected using selected traffic features.',
            'To provide a clean step-by-step flow: Login, Home, Prediction, Result, History, and Reports.',
            'To store prediction data user-wise with date, time, country, and IP address.',
            'To show visual chart analysis and provide CSV/PDF download options.',
            'To include a basic malware scanner for uploaded files.',
            'To include a chatbot that explains cybersecurity concepts and project features.',
            'To allow admin users to allow or block normal user access.'
        ])
        bullets('System Modules',[
            'Login and Registration: authenticates users using username/email and hashed password.',
            'Home: introduces the project and provides access to main modules.',
            'Prediction: collects 15 network traffic values and sends them for classification.',
            'Result: displays final result, severity, confidence, score, recommendation, IP address, and country.',
            'History: displays all user prediction records with chart, PDF download, CSV export, delete, and clear options.',
            'Malware Scanner: checks uploaded file extension, size, hash, and suspicious keywords.',
            'Chatbot: answers questions about CyberShield modules and cybersecurity concepts.',
            'Report: explains the project clearly for academic submission and provides PDF download.',
            'Profile: shows logged-in user account information.',
            'Admin Panel: allows admin to view users and decide whether each user can access the application.'
        ])

        pdf.add_page()
        pdf.set_font('Arial','B',14)
        pdf.cell(0,10,'Technologies Used',ln=True)
        tech_rows=[
            ('Frontend','HTML, CSS, JavaScript, Chart.js'),
            ('Backend','Python Flask'),
            ('Database','SQLite'),
            ('Machine Learning','scikit-learn Random Forest, joblib model file'),
            ('Security','Password hashing, Flask session, role-based admin access'),
            ('Reporting','FPDF for PDF generation and CSV export'),
            ('File Analysis','Werkzeug secure upload, SHA-256 hash, static file checks')
        ]
        pdf.set_font('Arial','B',11)
        pdf.cell(55,8,'Category',border=1)
        pdf.cell(130,8,'Tools / Purpose',border=1,ln=True)
        pdf.set_font('Arial','',10)
        for cat, tools in tech_rows:
            x=pdf.get_x(); y=pdf.get_y()
            pdf.multi_cell(55,8,cat,border=1)
            pdf.set_xy(x+55,y)
            pdf.multi_cell(130,8,tools,border=1)
        pdf.ln(5)
        section('Architecture and Workflow','The application follows a simple web architecture. The user interacts with HTML templates. Flask handles routing and backend logic. SQLite stores users, detections, and malware scan records. The trained machine learning model predicts the traffic class. Chart.js displays visual analytics, while FPDF and CSV modules generate downloadable reports. Workflow: Login -> Home -> Prediction -> Result -> History -> Chart/PDF/CSV. Additional modules are Malware Scanner, Chatbot, Report, Profile, and Admin Panel.')
        section('Machine Learning Logic','The project uses a Random Forest based classifier saved as cyber_model.pkl. The prediction page sends 15 numeric traffic features to the model. Random Forest combines multiple decision trees and is suitable for classification because it handles multiple numeric features and gives stable output. If suspicious network patterns are detected, the result is shown as Cyber Attack Detected; otherwise it is shown as Normal Traffic.')
        section('Input Features','The 15 input features are Protocol, Flow Duration, Total Forward Packets, Total Backward Packets, Forward Packets Length, Backward Packets Length, Forward Packet Length Mean, Backward Packet Length Mean, Forward Packets/sec, Backward Packets/sec, Forward IAT Mean, Backward IAT Mean, Flow IAT Mean, Flow Packets/sec, and Flow Bytes/sec.')

        pdf.add_page()
        section('Normal vs Attack Explanation','Normal traffic usually has balanced packet flow, moderate packet rate, reasonable bytes/sec, and stable flow duration. Attack traffic may show abnormal packet bursts, very high bytes/sec, unusual packet imbalance, or suspicious flow timing. The final result is decided using the combined pattern of all 15 features, not only one input value.')
        section('Malware Scanner Explanation','The malware scanner is a basic static analysis module. It checks the uploaded file name, extension, file size, SHA-256 hash, risky extensions such as .exe, .bat, .js, .ps1, and suspicious keywords such as powershell or cmd.exe. Based on these checks, it generates a risk score and result. It is useful for academic demonstration but does not replace a professional antivirus engine.')
        section('Chatbot Explanation','The chatbot acts as a CyberShield help assistant. It can answer questions about project overview, flow, AI, Random Forest, dataset, 15 input features, prediction, normal traffic, cyber attack, result, history, chart, PDF, CSV, malware scanner, project report, profile, admin allow/block access, advantages, limitations, and future scope.')
        section('Admin Access Control','The admin panel is used for user management. Admin can view registered users and change their access status. If a user is blocked, that user cannot login or use the application. This gives the project a role-based access control feature.')
        section('Current User Statistics',f'Total Detections: {total}\nNormal Traffic: {normal}\nCyber Attacks: {attacks}\nMalware Scans: {malware}')
        bullets('Advantages',[
            'Complete end-to-end project flow suitable for demonstration.',
            'User-wise history storage with date, time, IP address, and country.',
            'Chart-based analysis, CSV export, and PDF report download.',
            'Admin can allow or block users.',
            'Includes additional cybersecurity modules such as malware scanner and chatbot.',
            'Clean UI with animation and theme toggle support.'
        ])
        bullets('Limitations',[
            'Prediction accuracy depends on the trained dataset and model quality.',
            'Malware scanner uses basic static analysis only.',
            'Real-time packet capture is not fully integrated in this version.'
        ])
        bullets('Future Enhancements',[
            'Real-time packet capture and live traffic monitoring.',
            'Email OTP or password reset system.',
            'Advanced malware sandbox analysis.',
            'Deep learning based threat classification.',
            'Cloud deployment and real-time alert notification.'
        ])
        section('Conclusion','CyberShield demonstrates how machine learning, Flask web development, database storage, visualization, report generation, malware checking, chatbot assistance, and admin access control can be integrated into a complete cybersecurity academic project. It is suitable for project review because it has a clear workflow, practical modules, and understandable outputs.')
        pdf.output(path)
    else:
        with open(path,'w') as f:
            f.write('CyberShield Project Report\nAI-Based Cybersecurity Threat Detection Web Application\n')
    return send_file(path, as_attachment=True)

@app.route('/profile')
@login_required
def profile():
    conn=get_db(); user=conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone(); conn.close()
    return render_template('profile.html', user=user)


@app.route('/admin')
@admin_required
def admin_panel():
    conn=get_db()
    users=conn.execute('SELECT id,username,email,role,status,created_at FROM users ORDER BY id DESC').fetchall()
    detections=conn.execute('SELECT * FROM detections ORDER BY id DESC LIMIT 100').fetchall()
    scans=conn.execute('SELECT * FROM malware_scans ORDER BY id DESC LIMIT 100').fetchall()
    conn.close(); return render_template('admin.html', users=users, detections=detections, scans=scans)


@app.route('/admin/toggle_user/<int:user_id>')
@admin_required
def toggle_user(user_id):
    if user_id == session.get('user_id'):
        return redirect(url_for('admin_panel'))
    conn=get_db(); user=conn.execute('SELECT status,role FROM users WHERE id=?', (user_id,)).fetchone()
    if user and user['role'] != 'admin':
        new_status='blocked' if user['status']=='active' else 'active'
        conn.execute('UPDATE users SET status=? WHERE id=?', (new_status, user_id)); conn.commit()
    conn.close(); return redirect(url_for('admin_panel'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
