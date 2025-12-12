import os
import json
import time
import random
from datetime import datetime
from dotenv import load_dotenv
import sys 

from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_mail import Mail
from redis import Redis
from rq import Queue
from weasyprint import HTML, CSS
from sqlalchemy.exc import OperationalError

# --- Environment and App Setup ---
load_dotenv()
app = Flask(__name__)

# --- Configuration (Railway Integration) ---
DB_URL = os.getenv("DATABASE_URL")
if DB_URL and DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL or 'sqlite:///site.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')

# Safely handle MAIL_PORT integer conversion (Critical fix for environmental crash)
try:
    port_val = os.getenv('MAIL_PORT')
    app.config['MAIL_PORT'] = int(port_val) if port_val else 587
except ValueError:
    app.config['MAIL_PORT'] = 587
    print("Warning: MAIL_PORT environment variable is invalid. Defaulting to 587.")

app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# --- Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Redis/RQ Setup (Railway Integration) ---
try:
    # CRITICAL: Redis connection is wrapped in a safe check
    redis_conn = Redis.from_url(os.getenv('REDIS_URL') or 'redis://localhost:6379')
    redis_conn.ping() 
    task_queue = Queue(connection=redis_conn)
    print("Redis Queue initialized successfully.")
except Exception as e:
    print(f"Warning: Could not connect to Redis/initialize Queue: {e}")
    task_queue = None

# --- MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    scheduled_website = db.Column(db.String(255))
    scheduled_email = db.Column(db.String(120))
    reports = db.relationship('AuditReport', backref='auditor', lazy=True) 

class AuditReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_url = db.Column(db.String(255), nullable=False)
    date_audited = db.Column(db.DateTime, default=datetime.utcnow)
    metrics_json = db.Column(db.Text, nullable=False)
    performance_score = db.Column(db.Integer, default=0)
    security_score = db.Column(db.Integer, default=0)
    accessibility_score = db.Column(db.Integer, default=0)
    # These columns are not used by the existing database schema but are kept for completeness
    tech_seo_score = db.Column(db.Integer, default=0) 
    ux_score = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- AUDIT ENGINE with 10 CATEGORIES (Total 50 Metrics) ---
class AuditService:
    METRICS = {
        "1. Technical SEO Audit (7 checks)": ["Crawlability (robots.txt, sitemap)", "Indexability (noindex, canonicals)", "Broken Links Status", "Redirect Chains/Loops", "URL Structure Optimization", "Orphan Pages Check", "Crawl Errors (4xx/5xx)"],
        "2. Performance & Core Web Vitals (8 checks)": ["Largest Contentful Paint (LCP)", "Interaction to Next Paint (INP)", "Cumulative Layout Shift (CLS)", "Server Response Time (TTFB)", "Image Optimization Status", "CSS/JS Minification Status", "Browser Caching Policy", "Mobile Page Speed"],
        "3. On-Page SEO Audit (6 checks)": ["Unique Title Tags", "Unique Meta Descriptions", "H1/H2 Structure", "Content Keyword Relevance", "Image ALT Text Coverage", "Structured Data Markup"],
        "4. User Experience (UX) Audit (5 checks)": ["Navigation Usability (Menus)", "Readability Score", "Mobile Responsiveness (Viewport)", "Call-to-Action (CTA) Clarity", "Visual Consistency"],
        "5. Website Security Audit (6 checks)": ["HTTPS & SSL Certificate Validity", "HSTS Header Implementation", "Content Security Policy (CSP)", "Server Patch Level", "Dependency Security (OWASP)", "Malware/Vulnerability Check"],
        "6. Accessibility Audit (WCAG Standards) (5 checks)": ["Color Contrast Ratio", "Keyboard Navigation Compliance", "Screen Reader Compatibility", "ARIA Labels Presence", "Semantic HTML Structure"],
        "7. Content Audit (4 checks)": ["Content Uniqueness and Depth", "Relevance to User Intent", "Outdated Content Identification", "Content Gaps Identified"],
        "8. Off-Page SEO & Backlinks (4 checks)": ["Backlink Profile Quality Score", "Toxic Link Detection", "Local SEO Signals (NAP)", "Brand Mentions/Review Activity"],
        "9. Analytics & Tracking Audit (3 checks)": ["GA4/Analytics Setup Verification", "Goals and Events Tracking", "Tag Manager Configuration"],
        "10. E-Commerce Audit (Optional) (2 checks)": ["Product Page Optimization", "Checkout Flow Usability"]
    }

    @staticmethod
    def run_audit(url):
        time.sleep(2) # Simulate audit time
        detailed = {}
        all_metrics = [metric for sublist in AuditService.METRICS.values() for metric in sublist]
        for item in all_metrics:
            if any(k in item.lower() for k in ["lcp", "inp", "cls", "ttfb", "speed", "load"]):
                detailed[item] = f"{random.uniform(0.8, 4.5):.2f}s"
            else:
                detailed[item] = random.choices(["Excellent", "Good", "Fair", "Poor"], weights=[40, 30, 20, 10], k=1)[0]
        return { 'metrics': detailed }

    @staticmethod
    def calculate_score(metrics):
        scores = {'performance': 0, 'security': 0, 'accessibility': 0, 'tech_seo': 0, 'ux': 0}
        category_score_map = {"1. Technical SEO Audit (7 checks)": "tech_seo", "2. Performance & Core Web Vitals (8 checks)": "performance", "3. On-Page SEO Audit (6 checks)": "tech_seo", "4. User Experience (UX) Audit (5 checks)": "ux", "5. Website Security Audit (6 checks)": "security", "6. Accessibility Audit (WCAG Standards) (5 checks)": "accessibility", "7. Content Audit (4 checks)": "ux", "8. Off-Page SEO & Backlinks (4 checks)": "tech_seo", "9. Analytics & Tracking Audit (3 checks)": "tech_seo", "10. E-Commerce Audit (Optional) (2 checks)": "ux"}
        total_counts = {'performance': 0, 'security': 0, 'accessibility': 0, 'tech_seo': 0, 'ux': 0}
        positive_counts = {'performance': 0, 'security': 0, 'accessibility': 0, 'tech_seo': 0, 'ux': 0}

        for category, items in AuditService.METRICS.items():
            score_key = category_score_map.get(category)
            if score_key:
                total_counts[score_key] += len(items)
                for metric_name in items:
                    result = metrics.get(metric_name)
                    if result in ["Excellent", "Good"]:
                        positive_counts[score_key] += 1
        
        for key in scores.keys():
            if total_counts[key] > 0:
                scores[key] = round((positive_counts[key] / total_counts[key]) * 100)
        
        final_scores = {'performance': scores['performance'], 'security': scores['security'], 'accessibility': scores['accessibility'], 'metrics': metrics, 'all_scores': scores}
        return final_scores

# NOTE: Since the Procfile is single-line, we safely handle missing worker imports
send_report_email = None
run_scheduled_report = None


# --- Admin User Creation ---
def create_admin_user():
    with app.app_context():
        # NOTE: db.create_all() is handled by initialize_db_with_retries
        email = os.getenv('ADMIN_EMAIL', 'roy.jamshaid@gmail.com')
        password = os.getenv('ADMIN_PASSWORD', 'Jamshaid,1981')
        if not User.query.filter_by(email=email).first():
            hashed = bcrypt.generate_password_hash(password).decode('utf-8')
            admin = User(email=email, password=hashed, is_admin=True)
            db.session.add(admin)
            db.session.commit()

# CRITICAL FIX 2: Safely initialize database with retries on startup
def initialize_db_with_retries(retries=5, delay=5):
    with app.app_context():
        for i in range(retries):
            try:
                # Attempt to execute a basic query before creating tables to ensure connection is open
                db.session.execute(db.text('SELECT 1')) 
                db.create_all()
                print("Database initialized successfully.")
                return True
            except OperationalError as e:
                print(f"Database connection attempt {i+1} failed: {e}")
                if i < retries - 1:
                    print(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    print("Failed to initialize database after multiple retries. This is a FATAL error.")
                    return False
            except Exception as e:
                # Catch other potential errors (like schema errors)
                print(f"Fatal error during DB initialization: {e}")
                return False
        return False
        
# --- Routes (Routes below are unchanged, but function names are simplified) ---

@app.route('/')
def home():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    reports = AuditReport.query.filter_by(user_id=current_user.id).order_by(AuditReport.date_audited.desc()).limit(10).all()
    return render_template('dashboard.html', reports=reports)

@app.route('/run_audit', methods=['POST'])
@login_required
def run_audit():
    url = request.form.get('website_url', '').strip()
    email_recipient = request.form.get('email_recipient') 
    
    if not url.startswith(('http://', 'https://')):
        flash('Valid URL required', 'danger')
        return redirect(url_for('dashboard'))
    
    # 1. Run Audit
    result = AuditService.run_audit(url)
    scores_data = AuditService.calculate_score(result['metrics']) 
    
    # 3. Save Report
    report = AuditReport(
        website_url=url,
        performance_score=scores_data['performance'],
        security_score=scores_data['security'],
        accessibility_score=scores_data['accessibility'],
        metrics_json=json.dumps(scores_data['metrics']),
        user_id=current_user.id
    )
    db.session.add(report)
    db.session.commit()
    
    flash('Audit completed!', 'success')
    
    # 4. Worker is disabled
    if email_recipient:
        flash(f'Report saved, but email automation is disabled.', 'warning')
    
    return redirect(url_for('view_report', report_id=report.id))


@app.route('/report/<int:report_id>')
@login_required
def view_report(report_id):
    report = AuditReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    metrics_data = json.loads(report.metrics_json)
    scores_data = AuditService.calculate_score(metrics_data)
    scores_full = scores_data['all_scores']
    metrics_by_cat = {cat: {k: metrics_data.get(k, 'N/A') for k in items} 
                      for cat, items in AuditService.METRICS.items()}
    
    return render_template('report_detail.html', report=report, metrics=metrics_by_cat, scores=scores_full)

@app.route('/report/pdf/<int:report_id>')
@login_required
def report_pdf(report_id):
    report = AuditReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    metrics_data = json.loads(report.metrics_json)
    scores_data = AuditService.calculate_score(metrics_data)
    scores_full = scores_data['all_scores']
    metrics_by_cat = {cat: {k: metrics_data.get(k, 'N/A') for k in items} 
                      for cat, items in AuditService.METRICS.items()}
    
    def generate_pdf_content(report, metrics, scores):
        return render_template('report_pdf.html', report=report, metrics=metrics, scores=scores)
    
    html = generate_pdf_content(report, metrics_by_cat, scores_full)
    
    try:
        pdf = HTML(string=html).write_pdf(stylesheets=[CSS(string='@page { size: A4; margin: 2cm } body { font-family: sans-serif; }')])
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'inline; filename=report_{report.id}.pdf'
        return response
    except Exception as e:
        print(f"PDF GENERATION ERROR: {e}") 
        flash('PDF generation failed. This requires Pango/Cairo system libraries (check Dockerfile).', 'danger')
        return redirect(url_for('view_report', report_id=report_id))

@app.route('/schedule', methods=['POST'])
@login_required
def schedule_report():
    url = request.form.get('scheduled_website')
    email = request.form.get('scheduled_email')
    
    if not url or not url.startswith(('http://', 'https://')):
        flash('Invalid URL', 'danger')
        return redirect(url_for('dashboard'))
        
    current_user.scheduled_website = url
    current_user.scheduled_email = email
    db.session.commit()
    
    flash('Schedule saved. Email automation is currently disabled for stability.', 'warning')
    
    return redirect(url_for('dashboard'))

@app.route('/unschedule', methods=['POST'])
@login_required
def unschedule_report():
    current_user.scheduled_website = None
    current_user.scheduled_email = None
    db.session.commit()
    flash('Schedule cancelled', 'info')
    return redirect(url_for('dashboard'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Admin access required.', 'danger')
        return redirect(url_for('dashboard'))
    
    all_users = User.query.all()
    latest_reports = AuditReport.query.order_by(AuditReport.date_audited.desc()).limit(50).all()
    
    return render_template(
        'admin_dashboard.html', 
        users=all_users, 
        reports=latest_reports,
        title="Admin Panel"
    )

@app.route('/admin/create_user', methods=['POST'])
@login_required
def admin_create_user():
    if not current_user.is_admin:
        flash('Admin access required to create users.', 'danger')
        return redirect(url_for('dashboard'))
    
    email = request.form.get('new_user_email')
    password = request.form.get('new_user_password')
    is_admin_flag = request.form.get('is_admin_flag') == 'on' 
    
    if User.query.filter_by(email=email).first():
        flash(f'User with email {email} already exists.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    if email and password and len(password) >= 6: 
        try:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(email=email, password=hashed_password, is_admin=is_admin_flag)
            db.session.add(new_user)
            db.session.commit()
            flash(f'User {email} created successfully. Admin status: {is_admin_flag}', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {e}', 'danger')
    else:
        flash('Invalid email or password (must be at least 6 characters).', 'danger')
    
    return redirect(url_for('admin_dashboard'))


# --- Application Startup ---
# CRITICAL: Run database initialization before the application starts
if initialize_db_with_retries():
    create_admin_user()

if __name__ == '__main__':
    app.run(debug=True)
