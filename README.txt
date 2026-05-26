CyberShield - Final Clean Submit Ready Version

PROCESS FLOW:
Login -> Home -> Start Prediction -> Prediction Page -> Result Page -> History Page

History page contains:
- Normal vs Attack counts
- Graph / chart
- Detection history table
- Date, time, country, IP address
- PDF download per record
- CSV download for full history

Dashboard page removed because History already contains dashboard output.

ADMIN FEATURES:
- Admin login: admin / admin123
- Admin can view registered users
- Admin can allow or block normal users
- Blocked user cannot login/use application
- Admin can view all detection records and malware scans

USER FEATURES:
- User can login/register
- User can use prediction, result, history, malware scanner, chatbot, report and profile
- User can view only own history data

TEMPLATES USED ONLY:
1. base.html - common layout and navigation
2. login.html - user/admin login
3. register.html - new user registration
4. index.html - home page
5. predict.html - 15 feature input page
6. result.html - prediction output page
7. history.html - chart, graph, history, PDF, CSV
8. malware.html - file malware scanner
9. chatbot.html - help assistant
10. report.html - project report content
11. profile.html - logged in user details
12. admin.html - admin access control and all records

REMOVED:
- dashboard.html / dashboard route, because it duplicated history page.

RUN STEPS:
1. Open project folder in VS Code
2. Open terminal
3. pip install -r requirements.txt
4. python app.py
5. Open http://127.0.0.1:5000/

NOTES:
- SQLite database is created automatically as cybershield.db
- cyber_model.pkl is used if available
- If model has any issue, fallback logic still gives result
