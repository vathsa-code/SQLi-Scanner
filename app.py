from flask import Flask, render_template, request, send_file, redirect, url_for, session, make_response
from scanner import scan_sql_injection
import os
import json
import pdfkit
from pdfkit.configuration import Configuration  # ✅ Needed for manual wkhtmltopdf path

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url').strip()
        mode = request.form.get('mode', 'basic')
        logs, report_file = scan_sql_injection(url, mode)
        session['logs'] = logs
        session['report_file'] = report_file
        return redirect(url_for('report'))
    return render_template('index.html')

@app.route('/report')
def report():
    logs = session.get('logs', [])
    filename = session.get('report_file', None)
    report_data = []

    if filename and os.path.exists(filename):
        with open(filename, "r") as f:
            report_data = json.load(f)

    return render_template('report.html', logs=logs, report=report_data)

@app.route('/download/<filename>')
def download_report(filename):
    try:
        return send_file(filename, as_attachment=True)
    except:
        return "File not found."

@app.route('/export_pdf')
def export_pdf():
    logs = session.get('logs', [])
    filename = session.get('report_file', None)
    report_data = []

    if filename and os.path.exists(filename):
        with open(filename, "r") as f:
            report_data = json.load(f)

    path_wkhtmltopdf = r'C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe'
    config = Configuration(wkhtmltopdf=path_wkhtmltopdf)

    rendered = render_template("report_pdf.html", logs=logs, report=report_data)
    pdf = pdfkit.from_string(rendered, False, configuration=config)

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=scan_report.pdf'
    return response

if __name__ == '__main__':
    app.run(debug=True)
