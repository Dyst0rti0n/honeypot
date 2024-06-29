from flask import Flask, render_template
import sqlite3
import matplotlib.pyplot as plt
from io import BytesIO
import base64

app = Flask(__name__)

def get_logs():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    c.execute("SELECT * FROM logs")
    logs = c.fetchall()
    conn.close()
    return logs

def generate_time_series_chart():
    conn = sqlite3.connect('honeypot.db')
    c = conn.cursor()
    c.execute("SELECT timestamp, COUNT(*) FROM logs GROUP BY timestamp")
    data = c.fetchall()
    conn.close()

    timestamps = [row[0] for row in data]
    counts = [row[1] for row in data]

    plt.figure(figsize=(10, 6))
    plt.plot(timestamps, counts, marker='o')
    plt.xticks(rotation=45)
    plt.xlabel('Timestamp')
    plt.ylabel('Number of Connections')
    plt.title('Connections Over Time')

    img = BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    chart = base64.b64encode(img.getvalue()).decode('utf8')
    return chart

@app.route('/')
def index():
    logs = get_logs()
    time_series_chart = generate_time_series_chart()
    return render_template('index.html', logs=logs, time_series_chart=time_series_chart)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
