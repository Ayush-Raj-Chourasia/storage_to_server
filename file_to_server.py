from flask import Flask, request, send_from_directory, render_template_string, abort, session, redirect
import os
from datetime import datetime
import hashlib
import secrets
from functools import wraps
import logging
import socket

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure logging
logging.basicConfig(
    filename='file_manager.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Server Configuration
HOST_NAME = socket.gethostname()
SERVER_IP = socket.gethostbyname(HOST_NAME)  # Gets the server's IP address
PORT = 5000
# Updated shared directories
SHARE_DIRS = {
    "C": "C:/",  # Path to C: drive
    "D": "D:/"   # Path to D: drive
}

# Security Configuration - Change these for production!
USERS = {
    "admin": hashlib.sha256("123450".encode()).hexdigest()
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session:
            return render_template_string(LOGIN_TEMPLATE)
        return f(*args, **kwargs)
    return decorated_function

def safe_join(base, *paths):
    """Enhanced path sanitization"""
    try:
        base = os.path.abspath(base)
        final_path = os.path.abspath(os.path.join(base, *paths))
        if not final_path.startswith(base):
            logging.warning(f"Attempted directory traversal: {paths}")
            abort(403)
        return final_path
    except Exception as e:
        logging.error(f"Path join error: {str(e)}")
        abort(400)

def get_file_info(full_path):
    """Get file information"""
    try:
        stat_info = os.stat(full_path)
        size = stat_info.st_size
        # Convert size to appropriate unit
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        size_index = 0
        while size > 1024 and size_index < len(units) - 1:
            size = size / 1024
            size_index += 1
        formatted_size = f"{size:.2f} {units[size_index]}"
        
        return {
            "name": os.path.basename(full_path),
            "is_dir": os.path.isdir(full_path),
            "size": formatted_size if not os.path.isdir(full_path) else "-",
            "modified": datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            "extension": os.path.splitext(full_path)[1][1:].lower() if not os.path.isdir(full_path) else ""
        }
    except Exception as e:
        logging.error(f"Error getting file info: {str(e)}")
        return None

# HTML Templates
LOGIN_TEMPLATE = """
<html>
<head>
    <title>Login - File Manager</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            width: 300px;
        }
        h1 { color: #333; margin-bottom: 1.5rem; text-align: center; }
        input {
            width: 100%;
            padding: 8px;
            margin: 8px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        <form method="post" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

MAIN_TEMPLATE = """
<html>
<head>
    <title>File Manager</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .breadcrumb {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .sort-controls {
            margin: 20px 0;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .sort-link {
            padding: 6px 12px;
            background: #f8f9fa;
            border-radius: 4px;
            color: #007bff;
            text-decoration: none;
            font-size: 14px;
        }
        .sort-link:hover {
            background: #e9ecef;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        tr:hover {
            background-color: #f8f9fa;
        }
        .logout-btn {
            padding: 8px 16px;
            background-color: #dc3545;
            color: white;
            border: none;
            border-radius: 4px;
            text-decoration: none;
            font-size: 14px;
        }
        .logout-btn:hover {
            background-color: #c82333;
        }
        .action-btn {
            padding: 6px 12px;
            background-color: #007bff;
            color: white;
            border-radius: 4px;
            text-decoration: none;
            font-size: 14px;
        }
        .action-btn:hover {
            background-color: #0056b3;
        }
        a { text-decoration: none; color: #007bff; }
        a:hover { text-decoration: underline; }
        .search-input {
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            width: 200px;
        }
        .search-btn {
            padding: 8px 16px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .search-btn:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ title }}</h1>
            <a href="/logout" class="logout-btn">Logout</a>
            <form action="/search" method="get">
                <input type="text" name="query" placeholder="Search files" class="search-input">
                <button type="submit" class="search-btn">Search</button>
            </form>
        </div>
        
        <div class="breadcrumb">
            {{ breadcrumb|safe }}
        </div>

        <div class="sort-controls">
            {% for sort_option in sort_options %}
            <a href="{{ sort_option.url }}" class="sort-link">{{ sort_option.label }}</a>
            {% endfor %}
        </div>

        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Last Modified</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {% for item in items %}
                <tr>
                    <td>
                        {% if item.is_dir %}
                        <a href="{{ item.browse_url }}">{{ item.name }}/</a>
                        {% else %}
                        {{ item.name }}
                        {% endif %}
                    </td>
                    <td>{{ item.size }}</td>
                    <td>{{ item.modified }}</td>
                    <td>
                        {% if item.is_dir %}
                        <a href="{{ item.browse_url }}" class="action-btn">Browse</a>
                        {% else %}
                        <a href="{{ item.download_url }}" class="action-btn">Download</a>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

@app.route('/login', methods=['POST'])
def login():
    """Handle login requests"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username in USERS and USERS[username] == hashlib.sha256(password.encode()).hexdigest():
        session['authenticated'] = True
        session['username'] = username
        logging.info(f"Successful login: {username}")
        return redirect('/')
    
    logging.warning(f"Failed login attempt: {username}")
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    """Handle logout requests"""
    session.clear()
    return redirect('/')

@app.route('/')
@login_required
def list_drives():
    """Display available drives"""
    drive_links = [
        f'<a href="/browse/{drive}/">{drive}:/</a>' for drive in SHARE_DIRS.keys()
    ]
    drive_list_html = '<br>'.join(drive_links)
    return f"""
    <html>
    <head>
        <title>Available Drives</title>
    </head>
    <body>
        <h1>Select a Drive</h1>
        {drive_list_html}
    </body>
    </html>
    """

@app.route('/browse/<drive>/<path:subpath>')
@app.route('/browse/<drive>/')
@login_required
def browse_drive(drive, subpath=""):
    """Browse specific drive"""
    if drive not in SHARE_DIRS:
        abort(404)  # Invalid drive
    base_path = SHARE_DIRS[drive]
    full_path = safe_join(base_path, subpath)
    return handle_directory_listing(full_path, f"{drive}/{subpath}")

def handle_directory_listing(directory_path, relative_path):
    """Common directory listing logic"""
    try:
        sort_by = request.args.get('sort_by', 'name')
        order = request.args.get('order', 'asc')
        
        items = []
        for item_name in os.listdir(directory_path):
            full_item_path = os.path.join(directory_path, item_name)
            item_info = get_file_info(full_item_path)
            if item_info:
                item_info['browse_url'] = f"/browse/{relative_path}/{item_name}"
                item_info['download_url'] = f"/download/{relative_path}/{item_name}"
                items.append(item_info)

        # Sorting
        reverse = order == 'desc'
        if sort_by == 'size':
            items.sort(key=lambda x: float(x['size'].split()[0]) if x['size'] != '-' else 0, reverse=reverse)
        else:
            items.sort(key=lambda x: x[sort_by], reverse=reverse)
        
        # Generate breadcrumb
        parts = relative_path.split(os.sep)
        breadcrumb = '<a href="/">Drives</a>'
        current_path = ''
        for part in parts:
            if part:
                current_path = os.path.join(current_path, part)
                breadcrumb += f' / <a href="/browse/{current_path}">{part}</a>'

        # Generate sort options
        sort_options = [
            {"url": f"?sort_by=name&order=asc", "label": "Name ↑"},
            {"url": f"?sort_by=name&order=desc", "label": "Name ↓"},
            {"url": f"?sort_by=size&order=desc", "label": "Size ↑"},
            {"url": f"?sort_by=size&order=asc", "label": "Size ↓"},
            {"url": f"?sort_by=modified&order=desc", "label": "Newest"},
            {"url": f"?sort_by=modified&order=asc", "label": "Oldest"}
        ]

        return render_template_string(
            MAIN_TEMPLATE,
            title=f"File Manager - {relative_path.split('/')[0]}",
            breadcrumb=breadcrumb,
            items=items,
            sort_options=sort_options
        )

    except Exception as e:
        logging.error(f"Error in directory listing: {str(e)}")
        return f"Error accessing directory: {str(e)}"

@app.route('/download/<path:filepath>')
@login_required
def download_file(filepath):
    """Handle file downloads"""
    try:
        full_path = safe_join(SHARE_DIRS['C'], filepath)
        logging.info(f"File download: {filepath} by {session.get('username')}")
        return send_from_directory(
            os.path.dirname(full_path),
            os.path.basename(full_path),
            as_attachment=True
        )
    except Exception as e:
        logging.error(f"Download error: {str(e)}")
        return f"Error downloading file: {str(e)}"

@app.route('/search', methods=['GET'])
@login_required
def search_files():
    query = request.args.get('query')
    if not query:
        return redirect('/')
    
    results = []
    for drive in SHARE_DIRS.values():
        for root, dirs, files in os.walk(drive):
            for file in files:
                if query.lower() in file.lower():
                    file_path = os.path.join(root, file)
                    file_info = get_file_info(file_path)
                    if file_info:
                        file_info['browse_url'] = f"/browse/{file_path}"
                        file_info['download_url'] = f"/download/{file_path}"
                        results.append(file_info)
    
    return render_template_string(
        MAIN_TEMPLATE,
        title="Search Results",
        breadcrumb="<a href='/'>Drives</a>",
        items=results,
        sort_options=[]
    )

if __name__ == '__main__':
    # Display server information
    print("\n=== File Manager Server ===")
    print(f"Server Hostname: {HOST_NAME}")
    print(f"Server IP: {SERVER_IP}")
    print(f"Port: {PORT}")
    print(f"\nAccess URLs:")
    print(f"Local: http://localhost:{PORT}")
    print(f"Network: http://{SERVER_IP}:{PORT}")
    print(f"\nDefault credentials:")
    print("Username: admin")
    print("Password: change_this_password")
    print("\nWarning: Change the default password before deployment!")
    print("\nPress CTRL+C to stop the server")
    
    # Run the server
    app.run(
        host='0.0.0.0',  # Makes the server accessible from any IP
        port=PORT,
        debug=False  # Disable debug mode for production
    )
