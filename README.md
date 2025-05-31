
# Snippet Scanner

**Snippet Scanner** is a web-based tool that scans code snippets and URLs for security vulnerabilities based on the [OWASP Top 10](https://owasp.org/www-project-top-ten/) guidelines. It helps developers identify and fix critical security issues in their code with AI-powered analysis and real-time scanning.

🌐 Live Website: [https://snippet-scanner.pages.dev](https://snippet-scanner.pages.dev)

---

## Features

- **AI-Powered Vulnerability Detection**
- **Scan Code Snippets or URLs**
- **Severity Classification**
- 🛡**Covers OWASP Top Vulnerabilities**

---

## ⚙️ How to Set Up the Project

###  Backend (Flask)

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/snippet-scanner.git
   cd snippet-scanner
   ```

2. **Set up a virtual environment (recommended)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install the dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Flask app**
   ```bash
   python app.py
   ```
   This will start the backend server at `http://127.0.0.1:5050`.

> ✅ Make sure CORS is enabled for frontend integration.

---

## 🖥️ How to Run the Web App (Frontend)

The frontend is a static website built using **HTML, Tailwind CSS**, and vanilla **JavaScript**.

1. You can open the `index.html` directly in your browser **OR** deploy it using any static hosting provider like:
   - Cloudflare Pages (used here)
   - GitHub Pages
   - Netlify

2. Ensure the backend is running at the URL specified in the `fetch()` API inside the JS script (`app.py` runs at `http://127.0.0.1:5050` by default, or update to production backend URL).

---

## 📦 Dependencies

### Backend
- `Flask`
- `flask-cors`
- `re` (regex)
- `json`, `os`, etc. (standard Python libraries)

Install all Python dependencies using:
```bash
pip install -r requirements.txt
```

---

##  API Endpoints

### POST `/scan`

- Accepts JSON with either:
  ```json
  { "code_snippet": "<your_code_here>" }
  ```
  or
  ```json
  { "url": "https://yourwebsite.com" }
  ```

- Returns:
  ```json
  {
    "vulnerabilities": [
      {
        "issue": "XSS Detected",
        "severity": "High",
        "description": "...",
        "suggestion": "...",
        "line_number": 12,
        "owasp_category": "A7: Cross Site Scripting (XSS)"
      }
    ]
  }
  ```

---

developed by
Pitta shankumar
jessani radhika
kurva aishwarya
rani vamshika
