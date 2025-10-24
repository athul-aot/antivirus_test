# Antivirus Test App - Setup

A full-stack antivirus scanning app with VirusTotal and Cloudmersive integration.

---

## Prerequisites

- Python 3.9+
- Node.js 18+
- Free API keys for both [VirusTotal](https://www.virustotal.com/gui/join-us) and [Cloudmersive](https://portal.cloudmersive.com/)

---

## 1. Get API Keys

- **VirusTotal**: https://www.virustotal.com/gui/join-us  
- **Cloudmersive**: https://portal.cloudmersive.com/

---

## 2. Backend Setup

```bash
git clone <your_repo_url>
cd antivirus_test/backend
python -m venv venv

# Activate venv
# Windows:
venv\Scripts\activate

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt

create .env file in root of backend folder and add env's

VIRUSTOTAL_API_KEY=your_virustotal_key_here
CLOUDMERSIVE_API_KEY=your_cloudmersive_key_here


Start the backend
uvicorn main:app --reload --port 8000


cd ../frontend
npm install
npm run dev

frontend runs on port 3000
