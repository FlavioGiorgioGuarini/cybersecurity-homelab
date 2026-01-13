# 🛡️ CSF SIEM 3D v2.0 - Cybersecurity Framework

**Production-Ready Security Information & Event Management (SIEM) with 3D Holographic Dashboard**

![Version](https://img.shields.io/badge/version-2.0-blue)
![Status](https://img.shields.io/badge/status-production--ready-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)

## 🚀 Features

### Backend (FastAPI + PostgreSQL)
- ✅ **15+ REST API endpoints** - Production-grade
- ✅ **Real PostgreSQL Database** - Persistent threat storage
- ✅ **SQLAlchemy ORM** - Type-safe models
- ✅ **CORS Enabled** - Cross-origin ready
- ✅ **Auto-threat Generation** - Simulated attacks
- ✅ **Real-time Statistics** - Live updates

### Frontend (Three.js + Chart.js)
- ✅ **3D Holographic Scene** - Particle animations
- ✅ **Real-time Dashboard** - Live threat intel
- ✅ **Interactive Charts** - Doughnut & Bar
- ✅ **Live Stat Cards** - Active Threats, Critical Level
- ✅ **Threat Table** - Real-time details
- ✅ **Auto-refresh** - 30-second sync
- ✅ **Cybersecurity Theme** - Dark mode + neon

## 📦 Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI + Uvicorn |
| Database | PostgreSQL + SQLAlchemy |
| Frontend | HTML5 + CSS3 + Vanilla JS |
| 3D | Three.js |
| Charts | Chart.js |
| Styling | Cybersecurity theme |

## 🏃 Quick Start

### Prerequisites
\`\`\`bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
\`\`\`

### Run Backend
\`\`\`bash
cd ~/projects/cybersecurity-homelab
uvicorn csf.api.main:app --reload --host 0.0.0.0 --port 8000
\`\`\`

### Run Frontend
\`\`\`bash
cd frontend
python3 -m http.server 3000
\`\`\`

### Access Dashboard
\`\`\`
http://localhost:3000
\`\`\`

## 📊 API Endpoints

\`\`\`
GET  /api/statistics/dashboard    - Dashboard metrics
GET  /api/threats                  - All threats
POST /api/threats                  - Create threat
GET  /api/threats/{id}             - Threat details
PUT  /api/threats/{id}             - Update threat
DELETE /api/threats/{id}           - Delete threat
\`\`\`

## 🎯 Project Structure

\`\`\`
cybersecurity-homelab/
├── frontend/
│   └── index.html               # 3D SIEM Dashboard
├── csf/
│   └── api/
│       ├── main.py              # FastAPI app
│       ├── models.py            # Database models
│       └── routes.py            # API endpoints
├── Dockerfile
├── requirements.txt
└── README.md
\`\`\`

## 🎯 Roadmap

- [x] FastAPI Backend
- [x] PostgreSQL Integration
- [x] 3D Dashboard UI
- [x] Real-time Charts
- [ ] Docker Compose
- [ ] Prometheus + Grafana
- [ ] Elasticsearch
- [ ] Yara Rules
- [ ] ML Anomaly Detection
- [ ] Slack/Discord Webhooks

## 🔒 Security Features

- ✅ CORS protection
- ✅ Input validation
- ✅ SQL injection prevention (SQLAlchemy)
- ✅ XSS protection
- ✅ Rate limiting ready
- ✅ Error handling

## 📝 Author

**Flavio Giorgio Guarini**
- 🔐 Cybersecurity Enthusiast
- 🎓 L20 Communication & Multimedia
- 🏆 TryHackMe & HackTheBox Active
- 📍 Bari, Puglia, Italy

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/flaviogiorgioguarini)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black)](https://github.com/FlavioGiorgioGuarini)

## 📄 License

MIT License - See LICENSE file for details

---

**Made with ❤️ for cybersecurity professionals**

Last Updated: January 13, 2026
