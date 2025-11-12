# Network Traffic Management System

A comprehensive network monitoring and traffic analysis system with real-time visualization and security alerts.

## 🚀 Features

- **Real-time Traffic Monitoring** - Live packet capture and analysis
- **Interactive Dashboard** - Charts and statistics with live updates
- **Security Alerts** - Automated threat detection and notifications
- **Network Topology** - Visual network map with device status
- **User Management** - Role-based access control
- **Reports & Analytics** - Comprehensive traffic and security reports
- **Responsive UI** - Modern React interface with dark theme

## 📋 Prerequisites

- **Python 3.8+** (for backend)
- **Node.js 16+** (for frontend)
- **npm** or **yarn** (package manager)

## 🛠️ Installation & Setup

### Backend Setup

1. Navigate to backend directory:
```bash
cd backend
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Start the backend server:
```bash
python run.py
```

The backend will be available at `http://localhost:5000`

### Frontend Setup

1. Navigate to frontend directory:
```bash
cd frontend
```

2. Install Node.js dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

The frontend will be available at `http://localhost:3000`

## 🎯 Usage

1. **Start Backend**: Run `python run.py` in the backend directory
2. **Start Frontend**: Run `npm start` in the frontend directory
3. **Access Application**: Open `http://localhost:3000` in your browser

## 📊 API Endpoints

- `GET /api/alerts` - Fetch security alerts
- `GET /api/traffic` - Get traffic data
- `GET /api/stats` - System statistics
- `GET /api/network-nodes` - Network topology
- `GET /api/users` - User management
- `GET /api/reports/*` - Various reports

## 🔧 Configuration

The system uses default configurations suitable for development. For production deployment, update:

- Backend host/port in `app.py`
- API base URL in `frontend/src/services/api.js`
- CORS settings for production domains

## 🎨 Tech Stack

**Backend:**
- Flask (Python web framework)
- Flask-CORS (Cross-origin requests)
- Threading (Background data generation)

**Frontend:**
- React 18 (UI framework)
- Recharts (Data visualization)
- Lucide React (Icons)
- Axios (HTTP client)

## 📝 License

This project is for educational and demonstration purposes.