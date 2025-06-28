#  Health Check Application

A comprehensive Django-based health check system designed for organizations to monitor and assess team performance, project health, and departmental progress through a structured voting and reporting system.

##  Table of Contents

- [Features](#features)
- [User Roles](#user-roles)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Database Setup](#database-setup)
- [Usage Guide](#usage-guide)
- [Project Structure](#project-structure)
- [API Endpoints](#api-endpoints)

##  Features

###  Multi-Role Authentication System
- **Admin**: Full system management and oversight
- **Engineer**: Individual voting and progress tracking
- **Team Leader**: Team management and summary generation
- **Department Leader**: Department-wide monitoring and reporting
- **Senior Manager**: Organization-wide analytics and insights

###  Health Check System
- **Voting Mechanism**: Green/Amber/Red voting system (1-3 scale)
- **Progress Tracking**: Trend analysis and progress monitoring
- **Session Management**: Time-bound health check sessions
- **Real-time Analytics**: Interactive charts and visualizations

###  Reporting & Analytics
- **Individual Reports**: Personal voting history and performance
- **Team Reports**: Team-wide health assessments
- **Department Reports**: Department-level analytics
- **Organization Reports**: Company-wide health insights
- **Progress Summaries**: Automated summary generation

###  Modern UI/UX
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Bootstrap Framework**: Modern, clean interface
- **Interactive Charts**: Chart.js integration for data visualization
- **User-Friendly Navigation**: Intuitive role-based dashboards

##  User Roles

###  Engineer
- Submit health check votes for assigned teams
- View personal voting history
- Track team progress and performance
- Manage active voting sessions

###  Team Leader
- Manage team health check sessions
- Generate team progress summaries
- View team performance analytics
- Submit team-level assessments

###  Department Leader
- Monitor department-wide health
- View all teams within department
- Generate department progress reports
- Track cross-team performance

###  Senior Manager
- Organization-wide health monitoring
- Cross-department analytics
- Strategic insights and reporting
- Executive-level dashboards

###  Admin
- User management and role assignment
- Department and team creation
- Health card configuration
- Session management
- System-wide oversight

##  Technology Stack

- **Backend**: Django 5.1.6
- **Database**: SQLite3 (Development)
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Charts**: Chart.js, Matplotlib
- **Authentication**: Django Session-based
- **Static Files**: Django Static Files
- **Media Handling**: Django Media Files

##  Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Git

### Step 1: Clone the Repository
```sh
git clone <repository-url>
cd healthCheckApp
```

### Step 2: Install Dependencies
```sh
pip install -r requirements.txt
```

### Step 3: Database Setup
```sh
# Run migrations
python manage.py makemigrations
python manage.py migrate

# Create superuser (optional)
python manage.py createsuperuser
```

### Step 4: Run the Application
```sh
# Development server
python manage.py runserver
```

The application will be available at \http://127.0.0.1:8000/\

##  Database Setup

### Initial Data Population
```sh
# Run the seed data command to populate initial data
python manage.py seed_data
```

### Database Models
- **User**: User accounts with role-based access
- **Department**: Organizational departments
- **Team**: Teams within departments
- **Session**: Health check sessions
- **HealthCard**: Health assessment criteria
- **Vote**: Individual voting records
- **ProgressSummary**: Automated progress summaries

##  Usage Guide

###  Login Credentials

#### Admin Access
- **Username**: \
root\
- **Password**: \
root\

#### Other Users
- Register new accounts through the registration page
- Use email or username for login
- Role-based access control

###  Getting Started

1. **Access the Application**
   - Navigate to \http://127.0.0.1:8000/\
   - Choose your role and login

2. **Admin Setup** (First Time)
   - Login as admin (\
root\/\
root\)
   - Create departments and teams
   - Add health cards
   - Create user accounts

3. **User Registration**
   - Engineers and Team Leaders can register
   - Admin assigns teams and departments
   - Role-based permissions applied

###  Health Check Process

1. **Session Creation**
   - Admin creates health check sessions
   - Sessions have specific timeframes

2. **Voting Process**
   - Users activate sessions
   - Submit votes (Green/Amber/Red)
   - Add progress notes and trends

3. **Report Generation**
   - Automated summary generation
   - Interactive charts and analytics
   - Progress tracking and trends

##  Project Structure

\\\
healthCheckApp/
 demo/                          # Main application
    models.py                  # Database models
    views.py                   # View functions
    urls.py                    # URL routing
    forms.py                   # Form definitions
    admin.py                   # Admin interface
    management/                # Custom commands
        commands/
            seed_data.py       # Initial data seeding
 healthCheckApp/                # Project settings
    settings.py                # Django settings
    urls.py                    # Main URL configuration
    wsgi.py                    # WSGI configuration
 templates/                     # HTML templates
    base.html                  # Base template
    admin_*.html              # Admin templates
    engineer_*.html           # Engineer templates
    tl_*.html                 # Team Leader templates
    includes/                  # Template includes
 static/                        # Static files
    images/                    # Images and logos
    js/                        # JavaScript files
 media/                         # User uploaded files
 assets/                        # Collected static files
 manage.py                      # Django management script
 db.sqlite3                     # SQLite database
\\\

##  API Endpoints

### Authentication
- \GET/POST /\ - User registration
- \GET/POST /admins/\ - Admin login
- \GET/POST /engineer/\ - Engineer login
- \GET/POST /tl/\ - Team Leader login
- \GET/POST /dl/\ - Department Leader login
- \GET/POST /sm/\ - Senior Manager login
- \GET /logout\ - Logout

### Admin Management
- \GET /admins/dashboard/\ - Admin dashboard
- \GET/POST /admins/manage_users\ - User management
- \GET/POST /admins/manage-departments\ - Department management
- \GET/POST /admins/manage-teams\ - Team management
- \GET/POST /admins/manage-healthcards\ - Health card management
- \GET/POST /admins/manage-sessions\ - Session management

### Engineer Features
- \GET /engineer/dashboard/\ - Engineer dashboard
- \GET /engineer/sessions/\ - Session management
- \GET/POST /engineer/vote/\ - Voting interface
- \GET /engineers/profile/\ - Profile view
- \GET/POST /profile/update/\ - Profile update
- \GET /engineers/team-summary/\ - Team summary

### Team Leader Features
- \GET /tl/dashboard/\ - Team Leader dashboard
- \GET /tl/sessions/\ - Session management
- \GET/POST /tl/vote/\ - Voting interface
- \GET /tl/summary/\ - Team summary
- \GET/POST /tl/generate-summary/\ - Summary generation

### Department Leader Features
- \GET /dl/dashboard\ - Department Leader dashboard
- \GET /dl/dl-view-teams\ - View department teams
- \GET /dl/summary/\ - Department summary
- \GET/POST /dl/progress/\ - Progress management

### Senior Manager Features
- \GET /sm/dashboard\ - Senior Manager dashboard
- \GET /sm/summary/\ - Organization summary
- \GET /sm/progress/\ - Progress analytics

##  Deployment

### Development
```sh
python manage.py runserver
```

---
