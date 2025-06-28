from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404, HttpResponse
from .models import Team, User, Department, HealthCard, Session
from django.utils import timezone
from datetime import datetime
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
import logging

# Configure logger for error tracking
logger = logging.getLogger(__name__)

# Create your views here.
def register(request):
    """
    Handle user registration for the health check application.
    
    This function processes new user registrations, validates input data,
    checks for existing users, and creates new user accounts. It supports
    multiple user roles including Engineer and Team Leader.
    
    Args:
        request: HTTP request object containing form data
        
    Returns:
        Rendered template with success/error messages or redirect
    """
    if request.method == 'POST':
        try:
            # Extract and sanitize form data from POST request
            user_full_name = request.POST.get('name', '').strip()
            user_username = request.POST.get('username', '').strip()
            user_email = request.POST.get('email', '').strip().lower()
            user_password = request.POST.get('password', '')
            user_confirm_password = request.POST.get('confirmpassword', '')
            user_role = request.POST.get('role', '').strip()

            # Validate required fields
            if not all([user_full_name, user_username, user_email, user_password, user_confirm_password, user_role]):
                return render(request, 'register.html', {
                    'error': 'All fields are required. Please fill in all the information.'
                })

            # Validate email format
            if not is_valid_email(user_email):
                return render(request, 'register.html', {
                    'error': 'Please enter a valid email address.'
                })

            # Validate username format (alphanumeric and underscore only)
            if not is_valid_username(user_username):
                return render(request, 'register.html', {
                    'error': 'Username can only contain letters, numbers, and underscores.'
                })

            # Validate password strength
            password_validation_result = validate_password_strength(user_password)
            if not password_validation_result['is_valid']:
                return render(request, 'register.html', {
                    'error': password_validation_result['error_message']
                })

            # Validate role selection
            valid_roles = ['Engineer', 'Team Leader']
            if user_role not in valid_roles:
                return render(request, 'register.html', {
                    'error': 'Please select a valid role.'
                })

            # Check if username already exists in database
            if User.objects.filter(username=user_username).exists():
                return render(request, 'register.html', {
                    'error': f'Username "{user_username}" is already taken. Please choose a different username.'
                })
            
            # Check if email already exists in database
            if User.objects.filter(email=user_email).exists():
                return render(request, 'register.html', {
                    'error': f'Email "{user_email}" is already registered. Please use a different email address.'
                })

            # Validate that password and confirm password match
            if user_password != user_confirm_password:
                return render(request, 'register.html', {
                    'error': 'Passwords do not match. Please make sure both passwords are identical.'
                })

            # Create new user with provided details
            # Note: team and department are set to None initially
            new_user = User.objects.create(
                name=user_full_name,
                username=user_username,
                email=user_email,
                password=user_password,
                role=user_role,
                team=None,
                department=None
            )

            # Redirect to admin login page after successful registration
            return redirect('admin-login')

        except Exception as registration_error:
            # Log the error for debugging
            return render(request, 'register.html', {
                'error': 'An unexpected error occurred during registration. Please try again or contact support.'
            })

    # If GET request, simply render the registration form
    return render(request, 'register.html')

def is_valid_email(email_address):
    """
    Validate email address format using basic regex pattern.
    
    Args:
        email_address (str): Email address to validate
        
    Returns:
        bool: True if email format is valid, False otherwise
    """
    import re
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email_address) is not None

def is_valid_username(username):
    """
    Validate username format (alphanumeric and underscore only).
    
    Args:
        username (str): Username to validate
        
    Returns:
        bool: True if username format is valid, False otherwise
    """
    import re
    username_pattern = r'^[a-zA-Z0-9_]+$'
    return re.match(username_pattern, username) is not None and len(username) >= 3

def validate_password_strength(password):
    """
    Validate password strength requirements.
    
    Args:
        password (str): Password to validate
        
    Returns:
        dict: Contains 'is_valid' (bool) and 'error_message' (str) if validation fails
    """
    if len(password) < 8:
        return {
            'is_valid': False,
            'error_message': 'Password must be at least 8 characters long.'
        }
    
    if not any(char.isupper() for char in password):
        return {
            'is_valid': False,
            'error_message': 'Password must contain at least one uppercase letter.'
        }
    
    if not any(char.islower() for char in password):
        return {
            'is_valid': False,
            'error_message': 'Password must contain at least one lowercase letter.'
        }
    
    if not any(char.isdigit() for char in password):
        return {
            'is_valid': False,
            'error_message': 'Password must contain at least one number.'
        }
    
    return {
        'is_valid': True,
        'error_message': ''
    }

def user_list(request):
    """
    Display a list of all registered users in the system.
    
    This function retrieves all users from the database and displays them
    in a list format. Useful for administrative purposes to view all
    registered users and their details.
    
    Args:
        request: HTTP request object
        
    Returns:
        Rendered template with list of users
    """
    # Fetch all users from database
    users = User.objects.all()
    return render(request, 'user_list.html', {'users': users})

def admin_login(request):
    """
    Handle admin authentication with hardcoded credentials.
    
    This function provides a simple admin login mechanism using
    hardcoded credentials (username: 'root', password: 'root').
    Upon successful login, it sets session variables and redirects
    to the admin dashboard.
    
    Args:
        request: HTTP request object containing login credentials
        
    Returns:
        Rendered template with success/error messages
    """
    try:
        if request.method == 'POST':
            # Get login credentials from form
            username_or_email = request.POST.get('usernameoremail')
            password = request.POST.get('password')
            
            # Validate input fields
            if not username_or_email or not password:
                return render(request, 'admin_login.html', {'error': 'Please provide both username and password'})
            
            # Check against hardcoded admin credentials
            if username_or_email == 'root' and password == 'root':
                # Set session variables for admin user
                request.session['user_id'] = 'root'
                request.session['role'] = 'Admin'
                return render(request, 'admin_dashboard.html')
            else:
                # Display error for invalid credentials
                return render(request, 'admin_login.html', {'error': 'Invalid credentials for admin'})
        
        # If GET request, render the admin login form
        return render(request, 'admin_login.html')
    except Exception as e:
        return render(request, 'admin_login.html', {'error': f'Login error: {str(e)}'})

def engineer_login(request):
    """
    Handle engineer user authentication and login.
    
    This function authenticates engineers by checking their username/email
    and password against the database. It validates the user role and
    sets appropriate session variables upon successful login.
    
    Args:
        request: HTTP request object containing login credentials
        
    Returns:
        Rendered template with success/error messages
    """
    try:
        if request.method == 'POST':
            # Extract login credentials from form
            username_or_email = request.POST.get('usernameoremail')
            password = request.POST.get('password')

            # Validate input fields
            if not username_or_email or not password:
                return render(request, 'engineer_login.html', {'error': 'Please provide both username/email and password'})

            # Try to find user by username or email
            user = User.objects.filter(username=username_or_email).first() or User.objects.filter(email=username_or_email).first()
            
            if user:
                # Check if password matches
                if user.password == password:
                    # Verify user has Engineer role
                    if user.role == 'Engineer':
                        # Set session variables for authenticated engineer
                        request.session['user_id'] = user.user_id
                        request.session['role'] = user.role
                        return redirect('engineers-dashboard')
                    else:
                        # User exists but has wrong role
                        return render(request, 'engineer_login.html', {'error': 'Access denied: This account is not for engineers'})
                else:
                    # Password is incorrect
                    return render(request, 'engineer_login.html', {'error': 'Incorrect password'})
            else:
                # User not found in database
                return render(request, 'engineer_login.html', {'error': 'Username/email not found'})
        
        # If GET request, render the engineer login form
        return render(request, 'engineer_login.html')
    except Exception as e:
        return render(request, 'engineer_login.html', {'error': f'Login error: {str(e)}'})

def team_leader_login(request):
    """
    Handle Team Leader authentication and login.
    
    This function authenticates Team Leaders by checking their credentials
    and role. Similar to engineer login but specifically for users with
    'Team Leader' role.
    
    Args:
        request: HTTP request object containing login credentials
        
    Returns:
        Rendered template with success/error messages
    """
    try:
        if request.method == 'POST':
            # Extract login credentials from form
            username_or_email = request.POST.get('usernameoremail')
            password = request.POST.get('password')

            # Validate input fields
            if not username_or_email or not password:
                return render(request, 'tl_login.html', {'error': 'Please provide both username/email and password'})

            # Try to find user by username or email
            user = User.objects.filter(username=username_or_email).first() or User.objects.filter(email=username_or_email).first()
            
            if user:
                # Check if password matches
                if user.password == password:
                    # Verify user has Team Leader role
                    if user.role == 'Team Leader':
                        # Set session variables for authenticated team leader
                        request.session['user_id'] = user.user_id
                        request.session['role'] = user.role
                        return render(request, 'tl_dashboard.html')
                    else:
                        # User exists but has wrong role
                        return render(request, 'tl_login.html', {'error': 'Access denied: This account is not for team leaders'})
                else:
                    # Password is incorrect
                    return render(request, 'tl_login.html', {'error': 'Incorrect password'})
            else:
                # User not found in database
                return render(request, 'tl_login.html', {'error': 'Username/email not found'})
        
        # If GET request, render the team leader login form
        return render(request, 'tl_login.html')
    except Exception as e:
        return render(request, 'tl_login.html', {'error': f'Login error: {str(e)}'})

def department_leader_login(request):
    """
    Handle Department Leader authentication and login.
    
    This function authenticates Department Leaders and redirects them
    to their dashboard upon successful login. Uses redirect instead of
    render for successful login.
    
    Args:
        request: HTTP request object containing login credentials
        
    Returns:
        Rendered template with error messages or redirect to dashboard
    """
    try:
        if request.method == 'POST':
            # Extract login credentials from form
            username_or_email = request.POST.get('usernameoremail')
            password = request.POST.get('password')

            # Validate input fields
            if not username_or_email or not password:
                return render(request, 'dl_login.html', {'error': 'Please provide both username/email and password'})

            # Try to find user by username or email
            user = User.objects.filter(username=username_or_email).first() or User.objects.filter(email=username_or_email).first()
            
            if user:
                # Check if password matches
                if user.password == password:
                    # Verify user has Department Leader role
                    if user.role == 'Department Leader':
                        # Set session variables and redirect to dashboard
                        request.session['user_id'] = user.user_id
                        request.session['role'] = user.role
                        return redirect('dl-dashboard')
                    else:
                        # User exists but has wrong role
                        return render(request, 'dl_login.html', {'error': 'Access denied: This account is not for department leaders'})
                else:
                    # Password is incorrect
                    return render(request, 'dl_login.html', {'error': 'Incorrect password'})
            else:
                # User not found in database
                return render(request, 'dl_login.html', {'error': 'Username/email not found'})
        
        # If GET request, render the department leader login form
        return render(request, 'dl_login.html')
    except Exception as e:
        return render(request, 'dl_login.html', {'error': f'Login error: {str(e)}'})

def senior_manager_login(request):
    """
    Handle Senior Manager authentication and login.
    
    This function authenticates Senior Managers and redirects them
    to their dashboard upon successful login. Similar to DL login
    but for Senior Manager role.
    
    Args:
        request: HTTP request object containing login credentials
        
    Returns:
        Rendered template with error messages or redirect to dashboard
    """
    try:
        if request.method == 'POST':
            # Extract login credentials from form
            username_or_email = request.POST.get('usernameoremail')
            password = request.POST.get('password')

            # Validate input fields
            if not username_or_email or not password:
                return render(request, 'sm_login.html', {'error': 'Please provide both username/email and password'})

            # Try to find user by username or email
            user = User.objects.filter(username=username_or_email).first() or User.objects.filter(email=username_or_email).first()
            
            if user:
                # Check if password matches
                if user.password == password:
                    # Verify user has Senior Manager role
                    if user.role == 'Senior Manager':
                        # Set session variables and redirect to dashboard
                        request.session['user_id'] = user.user_id
                        request.session['role'] = user.role
                        return redirect('sm-dashboard')
                    else:
                        # User exists but has wrong role
                        return render(request, 'sm_login.html', {'error': 'Access denied: This account is not for senior managers'})
                else:
                    # Password is incorrect
                    return render(request, 'sm_login.html', {'error': 'Incorrect password'})
            else:
                # User not found in database
                return render(request, 'sm_login.html', {'error': 'Username/email not found'})
        
        # If GET request, render the senior manager login form
        return render(request, 'sm_login.html')
    except Exception as e:
        return render(request, 'sm_login.html', {'error': f'Login error: {str(e)}'})

def logout_view(request):
    """
    Handle user logout and session cleanup.
    
    This function clears all session data and logs the user out of the system.
    It includes debug logging to track session state before and after logout.
    
    Args:
        request: HTTP request object
        
    Returns:
        Rendered template with logout confirmation message
    """
    try:
        # Check if user is already logged out
        if not check_session(request):
            return render(request, 'admin_login.html', {'success': 'Successfully logged out'})
        
        # Debug logging - print session info before logout
        print(f"User ID: {request.session.get('user_id', 'Not found')}")
        print(f"Role: {request.session.get('role', 'Not found')}")
        
        # Clear all session data
        request.session.flush()
        
        # Debug logging - verify session is cleared
        print(f"User ID: {request.session.get('user_id', 'Not found')}")
        print(f"Role: {request.session.get('role', 'Not found')}")
        
        # Return logout confirmation message
        return render(request, 'admin_login.html', {'success': 'Successfully logged out'})
    except Exception as e:
        return render(request, 'admin_login.html', {'error': f'Logout error: {str(e)}'})

def check_session(request):
    """
    Check if user session is valid and active.
    
    This utility function verifies that the current request has valid
    session data with both user_id and role present. Used for session
    validation across the application.
    
    Args:
        request: HTTP request object
        
    Returns:
        bool: True if session is valid, False otherwise
    """
    try:
        # Debug logging to track session checking
        print("Checking session...")
        print(f"Session data: {request.session}")
        
        # Check if both user_id and role exist in session
        if 'user_id' in request.session and 'role' in request.session:
            return True
        return False
    except Exception as e:
        print(f"Session check error: {str(e)}")
        return False

def reset_account(request):
    """
    Handle account reset request by email verification.
    
    Args:
        request: HTTP request object
        
    Returns:
        Rendered template with verification result
    """
    try:
        if request.method == 'POST':
            email = request.POST.get('email')
            
            # Validate email input
            if not email:
                return render(request, 'reset_account.html', {'error': 'Please provide an email address'})
            
            user = User.objects.filter(email=email).first()
            if user:
                return render(request, 'reset_password.html', {'email': email, 'success': 'Email verified successfully!'})
            else:
                return render(request, 'reset_account.html', {'error': 'Email address not found in our records'})
        return render(request, 'reset_account.html')
    except Exception as e:
        return render(request, 'reset_account.html', {'error': f'Reset error: {str(e)}'})

def reset_password(request):
    """
    Render password reset form.
    
    Args:
        request: HTTP request object
        
    Returns:
        Rendered password reset template
    """
    return render(request, 'reset_password.html')

def reset_user_password_plaintext(request):
    """
    Handle password reset with plain text storage.
    
    Args:
        request: HTTP request object
        
    Returns:
        Rendered template with reset result
    """
    try:
        if request.method == 'POST':
            email = request.POST.get('email')
            new_password = request.POST.get('password')
            confirm_password = request.POST.get('confirmpassword')

            # Validate input fields
            if not email or not new_password or not confirm_password:
                return render(request, 'reset_password.html', {
                    'error': 'Please fill in all required fields',
                    'email': email
                })

            user = User.objects.filter(email=email).first()

            if not user:
                return render(request, 'reset_password.html', {
                    'error': 'Email address not found',
                    'email': email
                })

            if new_password != confirm_password:
                return render(request, 'reset_password.html', {
                    'error': 'Passwords do not match',
                    'email': email
                })

            # Validate password strength
            if len(new_password) < 6:
                return render(request, 'reset_password.html', {
                    'error': 'Password must be at least 6 characters long',
                    'email': email
                })

            # Store as plain text (not recommended for production)
            user.password = new_password
            user.save(update_fields=['password'])

            return render(request, 'admin_login.html', {
                'success': 'Password changed successfully!'
            })

        return render(request, 'reset_password.html')
    except Exception as e:
        return render(request, 'reset_password.html', {'error': f'Password reset error: {str(e)}'})

def admin_dashboard(request):
    print(f"User ID: {request.session['user_id']}")
    print(f"Role: {request.session['role']}")
    if request.method == 'POST' or request.method == 'GET':
        if not check_session(request):
            return redirect('admin-login')
    return render(request, 'admin_dashboard.html')

def manage_user(request):
    if not check_session(request):
        return redirect('admin-login')
    if request.method == 'POST':
        name = request.POST.get('name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirmpassword = request.POST.get('confirmpassword')
        role = request.POST.get('role')
        team_id = request.POST.get('team')
        department_id = request.POST.get('department')

        if User.objects.filter(username=username).exists():
            return render(request, 'admin_manage_users.html', {'error': 'Username already exists!'})
        if User.objects.filter(email=email).exists():
            return render(request, 'admin_manage_users.html', {'error': 'Email already exists!'})

        if password != confirmpassword:
            return render(request, 'admin_manage_users.html', {'error': 'Passwords do not match!'})

        # Initialize team and department as None
        team = None
        department = None

        # Set team and department based on role
        if role in ['Engineer', 'Team Leader']:
            if team_id:
                team = Team.objects.get(team_id=team_id)
            if department_id:
                department = Department.objects.get(department_id=department_id)
        elif role == 'Department Leader':
            if department_id:
                department = Department.objects.get(department_id=department_id)

        user = User.objects.create(
            name=name,
            username=username,
            email=email,
            password=password,
            role=role,
            team=team,
            department=department
        )
        users = User.objects.all()
        teams = Team.objects.all()
        departments = Department.objects.all()
        return render(request, 'admin_manage_users.html', {'users': users, 'teams': teams, 'departments': departments, 'success': 'User Added Successfully'}) 
    users = User.objects.all()
    teams = Team.objects.all()
    departments = Department.objects.all()
    return render(request, 'admin_manage_users.html', {'users': users, 'teams': teams, 'departments': departments})

def admin_users_profile(request, user_id):
    if not check_session(request):
        return redirect('admin-login')
    user = get_object_or_404(User, user_id=user_id)
    teams = Team.objects.all()
    departments = Department.objects.all()
    return render(request, 'admin_user_detail.html', {
        'user': user,
        'teams': teams,
        'departments': departments
    })

def admin_update_user(request, user_id):
    if not check_session(request):
        return redirect('admin-login')
    user = get_object_or_404(User, user_id=user_id)
    if request.method == 'POST':
        role = request.POST.get('role')
        team_id = request.POST.get('team')
        department_id = request.POST.get('department')
        user.role = role

        if team_id:
            user.team = Team.objects.get(name=team_id)
        else:
            user.team = None

        if department_id:
            user.department = Department.objects.get(name=department_id)
        else:
            user.department = None
        user.save()
        return redirect('admin-users-profile', user_id=user.user_id)
    return render(request, 'admin_user_detail.html', {'user': user})

def departments_list(request):
    if not check_session(request):
        return redirect('admin-login')
    if request.method == 'POST':
        departmentname = request.POST.get('departmentname')

        if Department.objects.filter(name=departmentname).exists():
            return render(request, 'admin_departments_list.html', {'error': 'Department name already exists!'})

        department = Department.objects.create(
            name=departmentname
        )
        departments = Department.objects.all()
        return render(request, 'admin_departments_list.html', {'departments': departments, 'success': 'Department Added Successfully'}) 
    departments = Department.objects.all()
    return render(request, 'admin_departments_list.html', {'departments': departments})

def teams_list(request):
    if not check_session(request):
        return redirect('admin-login')
    if request.method == 'POST':
        teamname = request.POST.get('teamname')
        getdepartment = request.POST.get('department')

        if Team.objects.filter(name=teamname).exists():
            teams = Team.objects.all()
            departments = Department.objects.all()
            return render(request, 'admin_teams_list.html.html', {'error': 'Team name already exists!', 'teams': teams, 'departments': departments})

        department = Department.objects.get(name=getdepartment)

        team = Team.objects.create(
            name=teamname,
            department=department
        )
        teams = Team.objects.all()
        departments = Department.objects.all()
        return render(request, 'admin_teams_list.html', {'teams': teams, 'departments': departments, 'success': 'Team Added Successfully'})
    teams = Team.objects.all()
    departments = Department.objects.all()
    return render(request, 'admin_teams_list.html', {'teams': teams, 'departments': departments})

def healthcards_list(request):
    if not check_session(request):
        return redirect('admin-login')
    if request.method == 'POST':
        healthcardtitle = request.POST.get('healthcardtitle')
        healthcarddescription = request.POST.get('healthcarddescription')

        healthcard = HealthCard.objects.create(
            title=healthcardtitle,
            description=healthcarddescription
        )
        healthcards = HealthCard.objects.all()
        return render(request, 'admin_healthcards_list.html', {'healthcards': healthcards, 'success': 'Healthcard Added Successfully'})
    healthcards = HealthCard.objects.all()
    return render(request, 'admin_healthcards_list.html', {'healthcards': healthcards})

def sessions_list(request):
    if not check_session(request):
        return redirect('admin-login')
    if request.method == 'POST':
        sessiondate = request.POST.get('sessiondate')
        Session.objects.create(date=sessiondate)
        sessions = Session.objects.all()
        return render(request, 'admin_sessions_list.html', {'sessions': sessions, 'success': 'Session Added Successfully'})

    sessions = Session.objects.all()
    return render(request, 'admin_sessions_list.html', {'sessions': sessions})

def delete_session(request, session_id):
    if not check_session(request):
        return redirect('admin-login')
    session = get_object_or_404(Session, session_id=session_id)  # Use id to find the session
    session.delete()  # Delete the session
    return redirect('admin-manage-sessions')  # Redirect to the sessions list page

def delete_user(request, user_id):
    if not check_session(request):
        return redirect('admin-login')
    user = get_object_or_404(User, user_id=user_id)
    user.delete()
    return redirect('admin-manage-user')

def delete_department(request, department_id):
    if not check_session(request):
        return redirect('admin-login')
    department = get_object_or_404(Department, department_id=department_id)
    department.delete()
    return redirect('admin-manage-departments')

def delete_team(request, team_id):
    if not check_session(request):
        return redirect('admin-login')
    team = get_object_or_404(Team, team_id=team_id)
    team.delete()
    return redirect('admin-manage-teams')

def delete_healthcard(request, card_id):
    if not check_session(request):
        return redirect('admin-login')
    healthcard = get_object_or_404(HealthCard, card_id=card_id)
    healthcard.delete()
    return redirect('admin-manage-healthcards')

def dl_dashboard(request):
    if not check_session(request):
        return redirect('dl-login')
    user_id = request.session.get('user_id')
    return render(request, 'dl_dashboard.html')

def view_teams_in_department(request):
    if not check_session(request):
        return redirect('dl-login')
    # Step 1: Get the department leader from session
    user_id = request.session.get('user_id')
    user = User.objects.filter(user_id=user_id, role='Department Leader').first()

    if not user:
        return render(request, 'dl_login.html', {'error': 'Invalid user or session.'})

    if not user.department:
        return render(request, 'dl_dashboard.html', {'error': 'You are not assigned to a department yet.'})

    # Step 2: Get all teams in the leader's department
    teams = Team.objects.filter(department=user.department)

    return render(request, 'dl_teams.html', {
        'teams': teams,
    })

def view_health_cards(request):
    if not check_session(request):
        return redirect('dl-login')
    cards = HealthCard.objects.all().order_by('-created_at')  # latest first
    return render(request, 'dl_view_cards.html', {'healthcards': cards})

def sm_dashboard(request):
    if not check_session(request):
        return redirect('sm-login')
    user_id = request.session.get('user_id')
    return render(request, 'sm_dashboard.html')

def sm_teams_list(request):
    if not check_session(request):
        return redirect('sm-login')
    teams = Team.objects.all()
    return render(request, 'sm_teams_list.html', {'teams': teams})

def sm_departments_list(request):
    if not check_session(request):
        return redirect('sm-login')
    departments = Department.objects.all()
    return render(request, 'sm_departments_list.html', {'departments': departments})
    return render(request, 'dl_dashboard.html')

########################## Engineer Panel #######################

def engineers_dashboard(request):
    """
    Engineer dashboard with real data from models.
    
    Fetches statistics and recent activities for the logged-in engineer.
    """
    print(f"1")
    try:
        # Get user from session
        print(f"2")
        user_id = request.session['user_id']
        print(f"User ID: {user_id}")
        print(f"Role: {request.session['role']}")
        if not check_session(request):
            return redirect('engineer-login')
        
        print(f"3")
        user = User.objects.get(user_id=user_id)
        
        # Get total number of sessions
        total_sessions = Session.objects.count()
        
        # Get total votes cast by this user
        user_votes = Vote.objects.filter(user=user).count()
        
        # Get team members count (if user has a team)
        team_members_count = 0
        if user.team:
            team_members_count = User.objects.filter(team=user.team).count()
        
        # Get user's recent votes (last 5) for recent activities
        recent_votes = Vote.objects.filter(user=user).order_by('-created_at')[:5]
        
        # Get user's recent profile updates (simulated - using user creation date)
        profile_updated = user.created_at
        
        # Get active session info
        active_session_id = request.session.get('engineer_active_session_id')
        active_session = None
        if active_session_id:
            try:
                active_session = Session.objects.get(session_id=active_session_id)
            except Session.DoesNotExist:
                pass
        
        # ========================================
        # RECENT ACTIVITIES LOGIC
        # ========================================
        # This section creates a dynamic list of user activities
        # by combining different types of events and sorting them by time
        
        recent_activities = []
        
        # 1. Add recent votes to activities
        # Convert each vote into an activity item with details
        for vote in recent_votes:
            recent_activities.append({
                'type': 'vote',  # Activity type for categorization
                'title': f'Vote submitted for {vote.team.name}',  # Human-readable title
                'description': f'Voted {vote.vote_value}/5 for {vote.card.title}',  # Detailed description
                'time': vote.created_at,  # Timestamp for sorting
                'color': 'success'  # Bootstrap color class for UI
            })
        
        # 2. Add active session info if user has an active session
        # This shows current participation status
        if active_session:
            recent_activities.append({
                'type': 'session',
                'title': f'Session activated: {active_session.date.strftime("%B %d, %Y")}',
                'description': 'You are currently participating in this session',
                'time': active_session.created_at,
                'color': 'warning'  # Warning color to indicate active state
            })
        
        # 3. Add profile update info (using user creation date as last update)
        # This provides a baseline activity for new users
        recent_activities.append({
            'type': 'profile',
            'title': 'Profile information updated',
            'description': 'Your profile details were last updated',
            'time': profile_updated,
            'color': 'info'  # Info color for profile-related activities
        })
        
        # Sort activities by time (most recent first)
        # This ensures the timeline shows activities in chronological order
        recent_activities.sort(key=lambda x: x['time'], reverse=True)
        
        # ========================================
        # TEAM PROGRESS LOGIC
        # ========================================
        # This section calculates the team's overall performance score
        # based on recent voting activity
        
        team_progress = 0  # Default value if no team or votes exist
        
        if user.team:
            # Get the 10 most recent votes for the user's team
            # This provides a recent performance snapshot
            team_votes = Vote.objects.filter(team=user.team).order_by('-created_at')[:10]
            
            if team_votes:
                # Calculate average vote score
                # Sum all vote values and divide by number of votes
                total_score = sum(vote.vote_value for vote in team_votes)
                avg_score = total_score / len(team_votes)
                
                # Convert to percentage (assuming 5 is the maximum vote value)
                # Formula: (average_score / max_possible_score) * 100
                team_progress = round((avg_score / 5) * 100)
                
                # Example calculation:
                # If team has votes: [4, 3, 5, 4, 3] (5 votes total)
                # Total score = 4 + 3 + 5 + 4 + 3 = 19
                # Average score = 19 / 5 = 3.8
                # Team progress = (3.8 / 5) * 100 = 76%
        
        # Prepare context data for template
        context = {
            'user': user,
            'total_sessions': total_sessions,
            'user_votes': user_votes,
            'team_members_count': team_members_count,
            'team_progress': team_progress,
            'recent_activities': recent_activities[:4],  # Show only 4 most recent activities
            'active_session': active_session,
        }

        print(context)
        
        return render(request, 'engineer_dashboard.html', context)
        
    except User.DoesNotExist:
        return redirect('engineer-login')
    except Exception as e:
        # Fallback with default values if there's an error
        # This ensures the dashboard still loads even if there are data issues
        context = {
            'total_sessions': 0,
            'user_votes': 0,
            'team_members_count': 0,
            'team_progress': 0,
            'recent_activities': [],
            'active_session': None,
        }
        return render(request, 'engineer_dashboard.html', context)

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from .models import Session
from django.views.decorators.csrf import csrf_protect
@csrf_protect
def engineer_manage_sessions(request):
    """
    Display and manage health check sessions for engineers.
    
    This view shows all available sessions and the currently active session.
    It handles session expiration checks and provides session management interface.
    
    Args:
        request: HTTP request object
        
    Returns:
        Rendered template with sessions data
    """
    # Fetch all sessions ordered by creation date (newest first)
    all_available_sessions = Session.objects.all().order_by('-created_at')
    
    # Get the currently active session ID from user's session
    current_active_session_id = request.session.get('engineer_active_session_id')
    current_active_session = None

    # Check if there's an active session and validate it
    if current_active_session_id:
        try:
            # Retrieve the active session from database
            current_active_session = Session.objects.get(session_id=current_active_session_id)
            
            # Check if the active session has expired
            current_time = timezone.now()
            if current_active_session.date < current_time:
                # Session has expired, remove it from user's session
                request.session.pop('engineer_active_session_id', None)
                messages.warning(request, "Your active session has expired and has been deactivated.")
                current_active_session = None
                
        except Session.DoesNotExist:
            # Active session no longer exists in database, clean up session
            request.session.pop('engineer_active_session_id', None)
            messages.error(request, "The active session was not found and has been deactivated.")
            current_active_session = None

    # Add expiration status to each session for template display
    for session in all_available_sessions:
        session.is_expired = session.date < timezone.now()

    return render(request, 'engineers_Session.html', {
        'sessions': all_available_sessions,
        'active_session': current_active_session,
    })

@csrf_protect
def engineer_select_session(request, session_id):
    """
    Activate a specific health check session for an engineer.
    
    This view handles session activation, validates session existence and expiration,
    and provides appropriate feedback to the user.
    
    Args:
        request: HTTP request object
        session_id: ID of the session to activate
        
    Returns:
        Redirect to session management page with success/error message
    """
    if request.method == 'POST':
        try:
            # Retrieve the session to be activated
            session_to_activate = get_object_or_404(Session, session_id=session_id)

            # Check if the session has expired
            if session_to_activate.is_expired():
                messages.error(request, f"Session {session_to_activate.date} has expired and cannot be activated.")
            else:
                # Activate the session by storing its ID in user's session
                request.session['engineer_active_session_id'] = session_to_activate.session_id
                messages.success(request, f"Session {session_to_activate.date} has been successfully activated.")
                
        except Session.DoesNotExist:
            messages.error(request, "The requested session was not found.")
        except Exception as e:
            # Handle any unexpected errors during session activation
            messages.error(request, f"An error occurred while activating the session: {str(e)}")
            logger.error(f"Error activating session {session_id}: {str(e)}")
    
    return redirect('engineer-manage-sessions')

@csrf_protect
def engineer_deactivate_session(request):
    """
    Deactivate the currently active health check session for an engineer.
    
    This view removes the active session from the user's session storage
    and provides confirmation feedback.
    
    Args:
        request: HTTP request object
        
    Returns:
        Redirect to session management page with success message
    """
    if request.method == 'POST':
        try:
            # Get the current active session ID before removing it
            current_active_session_id = request.session.get('engineer_active_session_id')
            
            # Remove the active session from user's session
            request.session.pop('engineer_active_session_id', None)
            
            if current_active_session_id:
                messages.success(request, "Your active session has been successfully deactivated.")
            else:
                messages.info(request, "No active session was found to deactivate.")
                
        except Exception as e:
            # Handle any unexpected errors during session deactivation
            messages.error(request, f"An error occurred while deactivating the session: {str(e)}")
            logger.error(f"Error deactivating session: {str(e)}")
    
    return redirect('engineer-manage-sessions')

# @login_required
def voting_guidance(request):
    return render(request, 'engineer_voting_guidance.html', {
        'vote_url': 'vote-page'
    })

from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404
from .models import Session, Team, HealthCard, Vote, User
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.utils import timezone

@csrf_protect
def vote_page(request):
    """
    Handle engineer voting functionality for health check assessments.
    
    This function processes vote submissions from engineers, including:
    - Form validation and data sanitization
    - Duplicate vote detection and updates
    - New vote creation
    - Session and user authentication checks
    
    Args:
        request: HTTP request object containing form data and session info
        
    Returns:
        Rendered template with success/error messages and form data
        
    Raises:
        Http404: If user or session not found in database
    """
    # ========================================
    # INITIAL DATA FETCHING AND VALIDATION
    # ========================================
    # Fetch all available teams and health cards for form dropdowns
    available_teams = Team.objects.all()
    available_health_cards = HealthCard.objects.all()
    
    # Get active session and user info from session storage
    current_active_session_id = request.session.get('engineer_active_session_id')
    current_user_id = request.session.get('user_id')

    # ========================================
    # AUTHENTICATION AND SESSION VALIDATION
    # ========================================
    # Check if user is logged in
    if not current_user_id:
        messages.error(request, "You must be logged in to submit votes.")
        return redirect('engineer-login')

    # Check if user has an active session for voting
    if not current_active_session_id:
        messages.error(request, "Please activate a session before submitting votes.")
        return redirect('engineer-manage-sessions')

    # Fetch user and session objects from database
    try:
        current_user = get_object_or_404(User, user_id=current_user_id)
        current_session = get_object_or_404(Session, session_id=current_active_session_id)
    except Http404 as e:
        messages.error(request, "Invalid session or user data. Please log in again.")
        return redirect('engineer-login')

    # ========================================
    # FORM PROCESSING (POST REQUEST HANDLING)
    # ========================================
    if request.method == 'POST':
        try:
            # Extract and sanitize form data
            selected_team_id = request.POST.get('team')
            selected_health_card_id = request.POST.get('card')
            selected_vote_value = request.POST.get('vote_value')
            selected_progress_trend = request.POST.get('progress_note', '').strip()

            # ========================================
            # FORM VALIDATION
            # ========================================
            # Check if all required fields are provided
            if not all([selected_team_id, selected_health_card_id, selected_vote_value]):
                messages.error(request, "All fields are required. Please fill in team, health card, and vote selection.")
                return render(request, 'engineer_vote.html', {
                    'teams': available_teams,
                    'cards': available_health_cards,
                    'user': current_user,
                    'session': current_session,
                })

            # Validate vote value is within acceptable range (1-3)
            try:
                vote_value_integer = int(selected_vote_value)
                if vote_value_integer not in [1, 2, 3]:
                    raise ValueError("Invalid vote value")
            except (ValueError, TypeError):
                messages.error(request, "Invalid vote selection. Please choose Green, Amber, or Red.")
                return render(request, 'engineer_vote.html', {
                    'teams': available_teams,
                    'cards': available_health_cards,
                    'user': current_user,
                    'session': current_session,
                })

            # Validate progress trend is one of the allowed values
            allowed_progress_trends = ['Up trend', 'Down trend', 'No change']
            if selected_progress_trend not in allowed_progress_trends:
                messages.error(request, "Invalid progress trend selection.")
                return render(request, 'engineer_vote.html', {
                    'teams': available_teams,
                    'cards': available_health_cards,
                    'user': current_user,
                    'session': current_session,
                })

            # ========================================
            # DATABASE OBJECT FETCHING
            # ========================================
            # Fetch team and health card objects from database
            try:
                selected_team = get_object_or_404(Team, pk=selected_team_id)
                selected_health_card = get_object_or_404(HealthCard, pk=selected_health_card_id)
            except Http404:
                messages.error(request, "Selected team or health card not found. Please try again.")
                return render(request, 'engineer_vote.html', {
                    'teams': available_teams,
                    'cards': available_health_cards,
                    'user': current_user,
                    'session': current_session,
                })

            # ========================================
            # DUPLICATE VOTE DETECTION AND HANDLING
            # ========================================
            # Check if user has already voted for this combination
            existing_vote_record = Vote.objects.filter(
                user=current_user,
                session=current_session,
                team=selected_team,
                card=selected_health_card
            ).first()

            if existing_vote_record:
                # ========================================
                # UPDATE EXISTING VOTE
                # ========================================
                try:
                    existing_vote_record.vote_value = vote_value_integer
                    existing_vote_record.progress_note = selected_progress_trend
                    existing_vote_record.save()
                    
                    messages.success(request, f"Your vote for {selected_health_card.title} has been updated successfully.")
                    
                except Exception as vote_update_error:
                    # Log the error for debugging (in production, use proper logging)
                    print(f"Error updating vote: {vote_update_error}")
                    messages.error(request, "Failed to update your vote. Please try again.")
            else:
                # ========================================
                # CREATE NEW VOTE RECORD
                # ========================================
                try:
                    Vote.objects.create(
                        user=current_user,
                        session=current_session,
                        team=selected_team,
                        card=selected_health_card,
                        vote_value=vote_value_integer,
                        progress_note=selected_progress_trend,
                        created_at=timezone.now()
                    )
                    
                    messages.success(request, f"Your vote for {selected_health_card.title} has been submitted successfully.")
                    
                except Exception as vote_creation_error:
                    # Log the error for debugging (in production, use proper logging)
                    print(f"Error creating vote: {vote_creation_error}")
                    messages.error(request, "Failed to submit your vote. Please try again.")

            # ========================================
            # SUCCESS RESPONSE
            # ========================================
            # Return the form with success message and current data
            return render(request, 'engineer_vote.html', {
                'teams': available_teams,
                'cards': available_health_cards,
                'user': current_user,
                'session': current_session,
            })

        except Exception as form_processing_error:
            # ========================================
            # GENERAL ERROR HANDLING
            # ========================================
            # Log the error for debugging (in production, use proper logging)
            print(f"Unexpected error in vote processing: {form_processing_error}")
            messages.error(request, "An unexpected error occurred. Please try again.")

    # ========================================
    # GET REQUEST HANDLING (FORM DISPLAY)
    # ========================================
    # Display the voting form for GET requests
    return render(request, 'engineer_vote.html', {
        'teams': available_teams,
        'cards': available_health_cards,
        'user': current_user,
        'session': current_session,
    })


def profile_view(request):
    """
    Display user profile information.
    
    This function retrieves the current user's profile data from the session
    and displays it in a user-friendly format. It handles cases where
    the user is not logged in or the user record doesn't exist.
    
    Args:
        request: HTTP request object containing session data
        
    Returns:
        Rendered profile template with user data or error page
        
    Raises:
        User.DoesNotExist: If user record is not found in database
    """
    # ========================================
    # SESSION VALIDATION AND USER FETCHING
    # ========================================
    # Extract user ID from session storage
    current_user_id = request.session.get('user_id')

    # Check if user is logged in (has valid session)
    if not current_user_id:
        messages.error(request, "You must be logged in to view your profile.")
        return redirect('engineer-login')

    # ========================================
    # DATABASE OPERATION AND ERROR HANDLING
    # ========================================
    try:
        # Fetch user record from database using session user ID
        current_user = User.objects.get(user_id=current_user_id)
    except User.DoesNotExist:
        # Handle case where user record doesn't exist in database
        messages.error(request, "User profile not found. Please contact support.")
        return render(request, 'error.html', {
            'error': 'User profile not found. Please log in again or contact support.',
            'error_code': 'USER_NOT_FOUND'
        })
    except Exception as database_error:
        # Handle unexpected database errors
        print(f"Database error in profile_view: {database_error}")
        messages.error(request, "An error occurred while loading your profile. Please try again.")
        return render(request, 'error.html', {
            'error': 'Unable to load profile. Please try again later.',
            'error_code': 'DATABASE_ERROR'
        })

    # ========================================
    # SUCCESS RESPONSE
    # ========================================
    # Render profile template with user data
    return render(request, 'profile.html', {
        'user': current_user,
        'page_title': 'My Profile'
    })


def profile_update(request):
    """
    Handle user profile update functionality.
    
    This function processes profile update requests, including form validation,
    data sanitization, and database updates. It handles both GET requests
    (display form) and POST requests (process form submission).
    
    Args:
        request: HTTP request object containing form data and session info
        
    Returns:
        Rendered update profile template or redirect to profile page
        
    Raises:
        User.DoesNotExist: If user record is not found in database
    """
    # ========================================
    # SESSION VALIDATION AND USER FETCHING
    # ========================================
    # Extract user ID from session storage
    current_user_id = request.session.get('user_id')

    # Validate user authentication
    if not current_user_id:
        messages.error(request, "You must be logged in to update your profile.")
        return redirect('engineer-login')

    # ========================================
    # DATABASE OPERATION AND ERROR HANDLING
    # ========================================
    try:
        # Fetch user record from database using session user ID
        current_user = User.objects.get(user_id=current_user_id)
    except User.DoesNotExist:
        # Handle case where user record doesn't exist in database
        messages.error(request, "User profile not found. Please contact support.")
        return render(request, 'error.html', {
            'error': 'User profile not found. Please log in again or contact support.',
            'error_code': 'USER_NOT_FOUND'
        })
    except Exception as database_error:
        # Handle unexpected database errors
        print(f"Database error in profile_update: {database_error}")
        messages.error(request, "An error occurred while loading your profile. Please try again.")
        return render(request, 'error.html', {
            'error': 'Unable to load profile. Please try again later.',
            'error_code': 'DATABASE_ERROR'
        })

    # ========================================
    # FORM PROCESSING (POST REQUEST HANDLING)
    # ========================================
    if request.method == 'POST':
        try:
            # Initialize form with POST data and file uploads
            profile_update_form = UserUpdateForm(
                request.POST, 
                request.FILES, 
                instance=current_user
            )

            # ========================================
            # FORM VALIDATION AND PROCESSING
            # ========================================
            if profile_update_form.is_valid():
                # ========================================
                # DATABASE UPDATE OPERATION
                # ========================================
                try:
                    # Save the updated user data to database
                    profile_update_form.save()
                    
                    # Display success message to user
                    messages.success(request, "Profile updated successfully!")
                    
                    # Redirect to profile page after successful update
                    return redirect('profile')
                    
                except Exception as save_error:
                    # Handle database save errors
                    print(f"Error saving profile update: {save_error}")
                    messages.error(request, "Failed to save profile changes. Please try again.")
                    
            else:
                # ========================================
                # FORM VALIDATION ERROR HANDLING
                # ========================================
                # Display form validation errors to user
                error_message = "Please correct the following errors:"
                for field_name, field_errors in profile_update_form.errors.items():
                    error_message += f" {field_name}: {', '.join(field_errors)}"
                
                messages.error(request, error_message)

        except Exception as form_processing_error:
            # ========================================
            # GENERAL FORM PROCESSING ERROR HANDLING
            # ========================================
            # Log the error for debugging (in production, use proper logging)
            print(f"Unexpected error in profile update form processing: {form_processing_error}")
            messages.error(request, "An unexpected error occurred while processing your request. Please try again.")

    # ========================================
    # GET REQUEST HANDLING (FORM DISPLAY)
    # ========================================
    else:
        # Initialize form with existing user data for display
        profile_update_form = UserUpdateForm(instance=current_user)

    # ========================================
    # TEMPLATE RENDERING
    # ========================================
    # Render update profile template with form and user data
    return render(request, 'update_profile.html', {
        'form': profile_update_form,
        'user': current_user,
        'page_title': 'Update Profile'
    })

import matplotlib
matplotlib.use('Agg')  # Use a non-interactive backend
from django.contrib import messages
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from .models import Vote, HealthCard, Session, User
import matplotlib.pyplot as plt
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas

from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
import io, base64

# @login_required
from django.views.decorators.csrf import csrf_protect
from django.shortcuts import render, redirect, get_object_or_404
from .models import User, Session, Vote, HealthCard
import io
import base64
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import matplotlib.pyplot as plt

@csrf_protect
def team_summary(request):
    """
    Handle team summary display with interactive charts and filtering.
    
    This function provides both individual and team vote summaries with:
    - Session and health card filtering
    - Chart.js data preparation for interactive charts
    - Individual and team view modes
    - Dynamic data based on selected filters
    
    Args:
        request: HTTP request object containing filter parameters
        
    Returns:
        Rendered template with chart data and filter options
    """
    # ========================================
    # INITIAL SETUP AND VALIDATION
    # ========================================
    # Get user from session and validate authentication
    current_user_id = request.session.get('user_id')
    if not current_user_id:
        messages.error(request, "You must be logged in to view summaries.")
        return redirect('engineer-login')

    # Fetch user and team information
    try:
        current_user = get_object_or_404(User, user_id=current_user_id)
        current_team = current_user.team
    except Http404:
        messages.error(request, "User not found. Please log in again.")
        return redirect('engineer-login')

    # ========================================
    # FILTER PARAMETERS EXTRACTION
    # ========================================
    # Get filter parameters from request
    selected_session_id = request.POST.get('session_id') or request.GET.get('session_id')
    selected_health_card_id = request.POST.get('card') or request.GET.get('card')
    selected_view_type = request.POST.get('view_type') or 'team'

    # Fetch all available sessions and health cards
    available_sessions = Session.objects.all().order_by('-created_at')
    available_health_cards = HealthCard.objects.all()

    # ========================================
    # SESSION SELECTION AND VALIDATION
    # ========================================
    # Determine which session to use
    current_session = None
    if selected_session_id:
        try:
            current_session = get_object_or_404(Session, session_id=selected_session_id)
        except Http404:
            messages.error(request, "Selected session not found.")
            current_session = available_sessions.first() if available_sessions.exists() else None
    elif available_sessions.exists():
        current_session = available_sessions.first()

    # Handle case where no sessions are available
    if not current_session:
        return render(request, 'team_summary.html', {
            'user': current_user,
            'cards': available_health_cards,
            'sessions': available_sessions,
            'no_sessions': True,
            'chart_data': None,
            'view_type': selected_view_type,
        })

    # ========================================
    # CHART DATA PREPARATION
    # ========================================
    chart_data = None
    no_votes = False

    if selected_view_type == 'individual':
        # ========================================
        # INDIVIDUAL VIEW DATA PREPARATION
        # ========================================
        # Get user's votes for the selected session
        user_votes = Vote.objects.filter(session=current_session, user=current_user)
        
        if selected_health_card_id:
            # Filter by specific health card
            try:
                selected_card = available_health_cards.get(card_id=selected_health_card_id)
                user_votes = user_votes.filter(card=selected_card)
                
                # Prepare data for single card chart
                vote_counts = {
                    'green': user_votes.filter(vote_value=1).count(),
                    'amber': user_votes.filter(vote_value=2).count(),
                    'red': user_votes.filter(vote_value=3).count()
                }
                
                if sum(vote_counts.values()) > 0:
                    chart_data = {
                        'type': 'individual_single_card',
                        'labels': [selected_card.title],
                        'datasets': [
                            {
                                'label': 'Green',
                                'data': [vote_counts['green']],
                                'backgroundColor': '#28a745',
                                'borderColor': '#28a745',
                                'borderWidth': 1
                            },
                            {
                                'label': 'Amber',
                                'data': [vote_counts['amber']],
                                'backgroundColor': '#ffc107',
                                'borderColor': '#ffc107',
                                'borderWidth': 1
                            },
                            {
                                'label': 'Red',
                                'data': [vote_counts['red']],
                                'backgroundColor': '#dc3545',
                                'borderColor': '#dc3545',
                                'borderWidth': 1
                            }
                        ],
                        'title': f"{current_user.username}'s Vote for {selected_card.title}",
                        'subtitle': f"Session: {current_session.date.strftime('%B %d, %Y')}"
                    }
                else:
                    no_votes = True
                    
            except HealthCard.DoesNotExist:
                messages.error(request, "Selected health card not found.")
            no_votes = True
        else:
            # Show all cards for individual
            card_data = []
            card_labels = []
            
            for card in available_health_cards:
                card_votes = user_votes.filter(card=card)
                card_data.append({
                    'green': card_votes.filter(vote_value=1).count(),
                    'amber': card_votes.filter(vote_value=2).count(),
                    'red': card_votes.filter(vote_value=3).count()
                })
                card_labels.append(card.title)
            
            # Check if any votes exist
            total_votes = sum(sum(card.values()) for card in card_data)
            if total_votes > 0:
                chart_data = {
                    'type': 'individual_all_cards',
                    'labels': card_labels,
                    'datasets': [
                        {
                            'label': 'Green',
                            'data': [card['green'] for card in card_data],
                            'backgroundColor': '#28a745',
                            'borderColor': '#28a745',
                            'borderWidth': 1
                        },
                        {
                            'label': 'Amber',
                            'data': [card['amber'] for card in card_data],
                            'backgroundColor': '#ffc107',
                            'borderColor': '#ffc107',
                            'borderWidth': 1
                        },
                        {
                            'label': 'Red',
                            'data': [card['red'] for card in card_data],
                            'backgroundColor': '#dc3545',
                            'borderColor': '#dc3545',
                            'borderWidth': 1
                        }
                    ],
                    'title': f"{current_user.username}'s Vote Summary",
                    'subtitle': f"Session: {current_session.date.strftime('%B %d, %Y')}"
                }
            else:
                no_votes = True

    elif selected_view_type == 'team':
        # ========================================
        # TEAM VIEW DATA PREPARATION
        # ========================================
        if selected_health_card_id:
            # Filter by specific health card for team
            try:
                selected_card = available_health_cards.get(card_id=selected_health_card_id)
                team_votes = Vote.objects.filter(
                    session=current_session, 
                    card=selected_card, 
                    team=current_team
                )
                
                vote_counts = {
                    'green': team_votes.filter(vote_value=1).count(),
                    'amber': team_votes.filter(vote_value=2).count(),
                    'red': team_votes.filter(vote_value=3).count()
                }
                
                if sum(vote_counts.values()) > 0:
                    chart_data = {
                        'type': 'team_single_card',
                        'labels': [selected_card.title],
                        'datasets': [
                            {
                                'label': 'Green',
                                'data': [vote_counts['green']],
                                'backgroundColor': '#28a745',
                                'borderColor': '#28a745',
                                'borderWidth': 1
                            },
                            {
                                'label': 'Amber',
                                'data': [vote_counts['amber']],
                                'backgroundColor': '#ffc107',
                                'borderColor': '#ffc107',
                                'borderWidth': 1
                            },
                            {
                                'label': 'Red',
                                'data': [vote_counts['red']],
                                'backgroundColor': '#dc3545',
                                'borderColor': '#dc3545',
                                'borderWidth': 1
                            }
                        ],
                        'title': f"Team Votes for {selected_card.title}",
                        'subtitle': f"Session: {current_session.date.strftime('%B %d, %Y')}"
                    }
                else:
                    no_votes = True

            except HealthCard.DoesNotExist:
                messages.error(request, "Selected health card not found.")
                no_votes = True
        else:
            # Show all cards for team
            card_data = []
            card_labels = []
            
            for card in available_health_cards:
                card_votes = Vote.objects.filter(
                    session=current_session, 
                    card=card, 
                    team=current_team
                )
                card_data.append({
                    'green': card_votes.filter(vote_value=1).count(),
                    'amber': card_votes.filter(vote_value=2).count(),
                    'red': card_votes.filter(vote_value=3).count()
                })
                card_labels.append(card.title)
            
            # Check if any votes exist
            total_votes = sum(sum(card.values()) for card in card_data)
            if total_votes > 0:
                chart_data = {
                    'type': 'team_all_cards',
                    'labels': card_labels,
                    'datasets': [
                        {
                            'label': 'Green',
                            'data': [card['green'] for card in card_data],
                            'backgroundColor': '#28a745',
                            'borderColor': '#28a745',
                            'borderWidth': 1
                        },
                        {
                            'label': 'Amber',
                            'data': [card['amber'] for card in card_data],
                            'backgroundColor': '#ffc107',
                            'borderColor': '#ffc107',
                            'borderWidth': 1
                        },
                        {
                            'label': 'Red',
                            'data': [card['red'] for card in card_data],
                            'backgroundColor': '#dc3545',
                            'borderColor': '#dc3545',
                            'borderWidth': 1
                        }
                    ],
                    'title': f"Team Vote Summary - All Cards",
                    'subtitle': f"Session: {current_session.date.strftime('%B %d, %Y')}"
                }
            else:
                no_votes = True

    # ========================================
    # CONTEXT PREPARATION AND RESPONSE
    # ========================================
    context = {
        'user': current_user,
        'cards': available_health_cards,
        'sessions': available_sessions,
        'selected_session_id': current_session.session_id,
        'selected_card_id': selected_health_card_id,
        'view_type': selected_view_type,
        'chart_data': chart_data,
        'no_votes': no_votes,
        'no_sessions': False,
    }

    return render(request, 'team_summary.html', context)



#################################### TEAM LEADER ###############################################

def tl_dashboard(request):
    return render(request, 'tl_dashboard.html')
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages
from .models import Session, User

@csrf_protect
def tl_manage_sessions(request):
    sessions = Session.objects.all().order_by('-created_at')
    active_session_id = request.session.get('tl_active_session_id')
    active_session = None

    if active_session_id:
        try:
            active_session = Session.objects.get(session_id=active_session_id)
            if active_session.date < timezone.now():
                # Expired, so deactivate it
                request.session.pop('tl_active_session_id', None)
                active_session = None
                messages.error(request, "Your active session has expired and was deactivated.")

        except Session.DoesNotExist:
            request.session.pop('tl_active_session_id', None)


    return render(request, 'tl_sessions.html', {
        'sessions': sessions,
        'active_session': active_session,
    })

@csrf_protect
def tl_select_session(request, session_id):
    if request.method == 'POST':
        session = get_object_or_404(Session, session_id=session_id)

        if session.is_expired():
            messages.error(request, "This session has expired and cannot be activated.")
            return redirect('tl-manage-sessions')

        request.session['tl_active_session_id'] = session.session_id
        messages.success(request, f"Session {session.date} activated.")
    return redirect('tl-manage-sessions')

@csrf_protect
def tl_deactivate_session(request):
    if request.method == 'POST':
        request.session.pop('tl_active_session_id', None)
        messages.success(request, "Active session deactivated.")
    return redirect('tl-manage-sessions')

# @login_required
def tl_voting_guidance(request):
    return render(request, 'tl_voting_guidance.html', {
        'vote_url': 'tl-vote'
    })


@csrf_protect
def tl_vote_page(request):
    """
    Handle team leader voting functionality for health check assessments.
    
    This function processes vote submissions from team leaders, including:
    - Form validation and data sanitization
    - Duplicate vote detection and updates
    - New vote creation
    - Session and user authentication checks
    
    Args:
        request: HTTP request object containing form data and session info
        
    Returns:
        Rendered template with success/error messages and form data
        
    Raises:
        Http404: If user or session not found in database
    """
    # ========================================
    # INITIAL DATA FETCHING AND VALIDATION
    # ========================================
    # Fetch all available teams and health cards for form dropdowns
    available_teams = Team.objects.all()
    available_health_cards = HealthCard.objects.all()
    
    # Get active session and user info from session storage
    current_active_session_id = request.session.get('tl_active_session_id')
    current_user_id = request.session.get('user_id')

    # ========================================
    # AUTHENTICATION AND SESSION VALIDATION
    # ========================================
    # Check if user is logged in
    if not current_user_id:
        messages.error(request, "You must be logged in to submit votes.")
        return redirect('tl-login')

    # Check if user has an active session for voting
    if not current_active_session_id:
        messages.error(request, "Please activate a session before submitting votes.")
        return redirect('tl-manage-sessions')

    # Fetch user and session objects from database
    try:
        current_user = get_object_or_404(User, user_id=current_user_id)
        current_session = get_object_or_404(Session, session_id=current_active_session_id)
    except Http404 as e:
        messages.error(request, "Invalid session or user data. Please log in again.")
        return redirect('tl-login')

    # ========================================
    # FORM PROCESSING (POST REQUEST HANDLING)
    # ========================================
    if request.method == 'POST':
        try:
            # Extract and sanitize form data
            selected_team_id = request.POST.get('team')
            selected_health_card_id = request.POST.get('card')
            selected_vote_value = request.POST.get('vote_value')
            selected_progress_trend = request.POST.get('progress_note', '').strip()

            # ========================================
            # FORM VALIDATION
            # ========================================
            # Check if all required fields are provided
            if not all([selected_team_id, selected_health_card_id, selected_vote_value]):
                messages.error(request, "All fields are required. Please fill in team, health card, and vote selection.")
                return render(request, 'tl_vote.html', {
                    'teams': available_teams,
                    'cards': available_health_cards,
                    'user': current_user,
                    'session': current_session,
                })

            # Validate vote value is within acceptable range (1-3)
            try:
                vote_value_integer = int(selected_vote_value)
                if vote_value_integer not in [1, 2, 3]:
                    raise ValueError("Invalid vote value")
            except (ValueError, TypeError):
                messages.error(request, "Invalid vote selection. Please choose Green, Amber, or Red.")
                return render(request, 'tl_vote.html', {
                    'teams': available_teams,
                    'cards': available_health_cards,
                    'user': current_user,
                    'session': current_session,
                })

            # Validate progress trend is one of the allowed values
            allowed_progress_trends = ['Up trend', 'Down trend', 'No change']
            if selected_progress_trend not in allowed_progress_trends:
                messages.error(request, "Invalid progress trend selection.")
                return render(request, 'tl_vote.html', {
                    'teams': available_teams,
                    'cards': available_health_cards,
                    'user': current_user,
                    'session': current_session,
                })

            # ========================================
            # DATABASE OBJECT FETCHING
            # ========================================
            # Fetch team and health card objects from database
            try:
                selected_team = get_object_or_404(Team, pk=selected_team_id)
                selected_health_card = get_object_or_404(HealthCard, pk=selected_health_card_id)
            except Http404:
                messages.error(request, "Selected team or health card not found. Please try again.")
                return render(request, 'tl_vote.html', {
                    'teams': available_teams,
                    'cards': available_health_cards,
                    'user': current_user,
                    'session': current_session,
                })

            # ========================================
            # DUPLICATE VOTE DETECTION AND HANDLING
            # ========================================
            # Check if user has already voted for this combination
            existing_vote_record = Vote.objects.filter(
                user=current_user,
                session=current_session,
                team=selected_team,
                card=selected_health_card
            ).first()

            if existing_vote_record:
                # ========================================
                # UPDATE EXISTING VOTE
                # ========================================
                try:
                    existing_vote_record.vote_value = vote_value_integer
                    existing_vote_record.progress_note = selected_progress_trend
                    existing_vote_record.save()
                    
                    messages.success(request, f"Your vote for {selected_health_card.title} has been updated successfully.")
                    
                except Exception as vote_update_error:
                    # Log the error for debugging (in production, use proper logging)
                    print(f"Error updating vote: {vote_update_error}")
                    messages.error(request, "Failed to update your vote. Please try again.")
            else:
                # ========================================
                # CREATE NEW VOTE RECORD
                # ========================================
                try:
                    Vote.objects.create(
                        user=current_user,
                        session=current_session,
                        team=selected_team,
                        card=selected_health_card,
                        vote_value=vote_value_integer,
                        progress_note=selected_progress_trend,
                        created_at=timezone.now()
                    )
                    
                    messages.success(request, f"Your vote for {selected_health_card.title} has been submitted successfully.")
                    
                except Exception as vote_creation_error:
                    # Log the error for debugging (in production, use proper logging)
                    print(f"Error creating vote: {vote_creation_error}")
                    messages.error(request, "Failed to submit your vote. Please try again.")

            # ========================================
            # SUCCESS RESPONSE
            # ========================================
            # Return the form with success message and current data
            return render(request, 'tl_vote.html', {
                'teams': available_teams,
                'cards': available_health_cards,
                'user': current_user,
                'session': current_session,
            })

        except Exception as form_processing_error:
            # ========================================
            # GENERAL ERROR HANDLING
            # ========================================
            # Log the error for debugging (in production, use proper logging)
            print(f"Unexpected error in vote processing: {form_processing_error}")
            messages.error(request, "An unexpected error occurred. Please try again.")

    # ========================================
    # GET REQUEST HANDLING (FORM DISPLAY)
    # ========================================
    # Display the voting form for GET requests
    return render(request, 'tl_vote.html', {
        'teams': available_teams,
        'cards': available_health_cards,
        'user': current_user,
        'session': current_session,
    })

# @login_required
def select_team_view(request):
    if 'user_id' not in request.session or request.session.get('role') != 'Team Leader':
        return redirect('tl-login')

    user = get_object_or_404(User, user_id=request.session['user_id'])

    if request.method == 'POST':
        team_id = request.POST.get('team_id')
        card_id = request.POST.get('card_id')

        try:
            selected_team = get_object_or_404(Team, team_id=team_id)
            selected_card = get_object_or_404(HealthCard, card_id=card_id)

            # Save team and department to user
            user.team = selected_team
            user.department = selected_team.department
            user.save()

            # Save selections to session
            request.session['selected_team_id'] = selected_team.team_id
            request.session['selected_card_id'] = selected_card.card_id

            messages.success(request, 'Team and Health Card selected successfully!')
            return redirect('team-leader-summary')
        except Exception as e:
            messages.error(request, f'Error selecting team or card: {str(e)}')


    # If no team or department assigned to user yet, show all teams
    if not user.team or not user.department:
        teams = Team.objects.all()
        team_list_heading = "All Teams"
    else:
        teams = Team.objects.filter(department=user.department)
        team_list_heading = f"Teams in Your Department: {user.department.name}"

    all_cards = HealthCard.objects.all()

    return render(request, 'select_team.html', {
        'teams': teams,
        'cards': all_cards,
        'user': user,
        'team_list_heading': team_list_heading,
    })


# @login_required
@csrf_protect
def team_leader_summary(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('engineer-login')

    # Retrieve the user and the team they belong to
    user = get_object_or_404(User, user_id=user_id)
    team = user.team
    team_sessions = Session.objects.all().order_by('-created_at')

    # Get the selected session from POST/GET or fallback to active session in session storage
    selected_session_id = request.POST.get('session_id') or request.GET.get('session_id') or request.session.get('tl_active_session_id')

    # If no session is selected, fallback to the first available session
    if selected_session_id:
        request.session['tl_active_session_id'] = selected_session_id
        session = get_object_or_404(Session, session_id=selected_session_id)
    elif team_sessions.exists():
        session = team_sessions.first()
        request.session['tl_active_session_id'] = session.session_id
    else:
        messages.warning(request, 'No sessions available.')

        return render(request, 'tl_summary.html', {
            'user': user,
            'sessions': team_sessions,
            'no_sessions': True,
        })

    # Get the cards (health cards) for the session
    cards = HealthCard.objects.all()
    chart_img_individual = chart_img_selected = chart_img_all = None
    no_votes = False

    # Determine the type of view (individual/team)
    view_type = request.POST.get('view_type') or 'team'
    selected_card_id = request.POST.get('card')

    # Handle individual view
    if view_type == 'individual':
        print("Found votes:", Vote.objects.filter(session=session, user=user))  # all votes

        votes = Vote.objects.filter(session=session, user=user)
        red_data, amber_data, green_data, card_titles = [], [], [], []

        for card in cards:
            v = votes.filter(card=card)
            red_data.append(v.filter(vote_value=3).count())
            amber_data.append(v.filter(vote_value=2).count())
            green_data.append(v.filter(vote_value=1).count())
            card_titles.append(card.title)

        if sum(red_data + amber_data + green_data) == 0:
            no_votes = True
        else:
            fig, ax = plt.subplots(figsize=(10, 6))
            x = range(len(card_titles))
            ax.bar(x, green_data, label='Green', color='green')
            ax.bar(x, amber_data, bottom=green_data, label='Amber', color='#FFBF00')
            ax.bar(x, red_data, bottom=[g + y for g, y in zip(green_data, amber_data)], label='Red', color='red')
            ax.set_xticks(x)
            ax.set_xticklabels(card_titles, rotation=45, ha='right')
            ax.set_ylabel('Votes')
            ax.set_title(f"{user.username}'s Vote Summary - {session.date}")
            ax.legend()

            buf = io.BytesIO()
            FigureCanvas(fig).print_png(buf)
            chart_img_individual = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

    # Handle team view
    elif view_type == 'team':
        if selected_card_id:
            try:
                selected_card = cards.get(card_id=selected_card_id)
                votes = Vote.objects.filter(session=session, card=selected_card, team=team)
                red = votes.filter(vote_value=3).count()
                amber = votes.filter(vote_value=2).count()
                green = votes.filter(vote_value=1).count()

                if red + amber + green == 0:
                    no_votes = True
                else:
                    fig1, ax1 = plt.subplots()
                    ax1.bar(selected_card.title, green, color='green', label='Green')
                    ax1.bar(selected_card.title, Amber, bottom=green, color='#FFBF00', label='Amber')
                    ax1.bar(selected_card.title, red, bottom=green + Amber, color='red', label='Red')
                    ax1.set_title(f"Votes for {selected_card.title} - {session.date}")
                    ax1.legend()

                    buf1 = io.BytesIO()
                    FigureCanvas(fig1).print_png(buf1)
                    chart_img_selected = base64.b64encode(buf1.getvalue()).decode('utf-8')
                    plt.close(fig1)

            except HealthCard.DoesNotExist:
                no_votes = True
        else:
            red_data, Amber_data, green_data, card_titles = [], [], [], []

            for card in cards:
                print("Found votes with team:", Vote.objects.filter(session=session, card=card, team=team))  # filtered

                votes = Vote.objects.filter(session=session, card=card, team=team)
                red_data.append(votes.filter(vote_value=3).count())
                Amber_data.append(votes.filter(vote_value=2).count())
                green_data.append(votes.filter(vote_value=1).count())
                card_titles.append(card.title)

            if sum(red_data + Amber_data + green_data) == 0:
                no_votes = True
            else:
                fig2, ax2 = plt.subplots(figsize=(10, 6))
                x = range(len(card_titles))
                ax2.bar(x, green_data, label='Green', color='green')
                ax2.bar(x, Amber_data, bottom=green_data, label='Amber', color='#FFBF00')
                ax2.bar(x, red_data, bottom=[g + y for g, y in zip(green_data, Amber_data)], label='Red', color='red')
                ax2.set_xticks(x)
                ax2.set_xticklabels(card_titles, rotation=45, ha='right')
                ax2.set_ylabel('Votes')
                ax2.set_title(f"Team Vote Summary - All Cards ({session.date})")
                ax2.legend()

                buf2 = io.BytesIO()
                FigureCanvas(fig2).print_png(buf2)
                chart_img_all = base64.b64encode(buf2.getvalue()).decode('utf-8')
                plt.close(fig2)

    
    return render(request, 'tl_summary.html', {
    'user': user,
    'cards': cards,
    'sessions': team_sessions,
    'selected_session_id': session.session_id,
    'selected_card_id': selected_card_id,
    'view_type': view_type,
    'chart_img_individual': chart_img_individual,
    'chart_img_team_card': chart_img_selected,   # <-- Fix here
    'chart_img_team_all': chart_img_all,         # <-- And here
    'no_votes': no_votes,
    'no_sessions': False,
})




from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import User

# @login_required
def team_leader_profile_view(request):
    # Get the user_id from the session
    user_id = request.session.get('user_id')

    # Fetch the user from the database using the user_id
    try:
        user = User.objects.get(user_id=user_id)
    except User.DoesNotExist:
        messages.error(request, 'User not found.')
        return render(request, 'error.html', {'error': 'User not found.'})


    # Pass the user data to the template
    return render(request, 'tl_profile.html', {'user': user})

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .forms import UserUpdateForm
from .models import User
# @login_required
def team_leader_profile_update(request):
    user_id = request.session.get('user_id')  # Get user from session

    if not user_id:
        messages.error(request, 'You need to be logged in to update your profile.')
        return redirect('team-leader-login')  # Redirect to login if no user is logged in

    try:
        user = User.objects.get(user_id=user_id)  # Fetch user based on session data
    except User.DoesNotExist:
        messages.error(request, 'User not found.')

        return render(request, 'error.html', {'error': 'User not found.'})  # Handle case if user is not found

    if request.method == 'POST':
        form = UserUpdateForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('team-leader-profile')
        
        else:
            messages.error(request, 'There was an error in updating your profile.')
    else:
        form = UserUpdateForm(instance=user)

    print(form.fields)  # Print form fields for debugging

    return render(request, 'tl_update_profile.html', {'form': form, 'user': user})

from django.db.models import Avg
from .models import Vote, ProgressSummary, HealthCard, Session, Team
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render, get_object_or_404
from django.contrib import messages
from .models import Team, Session, User  # make sure User is imported
# from .utils import generate_progress_summary  # assuming logic lives here

from django.db.models import Avg
from .models import Vote, ProgressSummary, HealthCard, Team, Session

def generate_progress_summary(team_id, session_id):
    team = Team.objects.get(pk=team_id)
    session = Session.objects.get(pk=session_id)
    cards = HealthCard.objects.all()

    has_votes = False  # Track if any card has votes

    for card in cards:
        votes = Vote.objects.filter(team=team, session=session, card=card)
        vote_count = votes.count()

        if vote_count == 0:
            continue

        has_votes = True  # At least one card has votes

        avg_vote = votes.aggregate(avg=Avg('vote_value'))['avg']
        if avg_vote is None:
            continue

        # Classify vote
        if avg_vote <= 1.5:
            overall_vote = 'Green'
        elif avg_vote <= 2.5:
            overall_vote = 'Amber'
        else:
            overall_vote = 'Red'

        # Get previous summary
        previous_summary = ProgressSummary.objects.filter(
            team=team,
            card=card
        ).exclude(session=session).order_by('-session__created_at').first()

        vote_map = {'Red': 3, 'Amber': 2, 'Green': 1}
        progress_trend = True

        if previous_summary:
            progress_trend = vote_map[overall_vote] <= vote_map[previous_summary.overall_vote]

        # Always delete old summary for this team/session/card (if any)
        ProgressSummary.objects.filter(team=team, session=session, card=card).delete()

        # Create updated summary
        ProgressSummary.objects.create(
            team=team,
            session=session,
            card=card,
            overall_vote=overall_vote.strip(),
            progress_trend=progress_trend
        )


    return has_votes  # Return status for view to use

# @login_required
@login_required
def generate_summary_view(request):
    summaries = []
    selected_session_id = None
    selected_session = None
    team = None

    if request.method == 'POST':
        session_id = request.POST.get('session_id')
        selected_session_id = int(session_id)
        selected_session = get_object_or_404(Session, pk=session_id)

        user_id = request.session.get('user_id')
        user = get_object_or_404(User, user_id=user_id)

        team = user.team

        has_votes = generate_progress_summary(team.team_id, session_id)

        if has_votes:
            messages.success(request, 'Progress Summary generated successfully.')
        else:
            messages.warning(request, 'No votes found for your team in this session.')

        summaries = ProgressSummary.objects.filter(
            team=team, session=selected_session
        ).select_related('card')

    sessions = Session.objects.all()

    return render(request, 'tl_generate_summary.html', {
        'sessions': sessions,
        'summaries': summaries,
        'selected_session_id': selected_session_id,
        'selected_session': selected_session,
        'team': team,
    })


from django.shortcuts import render, get_object_or_404
from .models import ProgressSummary, HealthCard, Team, Session
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
# @login_required

def engineer_progress_form(request):
    """
    Handle engineer progress view functionality with team progress and vote history.
    
    This function provides two main views:
    1. Team Progress View: Shows team summary for selected session and health card
    2. Vote History View: Shows engineer's complete voting history
    
    The function handles both GET requests for form display and data filtering,
    including session validation, database queries, and error handling.
    
    Args:
        request: HTTP request object containing query parameters and session data
        
    Returns:
        Rendered engineer progress view template with filtered data
        
    Raises:
        Http404: If user, health card, or session not found in database
    """
    # ========================================
    # INITIAL DATA FETCHING AND VALIDATION
    # ========================================
    # Fetch all available health cards and sessions for form dropdowns
    available_health_cards = HealthCard.objects.all()
    available_sessions = Session.objects.all()
    
    # Extract filter parameters from request
    selected_health_card_id = request.GET.get('card_id')
    selected_session_id = request.GET.get('session_id')
    current_view_mode = request.GET.get('view', 'team')  # 'team' or 'history'

    # ========================================
    # USER AUTHENTICATION AND TEAM FETCHING
    # ========================================
    # Get current user from session
    current_user_id = request.session.get('user_id')
    
    # Validate user authentication
    if not current_user_id:
        messages.error(request, "You must be logged in to view progress.")
        return redirect('engineer-login')

    # Fetch user and team information
    try:
        current_user = get_object_or_404(User, user_id=current_user_id)
        current_user_team = current_user.team
    except Http404:
        messages.error(request, "User not found. Please log in again.")
        return redirect('engineer-login')
    except Exception as user_fetch_error:
        # Handle unexpected database errors
        print(f"Database error fetching user in engineer_progress_form: {user_fetch_error}")
        messages.error(request, "An error occurred while loading your profile. Please try again.")
        return render(request, 'error.html', {
            'error': 'Unable to load user data. Please try again later.',
            'error_code': 'DATABASE_ERROR'
        })

    # ========================================
    # VARIABLE INITIALIZATION
    # ========================================
    # Initialize variables for team progress view
    team_progress_summary = None
    current_user_vote = None
    should_show_results = False
    selected_health_card = None
    selected_session = None
    
    # Initialize variable for vote history view
    user_vote_history = None

    # ========================================
    # VIEW MODE PROCESSING
    # ========================================
    if current_view_mode == 'history':
        # ========================================
        # VOTE HISTORY VIEW PROCESSING
        # ========================================
        try:
            # Fetch user's complete voting history with related data
            user_vote_history = Vote.objects.filter(
                user=current_user
            ).select_related(
                'card', 
                'session', 
                'team'
            ).order_by('-session__date', '-created_at')
            
        except Exception as history_fetch_error:
            # Handle database errors when fetching vote history
            print(f"Error fetching vote history: {history_fetch_error}")
            messages.error(request, "Unable to load your voting history. Please try again.")
            user_vote_history = []
            
    elif selected_health_card_id and selected_session_id:
        # ========================================
        # TEAM PROGRESS VIEW PROCESSING
        # ========================================
        try:
            # Fetch selected health card and session objects
            selected_health_card = get_object_or_404(HealthCard, pk=selected_health_card_id)
            selected_session = get_object_or_404(Session, pk=selected_session_id)
            
        except Http404 as not_found_error:
            # Handle case where health card or session doesn't exist
            messages.error(request, "Selected health card or session not found. Please try again.")
            return render(request, 'engineer_progress_view.html', {
                'cards': available_health_cards,
                'sessions': available_sessions,
                'view_mode': current_view_mode,
                'team': current_user_team,
                'vote_history': [],
                'error_message': 'Selected data not found'
            })
        except Exception as data_fetch_error:
            # Handle unexpected database errors
            print(f"Error fetching health card or session: {data_fetch_error}")
            messages.error(request, "An error occurred while loading the selected data. Please try again.")
            return render(request, 'error.html', {
                'error': 'Unable to load selected data. Please try again later.',
                'error_code': 'DATA_FETCH_ERROR'
            })

        # ========================================
        # TEAM PROGRESS SUMMARY FETCHING
        # ========================================
        try:
            # Fetch team progress summary for the selected combination
            team_progress_summary = ProgressSummary.objects.get(
                team=current_user_team,
                card=selected_health_card,
                session=selected_session
            )
        except ProgressSummary.DoesNotExist:
            # Handle case where no progress summary exists for this combination
            team_progress_summary = None
            messages.info(request, "No progress summary available for the selected team, card, and session combination.")
        except Exception as summary_fetch_error:
            # Handle unexpected database errors
            print(f"Error fetching progress summary: {summary_fetch_error}")
            messages.error(request, "Unable to load progress summary. Please try again.")
            team_progress_summary = None

        # ========================================
        # USER VOTE FETCHING
        # ========================================
        try:
            # Fetch user's vote for the selected combination
            current_user_vote = Vote.objects.filter(
                user=current_user,
                card=selected_health_card,
                session=selected_session
            ).first()
        except Exception as vote_fetch_error:
            # Handle unexpected database errors
            print(f"Error fetching user vote: {vote_fetch_error}")
            messages.error(request, "Unable to load your vote data. Please try again.")
            current_user_vote = None

        # Mark that results should be displayed
        should_show_results = True

    # ========================================
    # TEMPLATE CONTEXT PREPARATION
    # ========================================
    # Prepare context data for template rendering
    template_context = {
        'cards': available_health_cards,
        'sessions': available_sessions,
        'summary': team_progress_summary,
        'engineer_vote': current_user_vote,
        'selected_card': selected_health_card,
        'selected_session': selected_session,
        'selected_card_id': int(selected_health_card_id) if selected_health_card_id else None,
        'selected_session_id': int(selected_session_id) if selected_session_id else None,
        'team': current_user_team,
        'show_results': should_show_results,
        'vote_history': user_vote_history,
        'view_mode': current_view_mode,
    }

    # ========================================
    # TEMPLATE RENDERING
    # ========================================
    # Render the engineer progress view template with prepared context
    return render(request, 'engineer_progress_view.html', template_context)

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Avg
from .models import ProgressSummary, HealthCard, Team, Session, Vote, User


from django.shortcuts import get_object_or_404
from django.db.models import Avg
from .models import Vote, ProgressSummary, Session, HealthCard, Team

def generate_department_progress_summary(department_id, session_id):
    session = get_object_or_404(Session, pk=session_id)
    teams = Team.objects.filter(department_id=department_id)
    cards = HealthCard.objects.all()

    has_votes = False

    # --- Team-level summaries ---
    for team in teams:
        for card in cards:
            votes = Vote.objects.filter(team=team, session=session, card=card)
            if not votes.exists():
                continue

            has_votes = True
            avg_vote = votes.aggregate(avg=Avg('vote_value'))['avg']
            if avg_vote is None:
                continue

            overall_vote = (
                'Green' if avg_vote <= 1.5 else
                'Amber' if avg_vote <= 2.5 else
                'Red'
            )

            prev_summary = ProgressSummary.objects.filter(
                team=team, card=card
            ).exclude(session=session).order_by('-session__created_at').first()

            vote_map = {'Red': 3, 'Amber': 2, 'Green': 1}
            progress_trend = True
            if prev_summary:
                progress_trend = vote_map[overall_vote] <= vote_map[prev_summary.overall_vote]

            ProgressSummary.objects.filter(team=team, session=session, card=card).delete()

            ProgressSummary.objects.create(
                team=team,
                session=session,
                card=card,
                overall_vote=overall_vote,
                progress_trend=progress_trend
            )

    # --- Department-level summaries (team=None) ---
    for card in cards:
        dept_votes = Vote.objects.filter(team__department_id=department_id, session=session, card=card)
        if not dept_votes.exists():
            continue

        has_votes = True
        avg_vote = dept_votes.aggregate(avg=Avg('vote_value'))['avg']
        if avg_vote is None:
            continue

        overall_vote = (
            'Green' if avg_vote <= 1.5 else
            'Amber' if avg_vote <= 2.5 else
            'Red'
        )

        # ✅ Removed invalid session__team__department_id lookup
        prev_summary = ProgressSummary.objects.filter(
            team__isnull=True,
            card=card
        ).exclude(session=session).order_by('-session__created_at').first()

        vote_map = {'Red': 3, 'Amber': 2, 'Green': 1}
        progress_trend = True
        if prev_summary:
            progress_trend = vote_map[overall_vote] <= vote_map[prev_summary.overall_vote]

        # Delete existing department summary for this card/session
        ProgressSummary.objects.filter(
            team__isnull=True, session=session, card=card
        ).delete()

        ProgressSummary.objects.create(
            # team=None,
            session=session,
            card=card,
            overall_vote=overall_vote,
            progress_trend=progress_trend
        )

    return has_votes

from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from .models import Session, Vote, ProgressSummary, HealthCard, Team, User
# from .utils import generate_department_progress_summary  # or wherever it's defined

def dl_generate_summary_view(request):
    summaries = []
    dept_summaries = []
    selected_session_id = None
    selected_session = None

    user_id = request.session.get('user_id')
    user = get_object_or_404(User, user_id=user_id)

    if request.method == 'POST':
        session_id = request.POST.get('session_id')
        selected_session_id = int(session_id)
        selected_session = get_object_or_404(Session, pk=session_id)

        department_id = user.department_id
        has_votes = generate_department_progress_summary(department_id, session_id)

        if has_votes:
            messages.success(request, 'Department Progress Summary generated successfully.')
        else:
            messages.warning(request, 'No votes found in your department for this session.')

        # ✅ Team-wise summaries (only where team is NOT null)
        summaries = ProgressSummary.objects.filter(
            session=selected_session,
            team__isnull=False,
            team__department_id=department_id
        ).select_related('card', 'team')

        # ✅ Department-wide summary (team is null)
        dept_summaries = ProgressSummary.objects.filter(
            session=selected_session,
            team__isnull=True
        ).select_related('card')

    sessions = Session.objects.all()

    return render(request, 'DL_Progress.html', {
        'sessions': sessions,
        'summaries': summaries,
        'dept_summaries': dept_summaries,
        'selected_session_id': selected_session_id,
        'selected_session': selected_session,
    })


from django.views.decorators.csrf import csrf_protect
from django.shortcuts import render, get_object_or_404, redirect
from .models import User, Session, HealthCard, Vote
import matplotlib.pyplot as plt
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import io
import base64
@csrf_protect
def department_leader_summary(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('engineer-login')

    user = get_object_or_404(User, user_id=user_id)
    department = user.department

    if not department:
        return render(request, 'dl_summary.html', {
            'user': user,
            'error_message': 'You are not assigned to any department.'
        })

    # Allow department leaders to select a department
    departments = Department.objects.all()  # Assuming the model name is Department


    # Department handling
    selected_department_id = request.POST.get('department_id') or department.department_id
    selected_department_id = request.POST.get('department_id') or department.department_id

# Debugging the selected department id
    print("Selected Department ID:", selected_department_id)

    selected_department = get_object_or_404(Department, department_id=selected_department_id)


    # Get sessions and health cards
    sessions = Session.objects.all().order_by('-created_at')
    cards = HealthCard.objects.all()

    # Session and card selection
    selected_session_id = request.POST.get('session_id') or request.GET.get('session_id')
    selected_card_id = request.POST.get('card') or request.GET.get('card')

    selected_session = None
    selected_card = None
    chart_img = None
    no_votes = False

    # Session and card existence check
    if selected_session_id:
        selected_session = get_object_or_404(Session, session_id=selected_session_id)

    if selected_card_id:
        selected_card = get_object_or_404(HealthCard, card_id=selected_card_id)

    # Generate vote chart for a specific card
    if selected_session and selected_card:
        votes = Vote.objects.filter(
            session=selected_session,
            card=selected_card,
            team__department=selected_department
        )

        red = votes.filter(vote_value=3).count()
        amber = votes.filter(vote_value=2).count()
        green = votes.filter(vote_value=1).count()

        if red + amber + green == 0:
            no_votes = True
        else:
            fig, ax = plt.subplots()
            ax.bar(selected_card.title, green, color='green', label='Green')
            ax.bar(selected_card.title, amber, bottom=green, color='#FFBF00', label='Amber')
            ax.bar(selected_card.title, red, bottom=green + amber, color='red', label='Red')
            ax.set_title(f"{selected_department.name} Department Summary | {selected_card.title} ({selected_session.date})")
            ax.legend()

            buf = io.BytesIO()
            FigureCanvas(fig).print_png(buf)
            chart_img = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

    # Generate department-wide vote chart for all cards
    elif selected_session:
        red_data, amber_data, green_data, card_titles = [], [], [], []
        for card in cards:
            votes = Vote.objects.filter(session=selected_session, card=card, team__department=selected_department)
            red_data.append(votes.filter(vote_value=3).count())
            amber_data.append(votes.filter(vote_value=2).count())
            green_data.append(votes.filter(vote_value=1).count())
            card_titles.append(card.title)

        if sum(red_data + amber_data + green_data) == 0:
            no_votes = True
        else:
            fig, ax = plt.subplots(figsize=(10, 6))
            x = range(len(card_titles))
            ax.bar(x, green_data, label='Green', color='green')
            ax.bar(x, amber_data, bottom=green_data, label='Amber', color='#FFBF00')
            ax.bar(x, red_data, bottom=[g + a for g, a in zip(green_data, amber_data)], label='Red', color='red')
            ax.set_xticks(x)
            ax.set_xticklabels(card_titles, rotation=45, ha='right')
            ax.set_ylabel('Votes')
            ax.set_title(f"{selected_department.name} Department Summary - All Cards ({selected_session.date})")
            ax.legend()

            buf = io.BytesIO()
            FigureCanvas(fig).print_png(buf)
            chart_img = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

        messages.success(request, 'Chart generated successfully.')
    else:
        messages.error(request, 'No valid votes found for the selected session and card.')

    return render(request, 'dl_summary.html', {
        'user': user,
        'departments': departments,
        'selected_department_id': selected_department_id,
        'sessions': sessions,
        'cards': cards,
        'selected_session_id': selected_session_id,
        'selected_card_id': selected_card_id,
        'selected_card': selected_card,
        'chart_img': chart_img,
        'no_votes': no_votes
    })

from django.shortcuts import render, get_object_or_404, redirect
from .models import User, Department, Session, HealthCard, Vote
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_protect
import io
import base64
import matplotlib.pyplot as plt
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas

@csrf_protect
def senior_manager_summary(request):
    user_id = request.session.get('user_id')
    if not user_id:
        
        return redirect('engineer-login')

    user = get_object_or_404(User, user_id=user_id)

    if user.role != 'Senior Manager':
        messages.error(request, 'You do not have access to this page.')
        return redirect('engineer-login')

    departments = Department.objects.all()
    sessions = Session.objects.all().order_by('-created_at')
    cards = HealthCard.objects.all()

    # Extract filters from POST
    selected_department_id = request.POST.get('department_id')
    selected_session_id = request.POST.get('session_id')
    selected_card_id = request.POST.get('card')
    selected_team_id = request.POST.get('team_id')

    # Initialize objects
    selected_department = Department.objects.filter(department_id=selected_department_id).first() if selected_department_id else None
    selected_session = Session.objects.filter(session_id=selected_session_id).first() if selected_session_id else None
    selected_card = HealthCard.objects.filter(card_id=selected_card_id).first() if selected_card_id else None
    selected_team = Team.objects.filter(team_id=selected_team_id).first() if selected_team_id else None

    # Determine team list based on department
    if selected_department:
        teams = Team.objects.filter(department=selected_department)
    else:
        teams = Team.objects.all()

    chart_img = None
    no_votes = False

    # Generate chart for specific session + filters
    if selected_session:
        if selected_card:
            vote_filter = {
                'session': selected_session,
                'card': selected_card,
            }

            if selected_team:
                vote_filter['team'] = selected_team
            elif selected_department:
                vote_filter['team__department'] = selected_department

            votes = Vote.objects.filter(**vote_filter)

            red = votes.filter(vote_value=3).count()
            amber = votes.filter(vote_value=2).count()
            green = votes.filter(vote_value=1).count()

            if red + amber + green == 0:
                no_votes = True
            else:
                fig, ax = plt.subplots()
                ax.bar(selected_card.title, green, color='green', label='Green')
                ax.bar(selected_card.title, amber, bottom=green, color='#FFBF00', label='Amber')
                ax.bar(selected_card.title, red, bottom=green + amber, color='red', label='Red')

                title = f"{selected_card.title} ({selected_session.date})"
                if selected_team:
                    title = f"{selected_team.name} | " + title
                elif selected_department:
                    title = f"{selected_department.name} Dept | " + title

                ax.set_title(title)
                ax.legend()

                buf = io.BytesIO()
                FigureCanvas(fig).print_png(buf)
                chart_img = base64.b64encode(buf.getvalue()).decode('utf-8')
                plt.close(fig)
            messages.success(request, 'Chart generated successfully.')

        else:
            red_data, amber_data, green_data, card_titles = [], [], [], []
            for card in cards:
                vote_filter = {
                    'session': selected_session,
                    'card': card,
                }

                if selected_team:
                    vote_filter['team'] = selected_team
                elif selected_department:
                    vote_filter['team__department'] = selected_department

                votes = Vote.objects.filter(**vote_filter)
                red_data.append(votes.filter(vote_value=3).count())
                amber_data.append(votes.filter(vote_value=2).count())
                green_data.append(votes.filter(vote_value=1).count())
                card_titles.append(card.title)

            if sum(red_data + amber_data + green_data) == 0:
                no_votes = True
            else:
                fig, ax = plt.subplots(figsize=(10, 6))
                x = range(len(card_titles))
                ax.bar(x, green_data, label='Green', color='green')
                ax.bar(x, amber_data, bottom=green_data, label='Amber', color='#FFBF00')
                ax.bar(x, red_data, bottom=[g + a for g, a in zip(green_data, amber_data)], label='Red', color='red')
                ax.set_xticks(x)
                ax.set_xticklabels(card_titles, rotation=45, ha='right')
                ax.set_ylabel('Votes')
                

                title = f"All Cards ({selected_session.date})"
                if selected_team:
                    title = f"{selected_team.name} | " + title
                elif selected_department:
                    title = f"{selected_department.name} Dept | " + title

                ax.set_title(title)
                ax.legend()

                buf = io.BytesIO()
                FigureCanvas(fig).print_png(buf)
                chart_img = base64.b64encode(buf.getvalue()).decode('utf-8')
                plt.close(fig)

            messages.success(request, 'Chart generated successfully.')
    else:
        messages.error(request, 'No valid votes found for the selected session.')

    return render(request, 'sm_summary.html', {
        'user': user,
        'departments': departments,
        'selected_department_id': selected_department_id,
        'sessions': sessions,
        'cards': cards,
        'teams': teams,
        'selected_team_id': selected_team_id,
        'selected_session_id': selected_session_id,
        'selected_card_id': selected_card_id,
        'selected_card': selected_card,
        'chart_img': chart_img,
        'no_votes': no_votes
    })


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Department, Team, Session, HealthCard, ProgressSummary

# @login_required
def senior_manager_progress_summary(request):
    user = request.user  # Assuming user is authenticated and is a senior manager

    # Filters from request
    selected_department_id = request.POST.get('department_id')
    selected_team_id = request.POST.get('team_id')
    selected_session_id = request.POST.get('session_id')
    selected_card_id = request.POST.get('card_id')

    # Base queryset
    progress_summaries = ProgressSummary.objects.select_related(
        'team__department', 'session', 'card'
    ).all()

    # Filter by department if selected
    if selected_department_id:
        progress_summaries = progress_summaries.filter(team__department__department_id=selected_department_id)

    # Filter by team if selected
    if selected_team_id:
        progress_summaries = progress_summaries.filter(team__team_id=selected_team_id)

    # Filter by session if selected
    if selected_session_id:
        progress_summaries = progress_summaries.filter(session__session_id=selected_session_id)

    # Filter by card if selected
    if selected_card_id:
        progress_summaries = progress_summaries.filter(card__card_id=selected_card_id)

    # Get all dropdown data
    departments = Department.objects.all()
    teams = Team.objects.all()
    sessions = Session.objects.all().order_by('-date')
    cards = HealthCard.objects.all()

    context = {
        'departments': departments,
        'teams': teams,
        'sessions': sessions,
        'cards': cards,
        'progress_summaries': progress_summaries,
        'selected_department_id': selected_department_id,
        'selected_team_id': selected_team_id,
        'selected_session_id': selected_session_id,
        'selected_card_id': selected_card_id,
    }

    if not progress_summaries.exists():
        messages.error(request, "No progress summaries found for the selected filters.")

    return render(request, 'sm_progress.html', context)

from django.shortcuts import render, redirect
from django.contrib import messages
# from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Avg
from .models import Department, Team, Session, HealthCard, Vote, ProgressSummary

def get_vote_category(avg_score):
    if avg_score >= 2.5:
        return 'Red'
    elif avg_score >= 1.5:
        return 'Amber'
    else:
        return 'Green'

def get_progress_trend(team, card, session, current_vote):
    previous_sessions = Session.objects.filter(date__lt=session.date).order_by('-date')
    for prev_session in previous_sessions:
        try:
            prev_summary = ProgressSummary.objects.get(team=team, card=card, session=prev_session)
            prev_vote = prev_summary.overall_vote
            if current_vote == prev_vote:
                return None  # No Change → skip or don't update trend
            elif current_vote == 'Green' and prev_vote in ['Amber', 'Red']:
                return True   # Up
            elif current_vote == 'Amber' and prev_vote == 'Red':
                return True   # Up
            else:
                return False  # Down
        except ProgressSummary.DoesNotExist:
            continue
    return None  # No previous summary found → No Change
from django.db.models import Avg
from django.contrib import messages

def admin_progress_summary_combined(request):
    if request.method == 'POST':
        session_id = request.POST.get('session_id')

        try:
            session = Session.objects.get(session_id=session_id)
        except Session.DoesNotExist:
            messages.error(request, "Invalid session selected.")
            return redirect('admin_progress_summary_combined')

        teams = Team.objects.all()
        cards = HealthCard.objects.all()

        summary_created = False

        for team in teams:
            for card in cards:
                votes = Vote.objects.filter(session=session, team=team, card=card)
                if votes.exists():
                    summary_created = True  # At least one valid set of votes
                    avg_score = votes.aggregate(avg=Avg('vote_value'))['avg']
                    vote_category = get_vote_category(avg_score)
                    trend = get_progress_trend(team, card, session, vote_category)

                    summary_data = {
                        'overall_vote': vote_category,
                    }
                    if trend is not None:
                        summary_data['progress_trend'] = trend

                    ProgressSummary.objects.update_or_create(
                        team=team,
                        session=session,
                        card=card,
                        defaults=summary_data
                    )

        if summary_created:
            messages.success(request, 'Progress Summaries generated successfully.')
        else:
            messages.warning(request, 'No votes found for the selected session. No summaries were generated.')

        return redirect('admin_progress_summary_combined')

    # Handle GET
    selected_department_id = request.GET.get('department_id')
    selected_team_id = request.GET.get('team_id')
    selected_session_id = request.GET.get('session_id')
    selected_card_id = request.GET.get('card_id')

    summaries = ProgressSummary.objects.select_related('team__department', 'session', 'card')

    if selected_department_id:
        summaries = summaries.filter(team__department__department_id=selected_department_id)
    if selected_team_id:
        summaries = summaries.filter(team__team_id=selected_team_id)
    if selected_session_id:
        summaries = summaries.filter(session__session_id=selected_session_id)
    if selected_card_id:
        summaries = summaries.filter(card__card_id=selected_card_id)

    context = {
        'departments': Department.objects.all(),
        'teams': Team.objects.all(),
        'sessions': Session.objects.all().order_by('-date'),
        'cards': HealthCard.objects.all(),
        'summaries': summaries,
        'selected_department_id': selected_department_id,
        'selected_team_id': selected_team_id,
        'selected_session_id': selected_session_id,
        'selected_card_id': selected_card_id,
    }
    return render(request, 'admin_summary_combined.html', context)
