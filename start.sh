#!/bin/bash

# ACS Assignment Startup Script
# This script helps start the backend and frontend services

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Project root: $PROJECT_ROOT"

# Function to load environment variables from .env file
load_env() {
    local env_file="$PROJECT_ROOT/.env"
    if [ -f "$env_file" ]; then
        # Extract database URL from .env file
        DB_URL=$(grep "^DB_URL=" "$env_file" | cut -d'=' -f2)
        if [ ! -z "$DB_URL" ]; then
            # Parse the database URL: postgresql://user:password@host:port/database
            DB_USER=$(echo "$DB_URL" | sed -n 's|postgresql://\([^:]*\):.*|\1|p')
            DB_PASSWORD=$(echo "$DB_URL" | sed -n 's|postgresql://[^:]*:\([^@]*\)@.*|\1|p')
            DB_HOST=$(echo "$DB_URL" | sed -n 's|postgresql://[^@]*@\([^:]*\):.*|\1|p')
            DB_PORT=$(echo "$DB_URL" | sed -n 's|postgresql://[^@]*@[^:]*:\([^/]*\)/.*|\1|p')
            DB_NAME=$(echo "$DB_URL" | sed -n 's|postgresql://[^/]*/\(.*\)|\1|p')
            
            export PGPASSWORD="$DB_PASSWORD"
            echo "✅ Loaded database credentials from .env file"
            echo "   Database: $DB_NAME on $DB_HOST:$DB_PORT as user $DB_USER"
            return 0
        fi
    fi
    echo "❌ Could not load database credentials from .env file"
    return 1
}

# Function to check if a port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        echo "Port $port is already in use"
        return 1
    fi
    return 0
}

# Function to ensure PostgreSQL is running
ensure_postgresql() {
    echo "=== Checking PostgreSQL ==="
    
    # Check if PostgreSQL is running
    if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
        echo "✅ PostgreSQL is already running"
        echo "🚀 PostgreSQL is ready - skipping startup"
        return 0
    fi
    
    echo "PostgreSQL is not running. Attempting to start..."
    
    # Try different methods to start PostgreSQL based on the system
    if command -v systemctl >/dev/null 2>&1; then
        echo "Starting PostgreSQL using systemctl..."
        if sudo systemctl start postgresql 2>/dev/null; then
            echo "PostgreSQL started via systemctl"
        else
            echo "Failed to start PostgreSQL via systemctl"
        fi
    elif command -v brew >/dev/null 2>&1; then
        echo "Starting PostgreSQL using brew..."
        if brew services start postgresql 2>/dev/null; then
            echo "PostgreSQL started via brew"
        else
            echo "Failed to start PostgreSQL via brew"
        fi
    elif command -v service >/dev/null 2>&1; then
        echo "Starting PostgreSQL using service..."
        if sudo service postgresql start 2>/dev/null; then
            echo "PostgreSQL started via service"
        else
            echo "Failed to start PostgreSQL via service"
        fi
    else
        echo "❌ Could not determine how to start PostgreSQL on this system"
        echo "Please start PostgreSQL manually and try again"
        return 1
    fi
    
    # Wait for PostgreSQL to be ready
    echo "Waiting for PostgreSQL to be ready..."
    for i in {1..10}; do
        if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
            echo "✅ PostgreSQL is now running"
            return 0
        fi
        echo "Waiting... ($i/10)"
        sleep 2
    done
    
    echo "❌ PostgreSQL failed to start or is not responding"
    return 1
}

# Function to ensure database exists and is initialized
ensure_database() {
    echo "=== Checking Database ==="
    
    # Load environment variables including database credentials
    if ! load_env; then
        echo "❌ Failed to load database credentials. Aborting."
        return 1
    fi
    
    # Check if postgres database exists
    if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        echo "✅ Database '$DB_NAME' exists"

        # Check if schema is initialized (look for users table)
        if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "\dt" 2>/dev/null | grep -q users; then
            echo "✅ Database schema is already initialized"
            echo "🚀 Database is ready - skipping initialization"
            return 0
        else
            echo "Database exists but schema not initialized. Running init_schema.sql..."
            if [ -f "$PROJECT_ROOT/shared/init_schema.sql" ]; then
                if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$PROJECT_ROOT/shared/init_schema.sql" >/dev/null 2>&1; then
                    echo "✅ Database schema initialized"
                else
                    echo "❌ Failed to initialize database schema"
                    echo "You may need to run manually: PGPASSWORD='$DB_PASSWORD' psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME < shared/init_schema.sql"
                    return 1
                fi
            else
                echo "❌ Schema file not found: $PROJECT_ROOT/shared/init_schema.sql"
                return 1
            fi
        fi
    else
        echo "Database '$DB_NAME' does not exist. Creating..."
        if PGPASSWORD="$DB_PASSWORD" createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" 2>/dev/null; then
            echo "✅ Database '$DB_NAME' created"

            # Initialize schema for new database
            echo "Initializing schema for new database..."
            if [ -f "$PROJECT_ROOT/shared/init_schema.sql" ]; then
                if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -f "$PROJECT_ROOT/shared/init_schema.sql" >/dev/null 2>&1; then
                    echo "✅ Database schema initialized"
                else
                    echo "❌ Failed to initialize database schema"
                    echo "You may need to run manually: PGPASSWORD='$DB_PASSWORD' psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME < shared/init_schema.sql"
                    return 1
                fi
            else
                echo "❌ Schema file not found: $PROJECT_ROOT/shared/init_schema.sql"
                return 1
            fi
        else
            echo "❌ Failed to create database '$DB_NAME'"
            echo "You may need to create it manually: PGPASSWORD='$DB_PASSWORD' createdb -h $DB_HOST -p $DB_PORT -U $DB_USER $DB_NAME"
            return 1
        fi
    fi
    
    return 0
}

# Function to compile backend
compile_backend() {
    echo "=== Compiling Backend ==="
    cd "$PROJECT_ROOT/backend"
    
    # Always recompile to ensure latest code
    echo "Compiling backend with latest changes..."
    if nim c -d:release main.nim; then
        echo "✅ Backend compiled successfully"
    else
        echo "❌ Backend compilation failed"
        return 1
    fi
    
    return 0
}
# Function to start backend
start_backend() {
    echo "=== Starting Backend ==="
    cd "$PROJECT_ROOT/backend"
    
    # Check if main executable exists (compilation is now handled separately)
    if [ ! -f "main" ]; then
        echo "❌ Backend executable not found. Please run compilation first."
        return 1
    fi
    
    # Check if port 5000 is available
    if ! check_port 5000; then
        echo "Backend port 5000 is in use. Stopping..."
        return 1
    fi
    
    echo "Starting backend server on port 5000..."
    ./main &
    BACKEND_PID=$!
    echo "Backend started with PID: $BACKEND_PID"
    
    # Wait a moment for backend to start
    sleep 3
    
    # Check if backend is responding
    if curl -s http://localhost:5000/ >/dev/null 2>&1; then
        echo "✅ Backend is responding correctly"
    else
        echo "❌ Backend is not responding"
        kill $BACKEND_PID 2>/dev/null || true
        return 1
    fi
    
    return 0
}

# Function to start frontend
start_frontend() {
    echo "=== Starting Frontend ==="
    cd "$PROJECT_ROOT/frontend"
    
    # Check if port 8080 is available
    if ! check_port 8080; then
        echo "Frontend port 8080 is in use. Stopping..."
        return 1
    fi
    
    # Compile nginx config
    echo "Compiling nginx configuration..."
    if command -v lapis >/dev/null 2>&1; then
        lapis build
    else
        echo "WARNING: Lapis not found. Using pre-compiled nginx config..."
    fi
    
    # Start nginx
    echo "Starting nginx on port 8080..."
    openresty -c "$PROJECT_ROOT/frontend/nginx.conf.compiled" -p "$PROJECT_ROOT/frontend/"
    
    echo "✅ Frontend nginx started"
    
    # Wait a moment for frontend to start
    sleep 2
    
    # Check if frontend is responding
    if curl -s http://localhost:8080/ >/dev/null 2>&1; then
        echo "✅ Frontend is responding correctly"
    else
        echo "❌ Frontend is not responding"
        return 1
    fi
    
    return 0
}

# Function to test maintenance page
test_maintenance_page() {
    echo "=== Testing Maintenance Page ==="
    
    # Check if maintenance page exists
    if [ ! -f "$PROJECT_ROOT/frontend/static/maintenance.html" ]; then
        echo "❌ Maintenance page not found"
        return 1
    fi
    
    # Stop backend to test maintenance page
    if [ ! -z "$BACKEND_PID" ]; then
        echo "Stopping backend to test maintenance page..."
        kill $BACKEND_PID 2>/dev/null || true
        sleep 2
    fi
    
    # Test if maintenance page is served when backend is down
    echo "Testing maintenance page response..."
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/login 2>/dev/null || echo "000")
    
    if [ "$RESPONSE" = "502" ] || [ "$RESPONSE" = "503" ] || [ "$RESPONSE" = "504" ]; then
        echo "✅ Maintenance page should be displayed (HTTP $RESPONSE)"
    else
        echo "⚠️  HTTP response code: $RESPONSE (expected 502/503/504 for maintenance page)"
    fi
    
    return 0
}

# Function to stop services
stop_services() {
    echo "=== Stopping Services ==="
    
    # Stop backend
    if [ ! -z "$BACKEND_PID" ]; then
        echo "Stopping backend (PID: $BACKEND_PID)..."
        kill $BACKEND_PID 2>/dev/null || true
    fi
    
    # Stop nginx
    echo "Stopping nginx..."
    openresty -s stop -c "$PROJECT_ROOT/frontend/nginx.conf.compiled" -p "$PROJECT_ROOT/frontend/" 2>/dev/null || true
    
    # Kill any remaining processes
    pkill -f "main" 2>/dev/null || true
    pkill -f "nginx.*$PROJECT_ROOT" 2>/dev/null || true
    
    echo "✅ Services stopped"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start      - Auto-start PostgreSQL, compile backend, start both services"
    echo "  backend    - Auto-start PostgreSQL, compile backend, start only backend"
    echo "  frontend   - Start only frontend"
    echo "  compile    - Just compile the backend without starting"
    echo "  stop       - Stop all services"
    echo "  test       - Run maintenance page test"
    echo "  status     - Check service status"
    echo "  help       - Show this help"
    echo ""
    echo "Features:"
    echo "  • Automatically starts PostgreSQL if not running"
    echo "  • Creates and initializes database if needed"
    echo "  • Always recompiles backend for latest changes"
    echo "  • Comprehensive error checking and reporting"
    echo ""
}

# Function to check status
check_status() {
    echo "=== Service Status ==="
    
    # Check backend
    if curl -s http://localhost:5000/ >/dev/null 2>&1; then
        echo "✅ Backend (port 5000): Running"
    else
        echo "❌ Backend (port 5000): Not running"
    fi
    
    # Check frontend
    if curl -s http://localhost:8080/ >/dev/null 2>&1; then
        echo "✅ Frontend (port 8080): Running"
    else
        echo "❌ Frontend (port 8080): Not running"
    fi
    
    # Check database using credentials from .env
    if load_env >/dev/null 2>&1 && pg_isready -h "$DB_HOST" -p "$DB_PORT" >/dev/null 2>&1; then
        echo "✅ Database (PostgreSQL): Running on $DB_HOST:$DB_PORT"
    else
        echo "❌ Database (PostgreSQL): Not running or not accessible"
    fi
}

# Trap to cleanup on exit
trap stop_services EXIT

# Main command handling
case "${1:-start}" in
    "start")
        echo "🚀 Starting ACS Assignment Application"
        echo ""
        
        # Step 1: Ensure PostgreSQL is running
        if ! ensure_postgresql; then
            echo "❌ Failed to start PostgreSQL. Aborting."
            exit 1
        fi
        
        # Step 2: Ensure database exists and is initialized
        if ! ensure_database; then
            echo "❌ Database setup failed. Aborting."
            exit 1
        fi
        
        # Step 3: Compile backend
        if ! compile_backend; then
            echo "❌ Backend compilation failed. Aborting."
            exit 1
        fi
        
        # Step 4: Start services
        start_backend && start_frontend
        if [ $? -eq 0 ]; then
            echo ""
            echo "🎉 Application started successfully!"
            echo "   Frontend: http://localhost:8080"
            echo "   Backend API: http://localhost:5000"
            echo "   Database: PostgreSQL on localhost:5432"
            echo ""
            echo "Press Ctrl+C to stop all services"
            wait
        fi
        ;;
    "backend")
        echo "🚀 Starting Backend Only"
        echo ""
        
        # Ensure PostgreSQL is running
        if ! ensure_postgresql; then
            echo "❌ Failed to start PostgreSQL. Aborting."
            exit 1
        fi
        
        # Ensure database exists
        if ! ensure_database; then
            echo "❌ Database setup failed. Aborting."
            exit 1
        fi
        
        # Compile backend
        if ! compile_backend; then
            echo "❌ Backend compilation failed. Aborting."
            exit 1
        fi
        
        # Start backend
        start_backend
        if [ $? -eq 0 ]; then
            echo "Backend running. Press Ctrl+C to stop."
            wait
        fi
        ;;
    "frontend")
        start_frontend
        if [ $? -eq 0 ]; then
            echo "Frontend running. Press Ctrl+C to stop."
            wait
        fi
        ;;
    "compile")
        echo "🔨 Compiling Backend"
        compile_backend
        trap - EXIT  # Remove the trap
        ;;
    "stop")
        stop_services
        trap - EXIT  # Remove the trap
        ;;
    "test")
        test_maintenance_page
        trap - EXIT  # Remove the trap
        ;;
    "status")
        check_status
        trap - EXIT  # Remove the trap
        ;;
    "help"|"-h"|"--help")
        show_usage
        trap - EXIT  # Remove the trap
        ;;
    *)
        echo "Unknown command: $1"
        show_usage
        trap - EXIT  # Remove the trap
        exit 1
        ;;
esac
