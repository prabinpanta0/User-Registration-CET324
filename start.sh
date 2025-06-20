#!/bin/bash

# ACS Assignment Startup Script
# This script helps start the backend and frontend services

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Project root: $PROJECT_ROOT"

# Function to check if a port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        echo "Port $port is already in use"
        return 1
    fi
    return 0
}

# Function to start backend
start_backend() {
    echo "=== Starting Backend ==="
    cd "$PROJECT_ROOT/backend"
    
    # Check if backend executable exists
    if [ ! -f "main" ]; then
        echo "Backend not compiled. Compiling now..."
        nim c -d:release main.nim
    fi
    
    # Check if database is available
    echo "Checking database connection..."
    if ! pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
        echo "WARNING: PostgreSQL is not running or not accessible"
        echo "Please start PostgreSQL service first"
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
    echo "  start      - Start both backend and frontend"
    echo "  backend    - Start only backend"
    echo "  frontend   - Start only frontend"  
    echo "  stop       - Stop all services"
    echo "  test       - Run maintenance page test"
    echo "  status     - Check service status"
    echo "  help       - Show this help"
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
    
    # Check database
    if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
        echo "✅ Database (PostgreSQL): Running"
    else
        echo "❌ Database (PostgreSQL): Not running"
    fi
}

# Trap to cleanup on exit
trap stop_services EXIT

# Main command handling
case "${1:-start}" in
    "start")
        echo "🚀 Starting ACS Assignment Application"
        start_backend && start_frontend
        if [ $? -eq 0 ]; then
            echo ""
            echo "🎉 Application started successfully!"
            echo "   Frontend: http://localhost:8080"
            echo "   Backend API: http://localhost:5000"
            echo ""
            echo "Press Ctrl+C to stop all services"
            wait
        fi
        ;;
    "backend")
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
