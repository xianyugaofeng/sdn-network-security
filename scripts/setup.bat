@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

REM =============================================================================
REM SDN Network Security System - Windows Setup Script
REM SDN Network Security System - Windows Installation Script
REM =============================================================================

title SDN Network Security System Setup

echo.
echo ============================================================
echo   SDN Network Security System Setup (Windows Version)
echo   SDN Network Security System Installation (Windows Version)
echo ============================================================
echo.

REM Set project directory
set "PROJECT_DIR=%~dp0.."
cd /d "%PROJECT_DIR%"
echo [INFO] Project directory: %PROJECT_DIR%
echo.

REM ========== Step 1: Check Python ==========
echo ------------------------------------------------------------
echo Step 1: Check Python Environment
echo ------------------------------------------------------------

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo [INFO] Please download and install Python 3.6+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2" %%a in ('python --version 2^>^&1') do set PYTHON_VERSION=%%a
echo [INFO] Python version: %PYTHON_VERSION%
echo [SUCCESS] Python check passed
echo.

REM ========== Step 2: Check pip ==========
echo ------------------------------------------------------------
echo Step 2: Check pip
echo ------------------------------------------------------------

pip --version >nul 2>&1
if errorlevel 1 (
    echo [WARNING] pip not found, attempting to install...
    python -m ensurepip --upgrade
    if errorlevel 1 (
        echo [ERROR] pip installation failed
        pause
        exit /b 1
    )
)
echo [SUCCESS] pip check passed
echo.

REM ========== Step 3: Create virtual environment ==========
echo ------------------------------------------------------------
echo Step 3: Create Virtual Environment
echo ------------------------------------------------------------

if exist "venv" (
    echo [WARNING] Old virtual environment detected, deleting...
    rmdir /s /q "venv"
)

echo [INFO] Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo [ERROR] Virtual environment creation failed
    pause
    exit /b 1
)
echo [SUCCESS] Virtual environment created successfully
echo.

REM ========== Step 4: Activate virtual environment and upgrade pip ==========
echo ------------------------------------------------------------
echo Step 4: Upgrade pip Tools
echo ------------------------------------------------------------

echo [INFO] Activating virtual environment and upgrading pip...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip setuptools wheel
if errorlevel 1 (
    echo [WARNING] pip upgrade failed, but continuing installation...
)
echo [SUCCESS] pip upgrade completed
echo.

REM ========== Step 5: Install dependencies ==========
echo ------------------------------------------------------------
echo Step 5: Install Python Dependencies
echo ------------------------------------------------------------

if not exist "requirements.txt" (
    echo [ERROR] requirements.txt not found
    pause
    exit /b 1
)

echo [INFO] Installing dependencies, this may take a few minutes...
echo [INFO] Installing Ryu SDN framework and related dependencies...

REM Try to install with default settings first
echo [INFO] Attempting installation with default settings...
pip install -r requirements.txt
if errorlevel 1 (
    echo [WARNING] Default installation failed, trying with Tsinghua mirror...
    pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn
    if errorlevel 1 (
        echo [WARNING] Tsinghua mirror failed, trying with Alibaba mirror...
        pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
        if errorlevel 1 (
            echo [WARNING] Alibaba mirror failed, trying with Douban mirror...
            pip install -r requirements.txt -i https://pypi.doubanio.com/simple/ --trusted-host pypi.doubanio.com
            if errorlevel 1 (
                echo [ERROR] All installation attempts failed
                echo [INFO] Please check your internet connection or configure proxy settings
                echo [INFO] You can manually run: pip install -r requirements.txt
                pause
                exit /b 1
            )
        )
    )
)
echo [SUCCESS] Dependencies installed successfully
echo.

REM ========== Step 6: Create necessary directories ==========
echo ------------------------------------------------------------
echo Step 6: Create Necessary Directories
echo ------------------------------------------------------------

for %%d in (logs data config docs tests scripts) do (
    if not exist "%%d" (
        mkdir "%%d"
        echo [INFO] Directory created: %%d
    ) else (
        echo [INFO] Directory already exists: %%d
    )
)
echo [SUCCESS] Directory creation completed
echo.

REM ========== Step 7: Verify installation ==========
echo ------------------------------------------------------------
echo Step 7: Verify Installation
echo ------------------------------------------------------------

echo [INFO] Verifying key module imports...
python -c "import sys; print('[INFO] Python version:', sys.version_info[:2])"
if errorlevel 1 (
    echo [ERROR] Python version check failed
)

python -c "import ryu; print('[SUCCESS] Ryu imported successfully, version:', ryu.__version__)"
if errorlevel 1 (
    echo [ERROR] Ryu import failed
    pause
    exit /b 1
)

python -c "import scapy; print('[SUCCESS] Scapy imported successfully')" 2>nul
if errorlevel 1 (
    echo [WARNING] Scapy import failed (optional component)
)

python -c "import sklearn; print('[SUCCESS] Scikit-learn imported successfully')" 2>nul
if errorlevel 1 (
    echo [WARNING] Scikit-learn import failed (optional component)
)

echo [SUCCESS] Key module verification completed
echo.

REM ========== Step 8: Create run scripts ==========
echo ------------------------------------------------------------
echo Step 8: Create Windows Run Scripts
echo ------------------------------------------------------------

call :CreateRunScript
call :CreateTestScript
call :CreateFrontendScript

echo [SUCCESS] Windows run scripts created successfully
echo.

REM ========== Installation complete ==========
echo ------------------------------------------------------------
echo Installation Complete
echo ------------------------------------------------------------
echo.
echo ============================================================
echo   [SUCCESS] Installation successful! 
echo   System is now configured for Windows
echo ============================================================
echo.
echo Next steps:
echo   1. Start Ryu controller:
echo      run.bat controller
echo.
echo   2. Start frontend interface:
echo      run.bat frontend
echo.
echo   3. Run tests:
echo      test.bat
echo.
echo   4. View help:
echo      run.bat help
echo.
pause
exit /b 0

REM =============================================================================
REM Subroutine: Create run script
REM =============================================================================
:CreateRunScript
(
echo @echo off
echo chcp 65001 ^>nul
echo setlocal EnableDelayedExpansion
echo.
echo REM SDN Network Security System - Windows Run Script
echo.
echo set "PROJECT_DIR=%%~dp0"
echo cd /d "%%PROJECT_DIR%%"
echo.
echo if "%%~1"=="" goto :help
echo if "%%~1"=="help" goto :help
echo if "%%~1"=="controller" goto :controller
echo if "%%~1"=="frontend" goto :frontend
echo if "%%~1"=="api" goto :api
echo if "%%~1"=="all" goto :all
echo.
echo echo [ERROR] Unknown command: %%~1
echo goto :help
echo.
echo :help
echo echo.
echo echo SDN Network Security System - Windows Run Script
echo echo.
echo echo Usage: run.bat [command]
echo echo.
echo echo Available commands:
echo echo   controller    Start Ryu SDN controller
echo echo   frontend      Start frontend interface (development mode)
echo echo   api           Start API server
echo echo   all           Start all services (requires multiple terminals)
echo echo   help          Show this help message
echo echo.
echo echo Examples:
echo echo   run.bat controller
echo echo   run.bat frontend
echo echo.
echo pause
echo exit /b 0
echo.
echo :controller
echo echo [INFO] Starting Ryu SDN controller...
echo call venv\Scripts\activate.bat
echo echo [INFO] Using config: config\config.yaml
echo ryu-manager --verbose --ofp-tcp-listen-port 6633 controllers\ryu_controller.py
echo if errorlevel 1 (
echo     echo [ERROR] Controller startup failed
echo     pause
echo ^)
echo exit /b 0
echo.
echo :frontend
echo echo [INFO] Starting frontend interface...
echo cd frontend
echo if not exist "node_modules" (
echo     echo [INFO] First run, installing frontend dependencies...
echo     call npm install
echo ^)
echo echo [INFO] Starting development server...
echo call npm run dev
echo exit /b 0
echo.
echo :api
echo echo [INFO] Starting API server...
echo call venv\Scripts\activate.bat
echo python -m flask run --host=0.0.0.0 --port=5000
echo exit /b 0
echo.
echo :all
echo echo [INFO] Starting all services...
echo echo [INFO] Note: This feature requires manually running different services in multiple terminals
echo echo.
echo echo Please start services in the following order:
echo echo 1. Run in first terminal: run.bat controller
echo echo 2. Run in second terminal: run.bat api
echo echo 3. Run in third terminal: run.bat frontend
echo echo.
echo pause
echo exit /b 0
) > "run.bat"
exit /b 0

REM =============================================================================
REM Subroutine: Create test script
REM =============================================================================
:CreateTestScript
(
echo @echo off
echo chcp 65001 ^>nul
echo setlocal EnableDelayedExpansion
echo.
echo REM SDN Network Security System - Windows Test Script
echo.
echo set "PROJECT_DIR=%%~dp0"
echo cd /d "%%PROJECT_DIR%%"
echo.
echo echo.
echo echo ============================================================
echo echo   SDN Network Security System - Test Script
echo echo ============================================================
echo echo.
echo echo.
echo if "%%~1"=="" goto :run_all_tests
echo if "%%~1"=="all" goto :run_all_tests
echo if "%%~1"=="firewall" goto :test_firewall
echo if "%%~1"=="ids" goto :test_ids
echo if "%%~1"=="traffic" goto :test_traffic
echo if "%%~1"=="anomaly" goto :test_anomaly
echo if "%%~1"=="help" goto :help
echo.
echo echo [ERROR] Unknown test type: %%~1
echo goto :help
echo.
echo :help
echo echo Usage: test.bat [test type]
echo echo.
echo echo Available test types:
echo echo   all       Run all tests
echo echo   firewall  Run firewall module tests
echo echo   ids       Run intrusion detection module tests
echo echo   traffic   Run traffic monitor module tests
echo echo   anomaly   Run anomaly detection module tests
echo echo   help      Show this help message
echo echo.
echo pause
echo exit /b 0
echo.
echo :run_all_tests
echo echo [INFO] Running all tests...
echo call venv\Scripts\activate.bat
echo python -m pytest tests\ -v --tb=short
echo if errorlevel 1 (
echo     echo [ERROR] Tests failed
echo ^) else (
echo     echo [SUCCESS] All tests passed
echo ^)
echo pause
echo exit /b 0
echo.
echo :test_firewall
echo echo [INFO] Running firewall module tests...
echo call venv\Scripts\activate.bat
echo python -m pytest tests\test_firewall.py -v --tb=short
echo pause
echo exit /b 0
echo.
echo :test_ids
echo echo [INFO] Running intrusion detection module tests...
echo call venv\Scripts\activate.bat
echo python -m pytest tests\test_ids.py -v --tb=short
echo pause
echo exit /b 0
echo.
echo :test_traffic
echo echo [INFO] Running traffic monitor module tests...
echo call venv\Scripts\activate.bat
echo python -m pytest tests\test_traffic_monitor.py -v --tb=short
echo pause
echo exit /b 0
echo.
echo :test_anomaly
echo echo [INFO] Running anomaly detection module tests...
echo call venv\Scripts\activate.bat
echo python -m pytest tests\test_anomaly.py -v --tb=short
echo pause
echo exit /b 0
) > "test.bat"
exit /b 0

REM =============================================================================
REM Subroutine: Create frontend script
REM =============================================================================
:CreateFrontendScript
(
echo @echo off
echo chcp 65001 ^>nul
echo setlocal EnableDelayedExpansion
echo.
echo REM SDN Network Security System - Frontend Setup Script
echo.
echo set "PROJECT_DIR=%%~dp0"
echo cd /d "%%PROJECT_DIR%%\frontend"
echo.
echo echo [INFO] Checking Node.js environment...
echo node --version ^>nul 2^>^&1
echo if errorlevel 1 (
echo     echo [ERROR] Node.js is not installed
echo     echo [INFO] Please download and install Node.js 16+ from https://nodejs.org/
echo     pause
echo     exit /b 1
echo ^)
echo.
echo echo [INFO] Checking npm...
echo npm --version ^>nul 2^>^&1
echo if errorlevel 1 (
echo     echo [ERROR] npm not found
echo     pause
echo     exit /b 1
echo ^)
echo.
echo if not exist "node_modules" (
echo     echo [INFO] Installing frontend dependencies...
echo     call npm install
echo     if errorlevel 1 (
echo         echo [ERROR] Frontend dependency installation failed
echo         pause
echo         exit /b 1
echo     ^)
echo ^)
echo.
echo echo [INFO] Starting frontend development server...
echo call npm run dev
) > "scripts\frontend.bat"
exit /b 0
