# SQL Injection Vulnerability Scanner

A comprehensive SQL injection vulnerability scanner with support for multiple testing methods, Tor network routing, and detailed reporting capabilities.

## Features

- **Multiple Testing Methods**:
  - Authentication Bypass
  - Union-Based Injection
  - Error-Based Detection
  - Time-Based Blind Injection
  - And more...

- **Advanced Capabilities**:
  - Automatic parameter detection
  - Form input analysis
  - Tor network support
  - Detailed vulnerability reporting
  - Progress tracking
  - Configurable test types

- **Security Features**:
  - Customizable request delays
  - Tor network routing
  - Logging capabilities
  - Graceful interruption handling

## Installation

```bash
# Clone the repository
git clone https://github.com/Reo-0x/sql-injection-scanner

# Install required packages
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python scanner.py --url "http://target-url.com"
```

Advanced options:
```bash
python scanner.py --url "http://target-url.com" \
                 --delay 1 \
                 --tor \
                 --type 3 \
                 --report scan_results.txt \
                 --log
```

### Command Line Arguments

- `--url`: Target URL to test (required)
- `--delay`: Delay between requests in seconds (default: 0)
- `--tor`: Use Tor network for scanning
- `--type`: Select test type (1-5)
  1. All Tests (Default)
  2. Quick Scan (Auth Bypass + Error Based)
  3. Deep Scan (Union + Blind + Time Based)
  4. Basic Scan (Auth Bypass + URL Encoded)
  5. Advanced Scan (All except Time Based)
- `--report`: Enable and specify report file name
- `--log`: Enable logging

## Legal Disclaimer

This tool is provided for educational and testing purposes only. Users must obtain explicit permission before testing any website or application they don't own. The author is not responsible for any misuse or damage caused by this tool.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created by Reo-0x
GitHub: https://github.com/Reo-0x
