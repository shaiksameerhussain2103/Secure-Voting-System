# 🗳️ Secure Online Voting System Using RSA Algorithm

A secure, modern web-based voting application built with Flask that uses RSA encryption to ensure vote confidentiality and integrity.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Security](https://img.shields.io/badge/Security-RSA%202048--bit-red.svg)

## 🔒 Security Features

- **RSA 2048-bit Encryption**: All votes are encrypted using industry-standard RSA encryption
- **End-to-End Security**: Votes are encrypted on the client-side before transmission
- **Anonymous Voting**: Voter identities are not linked to their vote choices
- **Secure Session Management**: Flask sessions with secure secret keys
- **Data Integrity**: Encrypted vote storage with tamper-proof mechanisms

## 🚀 Features

### For Voters
- ✅ Secure user registration and authentication
- ✅ Encrypted vote casting with RSA encryption
- ✅ One-vote-per-user enforcement
- ✅ Mobile-responsive interface
- ✅ Real-time vote confirmation

### For Administrators
- ✅ Secure admin authentication
- ✅ Vote decryption using private key
- ✅ Real-time election results
- ✅ Visual analytics with charts
- ✅ Election statistics and monitoring

## 🛠️ Technology Stack

- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Encryption**: Python Cryptography Library (RSA)
- **Data Storage**: JSON files
- **Styling**: Modern CSS with CSS Grid/Flexbox
- **Charts**: Chart.js for data visualization

## 📁 Project Structure

```
Secure-Voting-System/
│
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── README.md                       # Project documentation
│
├── rsa_keys/                       # RSA key storage
│   ├── private.pem                 # RSA private key (auto-generated)
│   └── public.pem                  # RSA public key (auto-generated)
│
├── data/                           # Application data
│   ├── users.json                  # User accounts (auto-generated)
│   └── votes.json                  # Encrypted votes (auto-generated)
│
├── static/                         # Static assets
│   ├── css/
│   │   └── style.css              # Modern responsive CSS
│   └── js/
│       └── script.js              # Frontend JavaScript
│
└── templates/                      # HTML templates
    ├── layout.html                 # Base template
    ├── index.html                  # Login page
    ├── register.html               # Registration page
    ├── vote.html                   # Voting interface
    ├── admin_login.html            # Admin login
    └── admin_dashboard.html        # Admin results dashboard
```

## 🔧 Installation & Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Modern web browser with JavaScript enabled

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd Secure-Voting-System
```

### Step 2: Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install flask cryptography
```

### Step 4: Run the Application

```bash
python app.py
```

The application will start on `http://127.0.0.1:5000`

## 🔐 RSA Encryption Explained

### How It Works

1. **Key Generation**: When the app starts, it generates a 2048-bit RSA key pair
   - **Public Key**: Used for encrypting votes (stored in `rsa_keys/public.pem`)
   - **Private Key**: Used for decrypting votes (stored in `rsa_keys/private.pem`)

2. **Vote Encryption Process**:
   - Voter selects a candidate
   - JavaScript fetches the public key from the server
   - Vote is encrypted using RSA-OAEP with SHA-256 on the client-side
   - Encrypted vote is sent to the server and stored

3. **Vote Decryption Process**:
   - Admin logs in with proper credentials
   - Server uses the private key to decrypt all votes
   - Results are calculated and displayed

### Security Benefits

- **Confidentiality**: Only admins with the private key can see vote contents
- **Integrity**: Votes cannot be modified without detection
- **Non-repudiation**: Encrypted votes serve as tamper-proof records
- **Forward Secrecy**: Historical votes remain secure even if future keys are compromised

## 👥 Default Credentials

### Admin Account
- **Username**: `admin`
- **Password**: `admin123`

*⚠️ Important: Change these credentials in production!*

## 🎯 Usage Guide

### For Voters

1. **Register**: Create a new account with your details
2. **Login**: Access the voting system with your credentials
3. **Vote**: Select your preferred candidate
4. **Confirm**: Review and confirm your encrypted vote
5. **Verification**: Receive confirmation that your vote was recorded

### For Administrators

1. **Login**: Use admin credentials to access the dashboard
2. **View Results**: See real-time decrypted election results
3. **Analytics**: Review voting statistics and trends
4. **Monitor**: Track election progress and security metrics

## 🔧 Configuration

### Environment Variables (Optional)

```bash
# Set custom secret key
export FLASK_SECRET_KEY="your-super-secure-secret-key"

# Set custom port
export FLASK_PORT=8080

# Enable debug mode
export FLASK_DEBUG=1
```

### Customizing Candidates

Edit the `CANDIDATES` list in `app.py`:

```python
CANDIDATES = [
    {"id": 1, "name": "Your Candidate", "party": "Party Name", "slogan": "Campaign Slogan"},
    # Add more candidates...
]
```

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home/Login page |
| `/register` | GET/POST | User registration |
| `/login` | POST | User authentication |
| `/logout` | GET | User logout |
| `/vote` | GET | Voting interface |
| `/submit_vote` | POST | Submit encrypted vote |
| `/admin_login` | GET | Admin login page |
| `/admin_dashboard` | GET | Admin results dashboard |
| `/get_public_key` | GET | Fetch RSA public key |

## 🛡️ Security Considerations

### Production Deployment

1. **Change Default Credentials**: Update admin password
2. **Use HTTPS**: Deploy with SSL/TLS certificates
3. **Secure Secret Key**: Use a cryptographically secure secret key
4. **Database Security**: Consider using encrypted databases
5. **Regular Backups**: Backup keys and data securely
6. **Access Logging**: Implement comprehensive audit trails

### Known Limitations

- JSON file storage (consider database for production)
- Single admin account (implement role-based access)
- No user email verification (add for production)
- No rate limiting (implement to prevent abuse)

## 🧪 Testing

### Manual Testing Checklist

- [ ] User registration works correctly
- [ ] User login/logout functions properly
- [ ] Vote encryption and submission works
- [ ] Admin can decrypt and view results
- [ ] Only one vote per user is enforced
- [ ] RSA keys are generated correctly
- [ ] Responsive design works on mobile

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-flask

# Run tests (when available)
pytest tests/
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📋 Changelog

### Version 1.0.0 (Current)
- Initial release with RSA encryption
- User registration and authentication
- Voting system with encryption
- Admin dashboard with results
- Responsive modern UI
- Complete documentation

## 🐛 Troubleshooting

### Common Issues

**Issue**: RSA keys not generating
**Solution**: Ensure the `rsa_keys/` directory exists and has write permissions

**Issue**: Vote encryption fails
**Solution**: Check that the public key is loading correctly in the browser console

**Issue**: Admin dashboard shows no results
**Solution**: Verify that votes have been cast and the private key is accessible

**Issue**: Styling not loading
**Solution**: Check that Flask is serving static files correctly

### Debug Mode

Enable debug mode for development:

```python
# In app.py
app.run(debug=True, host='127.0.0.1', port=5000)
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Flask documentation and community
- Python Cryptography library developers
- Chart.js for beautiful visualizations
- Font Awesome for icons
- Inter font family for typography

## 📞 Support

If you encounter any issues or have questions:

1. Check the troubleshooting section above
2. Review the [Issues](../../issues) page
3. Create a new issue with detailed information
4. Include error messages and steps to reproduce

---

**⚠️ Security Notice**: This application is designed for educational and demonstration purposes. For production use, please conduct a thorough security audit and implement additional security measures as needed.

**🔒 Encryption Note**: This system uses RSA-OAEP with SHA-256 for vote encryption, providing strong security for modern voting applications.