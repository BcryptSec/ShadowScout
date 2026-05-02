# ShadowScout
### Offensive Recon & Risk Scoring Engine

ShadowScout is a asynchronous reconnaissance tool built for security researchers and penetration testers. It automates the discovery of sensitive files, parses JavaScript for hidden endpoints, and applies a dynamic risk-scoring algorithm to prioritize targets.

<img width="661" height="414" alt="image" src="https://github.com/user-attachments/assets/75f4fa10-9820-417f-85a7-283327371be1" />


---

## 🚀 Key Features

*   **Asynchronous Engine:** Built with `aiohttp` for lightning-fast scanning across hundreds of paths without the overhead of heavy threading.
*   **Deep Intelligence Mode:** Automatically crawls and parses client-side JavaScript files to extract internal API routes and hidden endpoints.
*   **Dynamic Risk Scoring:** Implements a weighted scoring system that categorizes targets (Informational to Critical) based on the sensitivity of discovered files (e.g., `.env`, `.git`, AWS credentials).
*   **Structured Reporting:** Generates clean, audit-ready JSON reports for seamless integration into security pipelines and bug bounty workflows.

---

## 🛠️ Installation

Ensure you have Python 3.7+ installed. 


1. Clone the repository:

   ```bash
   
   git clone https://github.com/BcryptSec/ShadowScout.git
   cd ShadowScout

2. Install the package:

   ```bash
   
   pip install .
 
💻 Usage
ShadowScout is designed to be simple yet powerful.

1. Basic Recon

   ```bash
   
   shadowscout -u https://example.com

2. Deep Analysis (API & JS Discovery)

   ```bash
   
   shadowscout -u https://example.com -d -t2
 
3. Save Audit Results.

   ```bash
   
   shadowscout -u https://example.com -o report.json

🛡️ Security Logic & Scoring
ShadowScout evaluates target security posture by looking for high-impact exposures

<img width="841" height="346" alt="image" src="https://github.com/user-attachments/assets/517150d1-5275-423d-ac37-9adafafbae9c" />

⚖️ Disclaimer
This tool is for educational and ethical security testing purposes only. Unauthorized scanning of targets without prior mutual consent is illegal. The developer (BcryptSec) assumes no liability for misuse or damage caused by this program.
