<div align="center">

<h1>🛡️ ANTI-BETA</h1>

<h3>An Anti-Forensic Firmware Detection and Analysis Tool for Betaflight Drones</h3>

<p>
<img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python">
<img src="https://img.shields.io/badge/UAV-Forensics-red?style=for-the-badge">
<img src="https://img.shields.io/badge/Firmware-Analysis-orange?style=for-the-badge">
<img src="https://img.shields.io/badge/Research-Project-success?style=for-the-badge">
<img src="https://img.shields.io/badge/NFSU-Gandhinagar-blueviolet?style=for-the-badge">
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
</p>

</div>

<hr>

<h2>📖 Introduction</h2>

<p>
ANTI-BETA is a specialized anti-forensic firmware analysis framework designed for the detection and investigation of hidden modifications within UAV firmware. Modern drones rely heavily on embedded firmware to control flight operations, communication systems, sensor management, and navigation mechanisms. Because firmware operates at a low level within the hardware stack, it has become an attractive target for attackers seeking to conceal malicious activities while maintaining normal system functionality.
</p>

<p>
Traditional firmware forensic approaches primarily focus on firmware extraction and signature-based analysis. However, these approaches often fail to detect sophisticated anti-forensic techniques that manipulate execution flow, conceal malicious logic, modify memory regions, or remove traces of unauthorized activity. ANTI-BETA addresses these challenges by introducing an automated framework capable of identifying structural anomalies, persistence mechanisms, covert communication channels, and integrity violations within Betaflight-based UAV firmware. The system combines binary comparison, heuristic evaluation, and modular detection techniques to provide investigators with meaningful and interpretable results.
</p>

<hr>

<h2>🎯 Aim of the Project</h2>

<p>
The primary aim of this project is to develop an automated anti-forensic detection framework capable of identifying hidden and suspicious modifications within UAV firmware. The framework seeks to assist digital forensic investigators in verifying firmware integrity, detecting malicious persistence mechanisms, and analyzing structural deviations that may indicate anti-forensic behavior.
</p>

<hr>

<h2>🎯 Objectives</h2>

<p>
The project focuses on understanding the structural behavior of UAV firmware and identifying indicators associated with anti-forensic manipulation. It aims to establish an effective methodology for comparing baseline firmware with modified firmware samples and detecting deviations that may compromise forensic investigations. Furthermore, the framework seeks to generate clear and interpretable outputs, enabling investigators to understand the nature and severity of detected anomalies without requiring extensive reverse engineering expertise.
</p>

<hr>

<h2>⚠️ Problem Statement</h2>

<p>
Firmware-level attacks present a significant challenge in modern digital forensic investigations. Attackers can modify firmware to alter execution flow, hide malicious functionality, erase evidence, and establish persistence mechanisms while preserving normal operational behavior. Such modifications often remain undetected by conventional forensic tools because they occur beneath the operating system and application layers.
</p>

<p>
Existing firmware analysis solutions are generally limited to extraction, pattern matching, and static signature detection. They frequently lack the ability to interpret structural modifications or identify sophisticated anti-forensic techniques. As a result, investigators face considerable difficulty when attempting to validate firmware authenticity and identify hidden anomalies. This challenge creates a pressing need for an automated system capable of detecting and analyzing anti-forensic characteristics within embedded firmware environments.
</p>

<hr>

<h2>🏗️ System Architecture</h2>

<p>
The ANTI-BETA framework follows a modular architecture that begins with firmware acquisition and validation. Input firmware files in binary or hexadecimal format are first subjected to integrity verification through cryptographic hashing. Once validated, the firmware undergoes binary difference analysis, where structural changes between a baseline firmware image and a target firmware sample are identified.
</p>

<p>
The extracted differences are then processed by a heuristic analysis engine that evaluates modification patterns, fragmentation behavior, region distribution, and mutation characteristics. Based on these observations, multiple anti-forensic detection modules perform specialized analyses, including stealth detection, hook detection, rootkit identification, rollback analysis, masquerade analysis, covert channel detection, integrity verification, and secure boot assessment. Finally, the system generates risk scores, AI-assisted interpretations, and structured forensic reports to support investigative decision-making.
</p>

<hr>

<h2>🔍 Detection Methodology</h2>

<p>
The proposed framework employs a static firmware analysis approach that does not require access to source code. By comparing a trusted baseline firmware image against a target firmware sample, the framework identifies structural deviations that may indicate unauthorized modifications. These deviations are subsequently evaluated using heuristic techniques designed to distinguish between legitimate firmware updates and potentially malicious changes.
</p>

<p>
The detection process is supported by multiple specialized modules. Stealth detection focuses on hidden memory modifications, while hook detection examines potential execution redirection points such as interrupt vectors and callback mechanisms. Rootkit detection identifies persistent execution structures capable of maintaining malicious functionality within firmware. Additional modules investigate rollback vulnerabilities, covert communication pathways, integrity violations, and firmware masquerading techniques that attempt to disguise unauthorized behavior as legitimate system functionality.
</p>

<hr>

<h2>🤖 AI Interpretation and Reporting</h2>

<p>
One of the distinguishing features of ANTI-BETA is the integration of an AI-assisted interpretation module. Technical findings produced by the analysis engine are translated into human-readable explanations that simplify understanding for investigators, researchers, and analysts. This capability reduces the complexity associated with firmware analysis and allows users to focus on investigative outcomes rather than low-level technical details.
</p>

<p>
The reporting module automatically generates structured forensic reports containing risk scores, detector outputs, heuristic observations, graphical summaries, and confidence assessments. These reports follow a standardized format suitable for documentation, evidence presentation, and academic research purposes.
</p>

<hr>

<h2>📊 Results and Findings</h2>

<p>
The framework was evaluated using baseline firmware images and multiple modified firmware test cases designed to simulate anti-forensic conditions. Experimental results demonstrated the ability of the system to identify structural anomalies, hidden modifications, persistence-related indicators, and firmware integrity concerns. Hash verification successfully confirmed the uniqueness and authenticity of each firmware sample, while heuristic analysis highlighted significant variations between baseline and modified firmware versions.
</p>

<p>
The modular detection framework consistently identified indicators associated with rollback vulnerabilities, covert communication interfaces, execution redirection mechanisms, and integrity anomalies. These findings demonstrate the effectiveness of the proposed approach in distinguishing suspicious firmware behavior from normal operational characteristics.
</p>

<hr>

<h2>💻 Technology Stack</h2>

<p>
The project is implemented using Python as the primary development language and utilizes Betaflight firmware running on STM32 ARM Cortex-M microcontrollers as the target analysis platform. The framework processes binary firmware images in .bin and .hex formats and provides results through a web-based interface designed for accessibility and ease of interpretation. Additional capabilities include automated PDF report generation and AI-assisted result explanation.
</p>

<hr>

<h2>🚀 Future Enhancements</h2>

<p>
Future development of ANTI-BETA will focus on expanding support beyond Betaflight and STM32-based platforms to accommodate a wider range of UAV ecosystems. Planned enhancements include dynamic firmware analysis capabilities, machine learning-driven anomaly detection, real-time firmware monitoring, integration with existing forensic toolchains, and advanced threat intelligence support. These improvements aim to further strengthen the framework's ability to detect sophisticated anti-forensic techniques in emerging embedded environments.
</p>

<hr>

<h2>🎓 Academic Information</h2>

<p>
This project was developed as part of the Master of Science (M.Sc.) program in Digital Forensics and Information Security at the School of Cyber Security and Digital Forensics, National Forensic Sciences University (NFSU), Gandhinagar. The research focuses on the intersection of UAV security, embedded systems analysis, firmware forensics, and anti-forensic detection methodologies. The work contributes to ongoing efforts aimed at improving the reliability and effectiveness of firmware-level forensic investigations.
</p>

<hr>

<div align="center">

<h3>🛡️ ANTI-BETA</h3>

<p><i>Detecting What Attackers Try To Hide.</i></p>

</div>
<hr>

<h2>⚙️ Installation & Setup</h2>

<p>
Follow the steps below to install and run <strong>ANTI-BETA</strong> on your local machine.
</p>

<h3>📥 Step 1: Clone the Repository</h3>

<pre>
git clone https://github.com/your-username/ANTI-BETA.git
cd ANTI-BETA
</pre>

<h3>🐍 Step 2: Create a Virtual Environment</h3>

<p><strong>Windows</strong></p>

<pre>
python -m venv venv
venv\Scripts\activate
</pre>

<p><strong>Linux / macOS</strong></p>

<pre>
python3 -m venv venv
source venv/bin/activate
</pre>

<h3>📦 Step 3: Install Dependencies</h3>

<pre>
pip install -r requirements.txt
</pre>



<h3>🔑 Step 4: Configure Environment Variables</h3>

<p>Create a <code>.env</code> file in the project root directory.</p>

<pre>
GROQ_API_KEY=your_groq_api_key_here
</pre>

<h3>🚀 Step 5: Launch the Application</h3>

<pre>
uvicorn app:app --reload
</pre>

<p>
For external network access:
</p>

<pre>
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
</pre>

<h3>🌐 Access the Application</h3>

<pre>
http://127.0.0.1:8000
</pre>

<p>or</p>

<pre>
http://localhost:8000
</pre>

<hr>

<h2>🛠 Complete Installation Commands</h2>

<pre>
git clone https://github.com/your-username/ANTI-BETA.git

cd ANTI-BETA

python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt

uvicorn app:app --reload
</pre>

<hr>

<h2>📋 Verify Installation</h2>

<pre>
python --version
pip --version
uvicorn --version
</pre>

<hr>

<h2>🔄 Updating Dependencies</h2>

<p>
If new packages are added to the project, regenerate the requirements file:
</p>

<pre>
pip freeze > requirements.txt
</pre>

<hr>

<h2>❗ Troubleshooting</h2>

<p><strong>Upgrade pip</strong></p>

<pre>
python -m pip install --upgrade pip
</pre>

<p><strong>Install pip if missing</strong></p>

<pre>
python -m ensurepip --upgrade
</pre>

<p><strong>Check installed packages</strong></p>

<pre>
pip list
</pre>
