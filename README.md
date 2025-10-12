# 💳 FinTech Credit Card Expense Tracker

A full-stack Java-based FinTech application to manage and track credit card expenditures. Built with Spring Boot, Thymeleaf, MySQL, Docker, GitHub Actions CI/CD, and deployed to AWS EKS with ALB Ingress and ECR integration.

---

## 🌟 Features

- Credit Card Information Storage (masked card, type, expiry)
- Expense Tracking:
  - Vendor, Amount, Date, Category
  - Linked to specific credit cards
- Monthly Expense View & Aggregation
- Thymeleaf Web UI
- RESTful Backend APIs (extendable)
- Built-in Database Integration with MySQL
- CI/CD Pipeline with:
  - Maven build
  - SonarQube static analysis
  - Docker image build + push to Amazon ECR
  - Kubernetes deployment to Amazon EKS via GitHub Actions
- Exposed using ALB Ingress via `https://cloudsroot.org`

---

## 🚀 Tech Stack

| Layer      | Technology                             |
|------------|-----------------------------------------|
| Backend    | Java 17, Spring Boot, Spring MVC, JPA   |
| Frontend   | Thymeleaf, HTML                         |
| Database   | MySQL (JPA/Hibernate)                   |
| CI/CD      | GitHub Actions, Maven, SonarQube        |
| Container  | Docker                                  |
| Cloud      | AWS ECR + EKS + ALB Ingress             |
| Security   | (Pluggable: Spring Security optional)   |

---

## 📦 Project Structure

. ├── src/ │ ├── main/java/com/fintech/app/ │ ├── resources/templates/ # Thymeleaf HTML │ └── application.yml # Configurations ├── k8s/ # Kubernetes Manifests ├── Dockerfile # App containerization ├── pom.xml # Maven dependencies └── .github/workflows/ci-cd.yml # CI/CD pipeline

---

## ⚙️ How to Run Locally

1. **Start MySQL DB (optional if using local setup)**
2. **Build & Run:**
```bash
mvn clean install
mvn spring-boot:run
Access: http://localhost:8080/expenses

🐳 Docker Build & Run

docker build -t fintech-app .
docker run -p 8080:8080 fintech-app
☁️ AWS CI/CD Pipeline
CI Steps:
Maven Build (mvn package)

SonarQube Scan

Docker Image Push to Amazon ECR

CD Steps:
Kubernetes Deploy to EKS

ALB Ingress to expose public URL

💡 All automated via GitHub Actions (.github/workflows/ci-cd.yml)

🛠 GitHub Secrets Required
Key	Description
SONAR_TOKEN	SonarQube project token
SONAR_HOST_URL	URL of your SonarQube instance
AWS_ACCESS_KEY_ID	AWS credentials for ECR/EKS
AWS_SECRET_ACCESS_KEY	AWS credentials
🌍 Public Access
✅ https://cloudsroot.com
Hosted via AWS ALB Ingress Controller.

📈 Future Improvements (Open for Contribution)
User Login (Spring Security)

Role-based dashboards (Admin vs Card Holder)

Export to PDF/Excel

Pie charts & vendor analytics with Chart.js

RESTful APIs for mobile client integration

👨‍💻 Author
Name: Emmanuel Tetteh
Role: DevOps Engineer 
GitHub: @EmmadevAI

📄 License
This project is open-source and licensed under the MIT License.

---

Let me know if you'd like a **`LICENSE`** file or **Swagger/OpenAPI docs** section added next! 📜🔥



🏃 GitHub Runner Auto-Start Setup (Ubuntu)
This guide explains how to configure the run.sh script to run continuously and automatically after reboot using systemd.

📁 Prerequisites
Ubuntu system with systemd (default in most distributions).

GitHub Actions self-hosted runner already configured.

Script located at: /home/ubuntu/actions-runner/run.sh

⚙️ 1. Create the systemd Service
Create a new systemd unit file:

sudo vi /etc/systemd/system/github-runner.service
Paste the following content:

[Unit]
Description=GitHub Actions Self-Hosted Runner
After=network.target

[Service]
ExecStart=/home/ubuntu/actions-runner/run.sh
WorkingDirectory=/home/ubuntu/actions-runner
User=ubuntu
Group=docker
Restart=always
RestartSec=10
Environment=RUNNER_MANUALLY_TRAP_SIG=1

[Install]
WantedBy=multi-user.target



✅ Make sure the paths (ExecStart, WorkingDirectory) are accurate for your environment.

🔐 2. Make the Script Executable

chmod +x /home/ubuntu/actions-runner/run.sh

🔄 3. Enable and Start the Service
Run the following commands to enable the service to start on boot and start it now:

sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable github-runner.service
sudo systemctl start github-runner.service


✅ 4. Verify the Service
Check if the runner is active:

sudo systemctl status github-runner.service
Expected output should show the status as active (running).

💡 Notes
Restart=always ensures the script restarts if it crashes.

RUNNER_MANUALLY_TRAP_SIG=1 helps the script handle shutdown signals gracefully.

📌 Troubleshooting
Use journalctl -u github-runner.service -f to see live logs.

Ensure no sudo commands inside the script block automatic execution as ubuntu user.

Confirm networking is available (runner needs internet access).

🧹 To Remove the Service
sudo systemctl stop github-runner.service
sudo systemctl disable github-runner.service
sudo rm /etc/systemd/system/github-runner.service
sudo systemctl daemon-reload


## 📦 Configuring Prometheus Stack
✅ Verify grafana password

kubectl --namespace monitoring get pods -l "release=prometheus-stack"

Get Grafana 'admin' user password by running:

kubectl --namespace monitoring get secrets prometheus-stack-grafana -o jsonpath="{.data.admin-password}" | base64 -d ; echo

Access Grafana local instance:

export POD_NAME=$(kubectl --namespace monitoring get pod -l "app.kubernetes.io/name=grafana,app.kubernetes.io/instance=prometheus-stack" -oname)
kubectl --namespace monitoring port-forward $POD_NAME 3000 




# Resetting Grafana Password

Step 1: Identify the Grafana Pod
List the pods in the namespace where Grafana is deployed (e.g., monitoring):

kubectl get pods -n monitoring
Step 2: Exec into the Grafana Pod
Pick a pod name (e.g., grafana-xyz) and exec into it:

kubectl exec -it <grafana-pod-name> -n monitoring -- /bin/sh
or use /bin/bash if available.

Step 3: Use grafana-cli to reset the admin password
Inside the pod, run:

grafana-cli admin reset-admin-password <newpassword>
Example:

grafana-cli admin reset-admin-password admin123


















