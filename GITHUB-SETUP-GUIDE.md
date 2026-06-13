# GitHub Setup Guide

## Step 1 - Create the Repository

1. Go to github.com/new
2. Repository name: soc-investigation-portfolio
3. Description: SOC Analyst investigation portfolio | Phishing, Brute Force, Lateral Movement and False Positive triage | Proofpoint, Wazuh, Elastic SIEM, Firewall | MITRE ATT&CK mapped | InfoSecLabs Platform
4. Set to Public
5. Do NOT check Add a README file
6. Click Create repository

## Step 2 - Upload via Git CLI

```bash
cd soc-portfolio/
git init
git remote add origin https://github.com/YOUR_USERNAME/soc-investigation-portfolio.git
git add .
git commit -m "Initial commit: SOC investigation portfolio with 6 investigations"
git branch -M main
git push -u origin main
```

## Step 3 - Pin the Repository

1. Go to your GitHub profile
2. Click Customize your profile
3. Pin soc-investigation-portfolio as a featured repository

## Step 4 - Add Screenshots

In each investigation folder there is a screenshots directory.
Take screenshots from your InfoSecLabs alert pages and drop them there.
Then reference them in the README with: ![alert](./screenshots/alert.png)
