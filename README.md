# 🚡 Firewall Configuration Review Tool

This tool helps analyze and optimize firewall rules to improve security posture.

---

## 🧰 Features
- Load and analyze firewall rules (CSV format)
- Detect redundant, conflicting, or risky rules
- Suggest optimizations
- Simulate packet flow through rules

---

## 🖼️ Screenshot

Here’s how the GUI looks:

![Firewall GUI Screenshot](assets/firewall_gui.png)

> 💡 Tip: Make sure you have an image file inside a folder named `assets` in your project.

---

## ⚙️ How to Run

1. Clone the repo:
   ```bash
   git clone https://github.com/Akhil-ch1/Firewall_Configuration.git
   cd Firewall_Configuration
2. Run 
 pip install tk
 python firewall_review_tool.py
3. Import the file after run
 save file into .csv file

 Like
    This formate:
        Action,Protocol,Source,Destination,Port
        ALLOW,TCP,0.0.0.0/0,192.168.1.10,22
        DENY,UDP,192.168.1.0/24,8.8.8.8,ANY
        ALLOW,TCP,10.0.0.5,0.0.0.0/0,80
asserts/
    

