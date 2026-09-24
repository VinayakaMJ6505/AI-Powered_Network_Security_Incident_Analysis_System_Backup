from backend.nlp_analyzer import analyze_security_log


log = "Failed SSH login from 192.168.1.25 on port 22"

result = analyze_security_log(log)

print(result)