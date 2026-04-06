# from main import detect_vulnerabilities

# def test_detects_hardcoded_password():
#     code = 'DB_PWD = "12345"\n'
#     result = detect_vulnerabilities(code)
#     print(result)
#     assert "hardcoded-credentials" in result
#     assert "Remediation" in result
#     assert "DB_PWD = \"12345\"" in result

# def test_no_vulnerabilities():
#     code = 'import os\nDB_PWD = os.environ.get("DB_PWD")\n'
#     result = detect_vulnerabilities(code)
#     assert "No vulnerabilities detected." in result
