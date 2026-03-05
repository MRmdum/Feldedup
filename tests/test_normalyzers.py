from app.normalyzer import zap, semgrep
import json
import os

def print_vulns(vulns,file:str):
    for vuln in vulns:
        with open(file, 'w', encoding='utf-8') as f:
            f.write(vuln)
            for (field,value) in enumerate(vuln.raw.items()):
                f.write(str(field)+ " : " + str(value)+"\n")

def test_zap():
    base_dir = os.path.dirname(__file__)
    report_path = os.path.join(
        base_dir,
        "..",
        "app",
        "security-reports",
        "zap.json"
    )

    with open(report_path, "r") as f:
        data = json.load(f)

    vulns = zap.normalize(data)

    print_vulns(vulns,"zap_output.txt")

    assert len(vulns) > 0

def test_semgrep():
    base_dir = os.path.dirname(__file__)
    report_path = os.path.join(
        base_dir,
        "..",
        "app",
        "security-reports",
        "semgrep.json"
    )

    with open(report_path, "r") as f:
        data = json.load(f)

    vulns = semgrep.normalize(data)
    print_vulns(vulns,"sem_output.txt")


    assert len(vulns) > 0