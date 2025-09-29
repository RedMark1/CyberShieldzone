import streamlit as st
import requests
import socket
import ssl
import json
import datetime
import time
import os
import pandas as pd
import matplotlib.pyplot as plt
import base64
import networkx as nx
from urllib.parse import urlparse
from fpdf import FPDF

# --- Config ---
TIMEOUT = 8
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
]
COMMON_ENDPOINTS = [
    "/", "/robots.txt", "/sitemap.xml", "/admin/", "/login", "/.git/", "/backup/", "/env", "/wp-admin/"
]
HISTORY_FILE = "scan_history.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

st.set_page_config(page_title="CyberShield", layout="wide")

# --- Utility Functions ---
def normalize_url(user_input: str) -> str:
    if not user_input.startswith(("http://", "https://")):
        user_input = "https://" + user_input
    return user_input.rstrip("/")

def fetch_headers(url: str):
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent":"CyberShield/1.0"})
        return {"status_code": r.status_code, "final_url": r.url, "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}

def check_security_headers(headers: dict):
    missing = []
    present = {}
    for h in SECURITY_HEADERS:
        if h in headers:
            present[h] = headers[h]
        else:
            missing.append(h)
    return {"present": present, "missing": missing}

def fetch_robots_sitemap(base_url):
    results = {}
    for p in ["/robots.txt", "/sitemap.xml"]:
        try:
            url = base_url.rstrip("/") + p
            r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent":"CyberShield/1.0"})
            results[p] = {"status_code": r.status_code, "length": len(r.text)}
        except Exception as e:
            results[p] = {"error": str(e)}
    return results

def get_tls_certificate(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                notAfter = cert.get("notAfter")
                notBefore = cert.get("notBefore")
                subject = cert.get("subject")
                issuer = cert.get("issuer")
                return {"notBefore": notBefore, "notAfter": notAfter, "subject": subject, "issuer": issuer}
    except Exception as e:
        return {"error": str(e)}

def check_common_endpoints(base_url):
    results = {}
    for p in COMMON_ENDPOINTS:
        try:
            url = base_url.rstrip("/") + p
            r = requests.head(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent":"CyberShield/1.0"})
            if r.status_code == 405:
                r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent":"CyberShield/1.0"})
            results[p] = {"status_code": r.status_code, "final_url": r.url}
        except Exception as e:
            results[p] = {"error": str(e)}
    return results

def fetch_cve_info(keyword):
    if not keyword:
        return []
    try:
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        r = requests.get(NVD_API_URL, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            items = []
            for cve in data.get("vulnerabilities", []):
                cve_id = cve["cve"]["id"]
                desc = cve["cve"]["descriptions"][0]["value"]
                cvss = cve["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
                items.append({
                    "CVE ID": cve_id,
                    "CVSS": cvss,
                    "Description": desc,
                    "Component": keyword
                })
            return items
        return []
    except Exception:
        return []

def parse_cert_expiry(notAfter: str):
    if not notAfter:
        return None
    try:
        dt = datetime.datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
        return dt
    except Exception:
        try:
            dt = datetime.datetime.strptime(notAfter, "%b %d %H:%M:%S %Y")
            return dt
        except Exception:
            return None

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            try:
                return json.load(f)
            except:
                return []
    return []

def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def highlight_attack_paths(vulns):
    return [v for v in vulns if v.get("CVSS") != "N/A" and is_high_cvss(v.get("CVSS"))]

def is_high_cvss(cvss):
    try:
        return float(cvss) >= 7
    except:
        return False

def risk_level(cvss):
    try:
        score = float(cvss)
        if score >= 7:
            return "High"
        elif score >= 4:
            return "Medium"
        else:
            return "Low"
    except:
        return "Unknown"

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'CyberShield Vulnerability Scan Report', 0, 1, 'C')
        self.set_font('Arial', '', 8)
        self.cell(0, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
        self.ln(10)
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(vuln_df: pd.DataFrame) -> bytes:
    if vuln_df.empty:
        return b""
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, "Summary", 0, 1)
    pdf.set_font("Arial", size=12)
    total_vulns = len(vuln_df)
    high_risk = sum(vuln_df['Risk'] == 'High')
    medium_risk = sum(vuln_df['Risk'] == 'Medium')
    low_risk = sum(vuln_df['Risk'] == 'Low')
    pdf.cell(0, 10, f"- Total Vulnerabilities Found: {total_vulns}", 0, 1)
    pdf.cell(0, 10, f"- High Risk: {high_risk}", 0, 1)
    pdf.cell(0, 10, f"- Medium Risk: {medium_risk}", 0, 1)
    pdf.cell(0, 10, f"- Low Risk: {low_risk}", 0, 1)
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, "Detailed Findings", 0, 1)
    for index, row in vuln_df.iterrows():
        pdf.set_font('Arial', 'B', 12)
        pdf.multi_cell(0, 10, f"Description: {row.get('Description', 'N/A')}")
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 8, f"  Component: {row.get('Component', 'N/A')}")
        pdf.multi_cell(0, 8, f"  CVE ID: {row.get('CVE ID', 'N/A')}")
        pdf.multi_cell(0, 8, f"  CVSS Score: {row.get('CVSS', 'N/A')} ({row.get('Risk', 'Unknown')})")
        pdf.ln(5)
    return pdf.output(dest='S').encode('latin1')

def generate_csv_report(vuln_df: pd.DataFrame) -> bytes:
    if vuln_df.empty:
        return b""
    return vuln_df.to_csv(index=False).encode('utf-8')

def phishing_check(url):
    suspicious_keywords = ['login', 'verify', 'secure', 'bank', 'account', 'update', 'password']
    suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 'rb.gy']
    parsed = urlparse(url)
    host = parsed.hostname or ""
    score = 0
    if any(kw in url.lower() for kw in suspicious_keywords):
        score += 1
    if any(dom in host for dom in suspicious_domains):
        score += 2
    if len(host.split('.')) > 3:
        score += 1
    if score >= 2:
        return "Phishing Suspected"
    return "Safe"

def password_strength(password):
    import re
    suggestions = []
    score = 0
    if len(password) < 8:
        suggestions.append("Use at least 8 characters.")
    else:
        score += 1
    if not re.search(r"[A-Z]", password): suggestions.append("Add uppercase letters.")
    else: score += 1
    if not re.search(r"[a-z]", password): suggestions.append("Add lowercase letters.")
    else: score += 1
    if not re.search(r"[0-9]", password): suggestions.append("Add numbers.")
    else: score += 1
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): suggestions.append("Add special symbols.")
    else: score += 1
    if score <= 2: return "Weak", suggestions
    if score == 3: return "Medium", suggestions
    return "Strong", suggestions

# --- Branding & Styles ---
st.markdown("""
    <style>
    .css-1d391kg {padding-top:0;}
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .sidebar .sidebar-content {width: 240px;}
    @media only screen and (max-width: 600px) {
        .block-container {padding-left: 0.5rem; padding-right: 0.5rem;}
        .sidebar .sidebar-content {width: 100vw;}
    }
    </style>
""", unsafe_allow_html=True)

# --- Expected Outcomes Section ---
def expected_outcomes_card():
    icons = [
        "🛡️",  # Single platform
        "📑",  # Consolidated reports
        "🗺️",  # Visualized attack paths
        "👩‍💻", # User-friendly for all
    ]
    points = [
        "Single platform for multiple scanners",
        "Consolidated, structured vulnerability reports",
        "Visualized attack paths",
        "User-friendly interface for professionals or students"
    ]
    st.markdown(
        "<div style='background: #f2f5fa; border-radius:12px; box-shadow:0 2px 8px #0d253f15; margin-bottom:1rem; padding:1rem;'>"
        "<h4 style='margin-top:0; color:#0D253F;'>🚀 Expected Outcomes</h4>"
        "</div>",
        unsafe_allow_html=True
    )
    cols = st.columns(4)
    for i, col in enumerate(cols):
        col.markdown(
            f"<div style='text-align:center; padding:0.7rem 0; border-radius: 10px; background: #ecf0f7;'>"
            f"<span style='font-size:2.5rem'>{icons[i]}</span><br>"
            f"<span style='font-size:1rem; color:#0D253F; font-weight:500'>{points[i]}</span>"
            "</div>", unsafe_allow_html=True
        )

# --- Brand Header ---
st.markdown(
    '<div style="background: #0D253F; padding: 1rem 0 0.5rem 0; color: white; text-align:center; border-radius:8px 8px 0 0;">'
    '<h2 style="margin:0; letter-spacing:1px;">CyberShield</h2></div>',
    unsafe_allow_html=True
)

# --- Menu Sidebar ---
with st.sidebar:
    st.markdown(
        "<h3 style='color:#0D253F; text-align:left;'>Menu</h3>", unsafe_allow_html=True
    )
    page = st.radio(
        "",
        options=["Scanner", "Reporting", "Phishing Detection", "Password Strength Tester"],
        index=0,
        label_visibility="collapsed"
    )
    st.markdown("---")
    expected_outcomes_card()

# --- Main Expected Outcomes (for first-time users, always prominent) ---
expected_outcomes_card()

# --- Session State Initialization ---
if "scan_running" not in st.session_state:
    st.session_state.scan_running = False
if "phish_running" not in st.session_state:
    st.session_state.phish_running = False
if "pw_running" not in st.session_state:
    st.session_state.pw_running = False

# --- Scanner Page ---
if page == "Scanner":
    st.subheader("Scanner")
    st.info("Scan a website or upload a report file. Only scan sites you own or have permission to test.")
    vuln_report = []

    tab1, tab2 = st.tabs(["Scan Target", "Upload Report"])
    with tab1:
        with st.form("scan_form", clear_on_submit=False):
            target = st.text_input("Target URL or domain", value="")
            include_endpoints = st.checkbox("Include common endpoint checks", value=True)
            submit = st.form_submit_button("Start scan")

        if submit:
            if not target:
                st.error("Please provide a target domain or URL.")
            else:
                st.session_state.scan_running = True
                # Responsive scanning animation
                scan_placeholder = st.empty()
                progress_placeholder = st.empty()
                status_placeholder = st.empty()
                animation_steps = [
                    "Initializing scan...",
                    "Connecting to target...",
                    "Probing endpoints...",
                    "Analyzing headers...",
                    "Checking TLS/SSL...",
                    "Gathering vulnerability intelligence...",
                    "Finalizing report..."
                ]
                for i, text in enumerate(animation_steps):
                    progress = (i + 1) / len(animation_steps)
                    with scan_placeholder.container():
                        st.markdown(
                            f"<div style='text-align:center;padding-top:1rem;'>"
                            f"<span style='font-size:2.5rem;'>{'🔎' if i%2==0 else '🛡️'}</span><br>"
                            f"<span style='color:#0D253F;font-weight:500;font-size:1.2rem'>{text}</span>"
                            "</div>", unsafe_allow_html=True
                        )
                    progress_placeholder.progress(progress)
                    time.sleep(0.27)
                scan_placeholder.empty()
                progress_placeholder.empty()
                st.session_state.scan_running = False

                base = normalize_url(target)
                parsed = urlparse(base)
                hostname = parsed.hostname or ""
                st.success(f"Starting scan of: **{base}**")
                progress = st.progress(0.0)
                status_placeholder = st.empty()
                timer_placeholder = st.empty()
                steps = [
                    ("HTTP fetch", "http"),
                    ("Security headers", "sec_headers"),
                    ("TLS certificate", "tls"),
                    ("Robots & Sitemap", "robots"),
                    ("Common endpoints", "endpoints") if include_endpoints else None,
                    ("Summary & report", "summary")
                ]
                steps = [s for s in steps if s is not None]
                total_steps = len(steps)
                step_idx = [0]
                start_time = time.perf_counter()
                scan_report = {
                    "target": base,
                    "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
                    "results": {}
                }
                def advance(step_name):
                    step_idx[0] += 1
                    fraction = step_idx[0] / total_steps
                    progress.progress(fraction)
                    status_placeholder.info(f"Step {step_idx[0]}/{total_steps}: {step_name}")
                    elapsed = time.perf_counter() - start_time
                    timer_placeholder.markdown(f"**Elapsed:** {elapsed:.1f}s")
                with st.spinner("Fetching target..."):
                    advance("HTTP fetch")
                    http_info = fetch_headers(base)
                    scan_report["results"]["http_fetch"] = http_info
                    col1, col2, col3, col4 = st.columns(4)
                    code = http_info.get("status_code") if isinstance(http_info, dict) else None
                    col1.metric("Status code", code if code is not None else "Error")
                    col2.metric("Final URL", http_info.get("final_url") if isinstance(http_info, dict) else "—")
                    server_banner = None
                    if isinstance(http_info, dict) and "headers" in http_info:
                        server_banner = http_info["headers"].get("Server") or http_info["headers"].get("X-Powered-By")
                    col3.metric("Server banner", server_banner if server_banner else "Not exposed")
                    pres_cnt = 0
                    if isinstance(http_info, dict) and "headers" in http_info:
                        pres_cnt = sum([1 for h in SECURITY_HEADERS if h in http_info["headers"]])
                    col4.metric("Security headers present", f"{pres_cnt}/{len(SECURITY_HEADERS)}")
                with st.spinner("Analyzing security headers..."):
                    advance("Security headers")
                    sec = {}
                    if isinstance(http_info, dict) and "headers" in http_info:
                        sec = check_security_headers(http_info["headers"])
                    else:
                        sec = {"error": "No headers to analyze"}
                    scan_report["results"]["security_headers"] = sec
                    with st.expander("Security headers summary"):
                        if "error" in sec:
                            st.error(sec["error"])
                        else:
                            if sec["missing"]:
                                st.warning(f"Missing: {', '.join(sec['missing'])}")
                            else:
                                st.success("All security headers present.")
                            st.write("Present headers:")
                            st.json(sec.get("present", {}))
                tls_info = {}
                with st.spinner("Checking TLS certificate..."):
                    advance("TLS certificate")
                    if parsed.scheme == "https" and hostname:
                        tls_info = get_tls_certificate(hostname)
                        scan_report["results"]["tls"] = tls_info
                        if "error" in tls_info:
                            st.error(f"TLS check error: {tls_info['error']}")
                        else:
                            notAfter = tls_info.get("notAfter")
                            expire_dt = parse_cert_expiry(notAfter)
                            days_left = None
                            if expire_dt:
                                days_left = (expire_dt - datetime.datetime.utcnow()).days
                            col1, col2 = st.columns(2)
                            col1.subheader("Certificate expiry")
                            col1.write(f"Not after: {notAfter or 'Unknown'}")
                            if days_left is not None:
                                if days_left < 0:
                                    col1.error(f"Expired {abs(days_left)} day(s) ago")
                                elif days_left < 30:
                                    col1.warning(f"Expires in {days_left} day(s)")
                                else:
                                    col1.success(f"Expires in {days_left} day(s)")
                            col2.subheader("Certificate issuer / subject")
                            col2.write(tls_info.get("issuer"))
                            col2.write(tls_info.get("subject"))
                    else:
                        st.info("Target is not HTTPS or hostname not parsed; skipping TLS check.")
                        scan_report["results"]["tls"] = {"skipped": True}
                with st.spinner("Fetching robots.txt and sitemap.xml..."):
                    advance("Robots & Sitemap")
                    robots = fetch_robots_sitemap(base)
                    scan_report["results"]["robots_sitemap"] = robots
                    with st.expander("robots.txt & sitemap.xml details"):
                        st.json(robots)
                endpoints_res = {}
                if include_endpoints:
                    with st.spinner("Checking common endpoints..."):
                        advance("Common endpoints")
                        endpoints_res = check_common_endpoints(base)
                        scan_report["results"]["common_endpoints"] = endpoints_res
                        success_endpoints = []
                        for p, v in endpoints_res.items():
                            code = v.get("status_code") if isinstance(v, dict) else None
                            if isinstance(code, int) and 200 <= code < 300:
                                success_endpoints.append((p, code, v.get("final_url", "")))
                        if success_endpoints:
                            st.success(f"Accessible endpoints: {', '.join([p for p,_,_ in success_endpoints])}")
                            st.table([{"path": p, "status": c, "resolved_url": u} for p,c,u in success_endpoints])
                        else:
                            st.info("No common endpoints returned 2xx (or none accessible).")
                advance("Summary & report")
                elapsed_total = time.perf_counter() - start_time
                progress.progress(1.0)
                status_placeholder.success("Scan completed.")
                timer_placeholder.markdown(f"**Total elapsed:** {elapsed_total:.1f}s")
                st.header("Summary")
                summary_cols = st.columns(4)
                http_status = http_info.get("status_code") if isinstance(http_info, dict) else None
                summary_cols[0].metric("Reachable", "Yes" if isinstance(http_info, dict) and "headers" in http_info else "No")
                summary_cols[1].metric("HTTP status", http_status if http_status else "—")
                tls_status = "Skipped"
                if scan_report["results"].get("tls"):
                    if scan_report["results"]["tls"].get("error"):
                        tls_status = "Error"
                    elif scan_report["results"]["tls"].get("skipped"):
                        tls_status = "Skipped"
                    else:
                        na = scan_report["results"]["tls"].get("notAfter")
                        exp_dt = parse_cert_expiry(na)
                        if exp_dt:
                            days = (exp_dt - datetime.datetime.utcnow()).days
                            tls_status = f"{days} days left" if days is not None else "Valid"
                        else:
                            tls_status = "Valid (unknown expiry format)"
                summary_cols[2].metric("TLS", tls_status)
                missing = scan_report["results"].get("security_headers", {}).get("missing", [])
                summary_cols[3].metric("Missing security headers", len(missing))
                st.header("Recommendations")
                recs = []
                if missing:
                    recs.append("Add missing security headers.")
                if scan_report["results"].get("tls", {}).get("error"):
                    recs.append("Investigate TLS / certificate issues.")
                if server_banner:
                    recs.append("Consider hiding or limiting server banners.")
                robot_data = scan_report["results"].get("robots_sitemap", {}).get("/robots.txt", {})
                if robot_data.get("status_code") == 200:
                    recs.append("Review robots.txt; it is public.")
                if include_endpoints and scan_report["results"].get("common_endpoints"):
                    found = [p for p,v in scan_report["results"]["common_endpoints"].items() if isinstance(v, dict) and 200 <= v.get("status_code",0) < 300 and p != "/"]
                    if found:
                        recs.append(f"Accessible endpoints discovered: {', '.join(found)} — review access controls.")
                if not recs:
                    recs.append("No quick findings. For a deeper audit, perform a full security assessment.")
                for r in recs:
                    st.markdown("- " + r)
                st.header("Downloadable Reports")
                scan_report["elapsed_seconds"] = round(elapsed_total, 2)
                report_json = json.dumps(scan_report, indent=2, default=str)
                st.download_button("Download JSON report", data=report_json, file_name="cybershield_report.json", mime="application/json")
                with st.expander("Raw JSON report"):
                    st.code(report_json, language="json")
                st.header("Vulnerability Report")
                vuln_report = []
                if server_banner:
                    cve_data = fetch_cve_info(server_banner)
                    if cve_data:
                        st.table(cve_data)
                        vuln_report.extend(cve_data)
                    else:
                        st.info("No CVEs found for this component.")
                for missing_header in missing:
                    vuln_report.append({
                        "CVE ID": "N/A",
                        "CVSS": "N/A",
                        "Description": f"Missing security header: {missing_header}",
                        "Component": "Web Server"
                    })
                high_risk = highlight_attack_paths(vuln_report)
                if high_risk:
                    st.warning("High-risk vulnerabilities detected (CVSS >= 7):")
                    st.table(high_risk)
                else:
                    st.success("No high-risk vulnerabilities detected.")
                st.download_button(
                    "Download Vulnerability Report (JSON)",
                    data=json.dumps(vuln_report, indent=2),
                    file_name="vulnerability_report.json",
                    mime="application/json"
                )
                df_vuln = pd.DataFrame(vuln_report)
                if not df_vuln.empty:
                    df_vuln['Risk'] = df_vuln['CVSS'].apply(risk_level)
                    st.subheader("Vulnerability Table")
                    st.dataframe(df_vuln)
                    st.subheader("Vulnerabilities by Component")
                    comp_counts = df_vuln['Component'].value_counts()
                    fig1, ax1 = plt.subplots()
                    comp_counts.plot(kind='bar', ax=ax1)
                    ax1.set_ylabel("Count")
                    ax1.set_xlabel("Component")
                    st.pyplot(fig1)
                    st.subheader("Risk Level Distribution")
                    risk_counts = df_vuln['Risk'].value_counts()
                    fig2, ax2 = plt.subplots()
                    risk_counts.plot(kind='pie', autopct='%1.0f%%', ax=ax2)
                    ax2.set_ylabel("")
                    st.pyplot(fig2)
                    st.subheader("Summary Report")
                    st.markdown(f"- **Total vulnerabilities:** {len(df_vuln)}")
                    st.markdown(f"- **High risk:** {sum(df_vuln['Risk']=='High')}")
                    st.markdown(f"- **Medium risk:** {sum(df_vuln['Risk']=='Medium')}")
                    st.markdown(f"- **Low risk:** {sum(df_vuln['Risk']=='Low')}")
                    st.markdown(f"- **Unknown risk:** {sum(df_vuln['Risk']=='Unknown')}")
                    st.subheader("Export Vulnerability Report")
                    st.download_button(
                        "Download as CSV",
                        data=generate_csv_report(df_vuln),
                        file_name="vulnerability_report.csv",
                        mime="text/csv"
                    )
                    try:
                        pdf_bytes = generate_pdf_report(df_vuln)
                        st.download_button(
                            "Download as PDF",
                            data=pdf_bytes,
                            file_name="vulnerability_report.pdf",
                            mime="application/pdf"
                        )
                    except Exception as e:
                        st.info(f"PDF export error: {e}")
                else:
                    st.info("No vulnerabilities found to report.")
                if submit and 'results' in scan_report:
                    history = load_history()
                    history.insert(0, scan_report)
                    save_history(history)
                st.header("Attack Path Visualization")
                if vuln_report:
                    G = nx.DiGraph()
                    for v in vuln_report:
                        comp = v.get("Component", "Unknown")
                        desc = v.get("Description", "Vulnerability")
                        risk = v.get("CVSS", "N/A")
                        node_vuln = f"{desc[:30]}..." if len(desc) > 30 else desc
                        node_risk = f"Risk: {risk}"
                        G.add_node(comp, color='lightblue')
                        G.add_node(node_vuln, color='orange')
                        G.add_node(node_risk, color='red' if is_high_cvss(risk) else 'yellow')
                        G.add_edge(comp, node_vuln)
                        G.add_edge(node_vuln, node_risk)
                    pos = nx.spring_layout(G, k=0.5)
                    node_colors = [G.nodes[n].get('color', 'gray') for n in G.nodes()]
                    fig, ax = plt.subplots(figsize=(8, 5))
                    nx.draw(G, pos, with_labels=True, node_color=node_colors, ax=ax, font_size=8, arrows=True)
                    st.pyplot(fig)
                    st.markdown("**Attack path graph:** Components → Vulnerabilities → Risk levels")
                else:
                    st.info("No vulnerabilities to visualize attack paths.")

    with tab2:
        st.markdown("Upload a previously generated JSON report for quick review.")
        uploaded_file = st.file_uploader("Upload JSON report", type=["json"])
        if uploaded_file:
            try:
                data = json.load(uploaded_file)
                st.json(data)
            except Exception as e:
                st.error(f"Failed to load report: {e}")

# --- Reporting Page ---
elif page == "Reporting":
    st.subheader("Reporting")
    st.info("View previous scans and download reports.")
    history = load_history()
    if history:
        options = [
            f"{h.get('target', h.get('Target', 'Unknown'))} ({h.get('scanned_at', h.get('time', 'N/A'))})"
            for h in history
        ]
        selected = st.selectbox("Select a previous scan", options=options, index=0)
        idx = options.index(selected)
        prev = history[idx]
        st.write(f"Target: {prev.get('target', prev.get('Target', 'Unknown'))}")
        st.write(f"Scanned at: {prev.get('scanned_at', prev.get('time', 'N/A'))}")
        st.download_button("Download JSON", data=json.dumps(prev, indent=2), file_name="cybershield_report.json")
        if prev.get("results", {}).get("http_fetch", {}).get("headers"):
            server_banner = prev["results"]["http_fetch"]["headers"].get("Server") or prev["results"]["http_fetch"]["headers"].get("X-Powered-By")
        else:
            server_banner = None
        missing = prev.get("results", {}).get("security_headers", {}).get("missing", [])
        vuln_report = []
        if server_banner:
            cve_data = fetch_cve_info(server_banner)
            vuln_report.extend(cve_data)
        for missing_header in missing:
            vuln_report.append({
                "CVE ID": "N/A",
                "CVSS": "N/A",
                "Description": f"Missing security header: {missing_header}",
                "Component": "Web Server"
            })
        df_vuln = pd.DataFrame(vuln_report)
        if not df_vuln.empty:
            df_vuln['Risk'] = df_vuln['CVSS'].apply(risk_level)
            st.subheader("Vulnerability Table")
            st.dataframe(df_vuln)
            st.subheader("Export Vulnerability Report")
            st.download_button(
                "Download as CSV",
                data=generate_csv_report(df_vuln),
                file_name="vulnerability_report.csv",
                mime="text/csv"
            )
            try:
                pdf_bytes = generate_pdf_report(df_vuln)
                st.download_button(
                    "Download as PDF",
                    data=pdf_bytes,
                    file_name="vulnerability_report.pdf",
                    mime="application/pdf"
                )
            except Exception as e:
                st.info(f"PDF export error: {e}")
        else:
            st.info("No vulnerabilities found in this scan.")
    else:
        st.info("No scan history found.")

# --- Phishing Detection Page ---
elif page == "Phishing Detection":
    st.subheader("Phishing Detection")
    with st.form("phishing_form"):
        url = st.text_input("Enter URL to check", value="")
        submit = st.form_submit_button("Check")
    if submit:
        if not url:
            st.error("Please enter a URL.")
        else:
            st.session_state.phish_running = True
            scan_placeholder = st.empty()
            progress_placeholder = st.empty()
            animation_steps = [
                "Analyzing URL...",
                "Checking domain reputation...",
                "Scanning for suspicious patterns...",
                "Finalizing analysis..."
            ]
            for i, text in enumerate(animation_steps):
                progress = (i + 1) / len(animation_steps)
                with scan_placeholder.container():
                    st.markdown(
                        f"<div style='text-align:center;padding-top:1rem;'>"
                        f"<span style='font-size:2.5rem;'>{'🔗' if i%2==0 else '⚠️'}</span><br>"
                        f"<span style='color:#0D253F;font-weight:500;font-size:1.15rem'>{text}</span>"
                        "</div>", unsafe_allow_html=True
                    )
                progress_placeholder.progress(progress)
                time.sleep(0.28)
            scan_placeholder.empty()
            progress_placeholder.empty()
            st.session_state.phish_running = False

            result = phishing_check(url)
            if result == "Safe":
                st.success("Result: Safe (No phishing detected).")
            else:
                st.error("Result: Phishing Suspected! Be careful.")
            st.markdown(
                "**Note:** This tool uses basic heuristics and should not be used as a substitute for comprehensive anti-phishing solutions."
            )

# --- Password Strength Tester Page ---
elif page == "Password Strength Tester":
    st.subheader("Password Strength Tester")
    with st.form("pw_form"):
        password = st.text_input("Enter Password", value="", type="password")
        show_suggestions = st.checkbox("Show improvement suggestions", value=True)
        submit = st.form_submit_button("Test Strength")
    if submit:
        st.session_state.pw_running = True
        scan_placeholder = st.empty()
        progress_placeholder = st.empty()
        animation_steps = [
            "Analyzing password...",
            "Checking for length and complexity...",
            "Evaluating strength...",
            "Finalizing results..."
        ]
        for i, text in enumerate(animation_steps):
            progress = (i + 1) / len(animation_steps)
            with scan_placeholder.container():
                st.markdown(
                    f"<div style='text-align:center;padding-top:1rem;'>"
                    f"<span style='font-size:2.5rem;'>{'🔒' if i%2==0 else '🔑'}</span><br>"
                    f"<span style='color:#0D253F;font-weight:500;font-size:1.15rem'>{text}</span>"
                    "</div>", unsafe_allow_html=True
                )
            progress_placeholder.progress(progress)
            time.sleep(0.22)
        scan_placeholder.empty()
        progress_placeholder.empty()
        st.session_state.pw_running = False

        if not password:
            st.error("Please enter a password.")
        else:
            strength, suggestions = password_strength(password)
            color = {"Weak": "red", "Medium": "orange", "Strong": "green"}.get(strength, "gray")
            st.markdown(f"<h4>Password Strength: <span style='color:{color}'>{strength}</span></h4>", unsafe_allow_html=True)
            if show_suggestions and suggestions:
                st.markdown("**Suggestions:**")
                for s in suggestions:
                    st.markdown(f"- {s}")
            elif not suggestions:
                st.success("Great password! No improvement suggestions.")