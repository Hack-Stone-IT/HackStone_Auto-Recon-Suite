"""
HackStone Auto Recon Suite - Report Generator Module
Generates HTML, PDF, and JSON reports.
Developed by HackStone Cybersecurity Company.
"""

import os
import json
from jinja2 import Environment, FileSystemLoader
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

def generate_html(report_data):
    """Generate HTML report."""
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report_template.html')

    html_content = template.render(**report_data)

    target = report_data['target']
    os.makedirs(f'reports/{target}', exist_ok=True)
    with open(f'reports/{target}/HackStone_Report_{target}.html', 'w') as f:
        f.write(html_content)

    print("HTML report generated")

def generate_pdf(report_data):
    """Generate PDF report."""
    target = report_data['target']
    filename = f'reports/{target}/HackStone_Report_{target}.pdf'

    doc = SimpleDocTemplate(filename, pagesize=letter, leftMargin=0.75*inch, rightMargin=0.75*inch, topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []

    # HackStone Header with enhanced design
    header_style = ParagraphStyle('Header', parent=styles['Heading1'], fontSize=24, spaceAfter=10, alignment=1, textColor=colors.HexColor('#1a365d'), fontName='Helvetica-Bold')
    story.append(Paragraph("HACKSTONE AUTO RECON SUITE", header_style))
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=14, spaceAfter=15, alignment=1, textColor=colors.HexColor('#2b6cb0'), fontName='Helvetica-Bold')
    story.append(Paragraph("Automated Recon & Vulnerability Scanner", subtitle_style))
    story.append(Paragraph(f"Target: {target}", ParagraphStyle('Target', parent=styles['Normal'], fontSize=12, alignment=1, spaceAfter=10)))
    story.append(Paragraph("Developed by HackStone Cybersecurity Company", ParagraphStyle('Company', parent=styles['Normal'], fontSize=10, alignment=1, spaceAfter=20)))
    story.append(Spacer(1, 20))

    # Executive Summary
    exec_style = ParagraphStyle('ExecTitle', parent=styles['Heading2'], fontSize=16, spaceAfter=15, textColor=colors.HexColor('#2d3748'), fontName='Helvetica-Bold')
    story.append(Paragraph("Executive Summary", exec_style))
    summary_data = [
        ['Metric', 'Count'],
        ['Subdomains Found', str(len(report_data['subdomains']))],
        ['Open Ports', str(len(report_data['open_ports']))],
        ['Vulnerabilities Detected', str(len(report_data['vulnerabilities']))],
        ['Web Vulnerabilities Detected', str(len(report_data.get('web_vulnerabilities', [])))],
        ['Web Technologies Detected', str(len(report_data.get('web_technologies', [])))],
        ['Subdomain Takeover Vulnerabilities', str(len(report_data.get('subdomain_takeover', [])))],
        ['OS Fingerprint', report_data['os_info']],
        ['Directories/Files Found', str(len(report_data.get('dir_bruteforce', [])))]
    ]
    summary_table = Table(summary_data, colWidths=[250, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2d3748')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('FONTSIZE', (0,1), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE')
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 25))

    # Define section style once with enhanced design
    section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=16, spaceAfter=15, textColor=colors.HexColor('#2d3748'), fontName='Helvetica-Bold')

    # Subdomains
    if report_data['subdomains']:
        story.append(Paragraph("Discovered Subdomains", section_style))
        subdomain_data = [['Subdomain', 'IP Address']] + [[s.name, s.ip] for s in report_data['subdomains']]
        subdomain_table = Table(subdomain_data, colWidths=[280, 120])
        subdomain_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2d3748')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 11),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,1), (-1,-1), 9),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('WORDWRAP', (0,0), (-1,-1), True)
        ]))
        story.append(subdomain_table)
        story.append(Spacer(1, 20))

    # Open Ports
    if report_data['open_ports']:
        story.append(Paragraph("Open Ports", section_style))
        port_data = [['Port', 'Service', 'Banner']] + [[str(p.number), p.service, p.banner[:80] + '...' if len(p.banner) > 80 else p.banner] for p in report_data['open_ports']]
        port_table = Table(port_data, colWidths=[80, 120, 200])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2d3748')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 11),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,1), (-1,-1), 9),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('WORDWRAP', (0,0), (-1,-1), True)
        ]))
        story.append(port_table)
        story.append(Spacer(1, 20))
    else:
        story.append(Paragraph("Open Ports: None found", styles['Normal']))
        story.append(Spacer(1, 20))

    # Vulnerabilities
    if report_data['vulnerabilities']:
        story.append(Paragraph("Vulnerability Findings", section_style))
        vuln_data = [['Title', 'Severity', 'Description', 'Recommendation']]
        for v in report_data['vulnerabilities']:
            desc = v.description[:150] + '...' if len(v.description) > 150 else v.description
            rec = v.recommendation[:150] + '...' if len(v.recommendation) > 150 else v.recommendation
            vuln_data.append([v.title, v.severity, desc, rec])

        vuln_table = Table(vuln_data, colWidths=[120, 60, 140, 140])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkred),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('WORDWRAP', (0,0), (-1,-1), True)
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 20))
    else:
        story.append(Paragraph("Vulnerabilities: None detected", styles['Normal']))
        story.append(Spacer(1, 20))

    # OS Fingerprint
    story.append(Paragraph("OS Fingerprint", section_style))
    os_style = ParagraphStyle('OS', parent=styles['Normal'], fontSize=12, spaceAfter=20)
    story.append(Paragraph(f"Detected OS: {report_data['os_info']}", os_style))

    # Directory & File Bruteforce
    if report_data.get('dir_bruteforce'):
        story.append(Paragraph("Directory & File Bruteforce Findings", section_style))
        dir_data = [['Path', 'Status', 'Type', 'Listing', 'Sensitive']] + [[d['path'], str(d['status']), d['type'], 'Yes' if d['listing'] else 'No', 'Yes' if d['sensitive'] else 'No'] for d in report_data['dir_bruteforce']]
        dir_table = Table(dir_data, colWidths=[160, 60, 80, 60, 70])
        dir_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2d3748')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('WORDWRAP', (0,0), (-1,-1), True)
        ]))
        story.append(dir_table)
        story.append(Spacer(1, 20))
    else:
        story.append(Paragraph("Directory & File Bruteforce: None found", styles['Normal']))
        story.append(Spacer(1, 20))

    # Web Vulnerabilities
    if report_data.get('web_vulnerabilities'):
        story.append(Paragraph("Web Vulnerability Findings", section_style))
        web_vuln_data = [['Type', 'URL', 'Payload', 'Evidence']] + [[v['type'], v['url'][:60] + '...' if len(v['url']) > 60 else v['url'], v['payload'][:40] + '...' if len(v['payload']) > 40 else v['payload'], v['evidence'][:60] + '...' if len(v['evidence']) > 60 else v['evidence']] for v in report_data['web_vulnerabilities']]
        web_vuln_table = Table(web_vuln_data, colWidths=[80, 130, 110, 110])
        web_vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkred),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('WORDWRAP', (0,0), (-1,-1), True)
        ]))
        story.append(web_vuln_table)
        story.append(Spacer(1, 20))
    else:
        story.append(Paragraph("Web Vulnerabilities: None detected", styles['Normal']))
        story.append(Spacer(1, 20))

    # Web Technologies
    if report_data.get('web_technologies'):
        story.append(Paragraph("Web Technologies Detected", section_style))
        tech_data = [['Technology']] + [[tech] for tech in report_data['web_technologies']]
        tech_table = Table(tech_data, colWidths=[400])
        tech_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2d3748')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 12),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,1), (-1,-1), 10),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('WORDWRAP', (0,0), (-1,-1), True)
        ]))
        story.append(tech_table)
        story.append(Spacer(1, 20))
    else:
        story.append(Paragraph("Web Technologies: None detected", styles['Normal']))
        story.append(Spacer(1, 20))

    # Subdomain Takeover
    if report_data.get('subdomain_takeover'):
        story.append(Paragraph("Subdomain Takeover Vulnerabilities", section_style))
        takeover_data = [['Subdomain', 'CNAME', 'Service', 'Vulnerable']] + [[t['subdomain'], t['cname'], t['service'], 'Yes' if t['vulnerable'] else 'No'] for t in report_data['subdomain_takeover']]
        takeover_table = Table(takeover_data, colWidths=[130, 130, 80, 70])
        takeover_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.darkred),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('WORDWRAP', (0,0), (-1,-1), True)
        ]))
        story.append(takeover_table)
        story.append(Spacer(1, 20))
    else:
        story.append(Paragraph("Subdomain Takeover: None detected", styles['Normal']))
        story.append(Spacer(1, 20))

    # Screenshots
    if report_data.get('screenshots'):
        story.append(Paragraph("Captured Screenshots", section_style))
        screenshot_data = [['URL', 'Type', 'Path']] + [[s['url'], s['type'], s['path']] for s in report_data['screenshots']]
        screenshot_table = Table(screenshot_data, colWidths=[200, 80, 200])
        screenshot_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2d3748')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f7fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('FONTSIZE', (0,1), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('WORDWRAP', (0,0), (-1,-1), True)
        ]))
        story.append(screenshot_table)
        story.append(Spacer(1, 20))
    else:
        story.append(Paragraph("Screenshots: None captured", styles['Normal']))
        story.append(Spacer(1, 20))

    # Footer
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9, alignment=1, textColor=colors.grey, spaceAfter=5)
    story.append(Spacer(1, 30))
    story.append(Paragraph("Report generated by HackStone Auto Recon Suite v1.0", footer_style))
    story.append(Paragraph("HackStone Cybersecurity Company - Professional Security Assessment Tools", footer_style))

    doc.build(story)
    print("PDF report generated")

def save_json(report_data):
    """Save JSON log."""
    target = report_data['target']
    os.makedirs(f'reports/{target}', exist_ok=True)

    # Convert objects to dicts
    json_data = {
        'target': target,
        'subdomains': [{'name': s.name, 'ip': s.ip} for s in report_data['subdomains']],
        'open_ports': [{'number': p.number, 'service': p.service, 'banner': p.banner} for p in report_data['open_ports']],
        'vulnerabilities': [{'title': v.title, 'severity': v.severity, 'description': v.description, 'recommendation': v.recommendation} for v in report_data['vulnerabilities']],
        'web_vulnerabilities': report_data.get('web_vulnerabilities', []),
        'web_technologies': report_data.get('web_technologies', []),
        'subdomain_takeover': report_data.get('subdomain_takeover', []),
        'os_info': report_data['os_info'],
        'dir_bruteforce': report_data.get('dir_bruteforce', [])
    }

    with open(f'reports/{target}/scan_data.json', 'w') as f:
        json.dump(json_data, f, indent=4)

    print("JSON data saved")
