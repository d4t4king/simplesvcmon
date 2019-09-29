import sys
import pprint
from termcolor import cprint,colored
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class mailer():

    def __init__(self, smtp_host='localhost'):
        self.smtp_host = smtp_host

    def send_scan_notice(self, to=None, _from=None, target=None, source=None, \
        engine=None, start=None):

        _subject = "Scanning {tar} beginning {st}".format( \
            tar=target, st=start)

        scan_type = None
        if 'masscan' in engine:
            scan_type = 'Network discovery scan'
        elif 'nmap' in engine:
            scan_type = 'Network discovery or host enumeration scan'

        text = "Automated server texting will be conducted "
        text += "on {tar} beginning {st}.".format(tar=target, st=start)

        body = """
<h3>TO WHOM IT MAY CONCERN:</h3>
<p>Automated server texting will be conducted on {tar} beginning {st}.</p>

<h3>OUTAGE:</h3>
<p>No outage is intended for this exercise.</p>

<h3>POTENTIAL IMPACT:</p>
<p>No anticipated impact.</p>

<h3>BACKPUT PLAN:</p>
<p>If any adverse reactions are observed that requires scanning to stop, please
call the Security Operation Center (SOC).</p>

<table style=\"border: 2px solid #000; padding 0px; margin: 0px;\">
<tr style=\"margine: 0px;\">
    <td style=\"text-align: center; background-color: #99ccff; font-weight:
bold; border: 1px solid #000;\">Target</td>
    <td style=\"text-align: center; background-color: #99ccff; font-weight:
bold; border: 1px solid #000;\">Source</td>
    <td style=\"text-align: center; background-color: #99ccff; font-weight:
bold; border: 1px solid #000;\">Component Engine</td>
    <td style=\"text-align: center; background-color: #99ccff; font-weight:
bold; border: 1px solid #000;\">Scan Type</td>
</tr>
<tr style=\"margin: 0px;\">
    <td style=\"text-align: center; padding: 0px; margin: 0px;
border: 1px solid #000;\">{tar}</td>
    <td style=\"text-align: center; padding: 0px; margin: 0px;
border: 1px solid #000;\">{src}</td>
    <td style=\"text-align: center; padding: 0px; margin: 0px;
border: 1px solid #000;\">{eng}</td>
    <td style=\"text-align: center; padding: 0px; margin: 0px;
border: 1px solid #000;\">{typ}</td>
</tr>
</table>
<p>Thank you for your time.</p>
""".format(st=start, tar=target, src=source, eng=engine, typ=scan_type)

        msg = MIMEMultipart('alternative')
        msg['Subject'] = _subject
        msg['From'] = _from
        msg['To'] = to

        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(body, 'html')

        msg.attach(part1)
        msg.attach(part2)

        s = smtplib.SMTP(self.smtp_host)
        s.sendmail(_from, to, msg.as_string())
        s.quit()
