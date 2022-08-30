# Eternalghost
* [Deutsch](#deutsch)
* [English](#english)
                                    
## Deutsch
Dieses Repository enthält einen Testfall für CVE-2020-0796

Mit diesem kleinen Skript können Sie überprüfen, ob ein Server von Ihnen verwundbar ist. Das Skript prüft, ob Sie Compression aktiviert haben und die SMB-Version 3.1.1 ist. Das ganze geschieht über einen "negotiate request".

### Wie man dieses Skript benutzt
<code> python3 eternalghost.py IP </code>

### Umgehungslösungen
[Microsoft-Hinweis zum Deaktivieren der SMBv3-Komprimierung - Englisch](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/adv200005)

<code> Set-ItemProperty -Pfad "HKLM:\SYSTEM\CurrentControlSet\Dienste\LanmanServer\Parameter" Deaktivieren der Kompression -Typ DWORD -Wert 1 -Kraft </code>

#### Anmerkungen
Wenn Sie eine Perimeter-Firewall haben, sollten Sie in Betracht ziehen, den TCP-Port 445 zu blockieren. Systeme sind von außen nicht anfällig, wenn Sie den Port blockieren. **Sie sind weiterhin von innerhalb des Unternehmens-Perimeters verwundbar**.

Da es sich um einen "wurmstichigen" Angriff handelt, sollten Sie auch den SMB-Verkehr von seitlichen Verbindungen und den Eintritt oder Austritt aus Ihrem Netzwerk verhindern.
[Verhindern von unkontrolliertem SMB Verkehr in Ihrem Netzwerk](https://support.microsoft.com/en-us/help/3185535/preventing-smb-traffic-from-lateral-connections)

Nähere Informationen finden Sie auf dem [AWARE7 Blog](https://aware7.com/de/blog/eternaldarkness-kritische-sicherheitsluecke-bei-windows-10/)

### Derzeit anfällige Systeme

* Windows 10 Version 1903 für 32-Bit-Systeme		 	 
* Windows 10 Version 1903 für ARM64-basierte Systeme		 	 
* Windows 10 Version 1903 für x64-basierte Systeme		 
* Windows 10 Version 1909 für 32-Bit-Systeme	
* Windows 10 Version 1909 für ARM64-basierte Systeme
* Windows 10 Version 1909 für x64-basierte Systeme
* Windows Server, Version 1903 (Server Core-Installation)
* Windows Server, Version 1909 (Server Core-Installation)

Im Rahmen unserer [Pentetrationstests](https://aware7.com/de/blog/eternaldarkness-kritische-sicherheitsluecke-bei-windows-10/) überprüfen wir Ihre Systeme auch auf diese Schwachstelle.

## English
This repository contains a test case for CVE-2020-0796

With this small script you can check wether a server of yours is vulnerable. The script checks for compression capability and SMB version 3.1.1 via a negotiate request.

### How to use this script
<code> python3 eternalghost.py IP </code>

### Workarounds
[Microsoft Advisory on Disabling SMBv3 compression](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/adv200005)

<code> Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force </code>

#### Notes
If you have a perimeter firewall you should consider blocking TCP port 445. Systems are not vulnerable from the outside, if you block this port. **You will still be vulnerable from within the enterprise perimeter**

Since the attack is "wormable" you should also prevent SMB traffic from lateral connections and entering or leaving your network.
[Preventing SMB traffic from lateral connections and entering/leaving your network](https://support.microsoft.com/en-us/help/3185535/preventing-smb-traffic-from-lateral-connections)

Find more information on our [AWARE7 blog](https://aware7.com/blog/eternaldarkness-critical-vulnerability-in-windows-10/)

### Currently Vulnerable Systems

* Windows 10 Version 1903 for 32-bit Systems		 	 
* Windows 10 Version 1903 for ARM64-based Systems		 	 
* Windows 10 Version 1903 for x64-based Systems		 
* Windows 10 Version 1909 for 32-bit Systems	
* Windows 10 Version 1909 for ARM64-based Systems
* Windows 10 Version 1909 for x64-based Systems
* Windows Server, version 1903 (Server Core installation)
* Windows Server, version 1909 (Server Core installation)

As part of our [penetration tests](https://aware7.com/blog/eternaldarkness-critical-vulnerability-in-windows-10/), we also check your systems for this vulnerability.
