# ToolBox
安全研究渗透工具箱

## 目录
- [Android](#android)
- [Binary](#binary)
- [CTF](#ctf)
- [CVE](#cve)
- [IOT](#IOT)
- [Pentest](#pentest)
- [Web](#web)

## Android
安卓相关工具箱
* ACF
* AndBug - Android Debugging Library
* android_run_root_shell - android root 脚本
* android-backup-extractor - manifest backup属性问题测试工具
* android-forensics - Open source Android Forensics app and framework
* android-simg2img - Tool to convert Android sparse images to raw images
* AndroidEmbedIT - apk之间合并工具
* androwarn - Yet another static code analyzer for malicious Android applications
* ApkDetecter - Android Apk查壳工具
* APKiD - Android Application Identifier for Packers, Protectors, Obfuscators and Oddities - PEiD for Android
* ApkScan-APKID - apk查壳
* baksmali - back smali
* busybox - busybox
* dex2jar - dex to jar
* drozer - android渗透测试工具
* Dwarf - Full featured multi arch/os debugger built on top of PyQt5 and frida
* ESFileExplorerOpenVuln - es cve
* Jadx - jadx
* jd-gui - jd gui
* LabServer - Server component of the mobile labs
* manifestbin2xml - mainfest binary to xml
* MobSF - mobsf
* odexMutildexRev - multi dex reverse
* pyAndriller - Forensic data extraction and decoding tool for Android devices取证工具
* qark - 类似mobsf，渗透工具
* root-poc - root
* smail - to smali
* su-Binary - su二进制编译文件
* tcpdump-Binary - tcpdump二进制编译文件
* TraceReader - android 调用栈
* unpacker - 安卓脱壳脚本集

## Binary
* afl - american fuzzy lop(AFL) fuzz框架
* angr - Angr符号化执行框架
* detect-secrets - An enterprise friendly way of detecting and preventing secrets in code.
* difuze - Fuzzer for Linux Kernel Drivers
* darkvuf - virtualization based agentless black-box binary analysis system
* dyninst - Tools for binary instrumentation, analysis, and modificatio
* edb-debugger - linux debbuger
* ghidra - like IDA
* IDA - IDA
* libc-database - libc数据库
* LibcSearcher - 识别libc版本
* pintools - pin插桩
* pwndbg - gdb pwn插件
* PyAna - Analyzing the Windows shellcode
* syzkaller - an unsupervised coverage-guided kernel fuzzer
* trinity - Linux system call fuzzer
* uncompyle2 - python byte-code decompiler
* usb-device-fuzzing - usb fuzzer
* wifuzz - wifi fuzzer
* pwntools - pwn python插件
* ollvm - ollvm

## CTF
CTF学习，CTF脚本分享
* how2heap - heap漏洞利用学习

## CVE
日常遇到的CVE，poc，exp以供后续遇到使用
* dedecms
* dnsmasq
* ffmpeg-avi-m3u-xbin
* goahead
* iis
* imageaMagick
* joomula
* memcached
* zabbix_web

## IOT
IOT，硬件相关工具和软件
* bladeRF - bladeRF SDR
* blue_hydra - a Bluetooth device discovery service built on top of the bluez library
* buildroot - generate embedded Linux systems through cross-compilation构建IOT设备文件系统
* canbus - canbus协议工具
* firmwalker -Script for searching the extracted firmware file system for goodies查找固件中的敏感信息
* firmware-analysis-toolkit Toolkit to emulate firmware and analyse it for security vulnerabilities几个工具的集合
* firmware-mod-kit -  extract and rebuild linux based firmware images 类似QEMU集合脚本
* gnuradio - SDR
* gr-gsm - gsm嗅探工具
* imx_usb_loader - USB & UART loader for i.MX5/6/7/8 series
* kalibrate-bladeRF - kalibrate bladeRF支持，获取频率
* openlte - LTE
* pybombs - like apt for SDR
* SubversiveBTS - GSM/CDBA BTS
* ubertooth - bluetooth工具


## Pentest
渗透测试工具（recon，scanning，enumerate,system hack，Post pentest）
* Recon - 信息收集
  * SocialEngineer
    * blackeye - 钓鱼工具
  * SubDomain
    * Sublist3r - 从公共API上进行sub domain枚举
  * OSINT
    * gOSINT - golang osint 工具
    * GitHack - githack
    * github - github hack
    * GitMiner - gitminer命令行git数据泄漏
    * pagodo - google hack
    * pwnedOrNot - OSINT Tool to Find Passwords for Compromised Email Addresses
    * spiderfoot - spiderfoot
    * Zeus-Scanner - Advanced reconnaissance utility
* Scanning - 扫描工具
  * Dirs
    * dirsearch - dirsearch
  * Allscanner - 数据库和其他服务的弱端口的弱口令检测以及未授权访问的集成检测工具
  * AutoSploit - Automated Mass Exploiter
  * WpsScan - wordpress scanner
  * bscan - an asynchronous target enumeration tool
  * chomp-scan - reconnaissance scan
  * CMSmap - CMS指纹识别
  * dzscan - web vul scan
  * Sitadel - web application scanner
  * SRCHunter - 联合扫描
  * ssh-auditor - ssh弱密码扫描
  * ssrf - ssrf工具
  * w8scan - w8scan
  * w9scan - w9scan
  * WPSeku - Wordpress Security Scanner
* Enumerate
  * BruteForce - bruteforce 工具
  * ds_store_exp - ds_store泄漏工具
  * dvcs-ripper - dvcs各种工具
  * medusa - medusa爆破工具
  * patator - Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.
  * SvnHack - svn hack
* System hack
  * MysqlUDF - mysql getshell
* Post Pentest
  * Empire - Empire is a PowerShell and Python post-exploitation agent.
  * koadic - Koadic C3 COM Command & Control - JScript RAT
  * n00bRAT - Remote Administration Toolkit (or Trojan) for POSiX (Linux/Unix) system working as a Web Service
  * metasploit - msf

## Web
web相关工具，web漏洞，扫描工具，代码审计工具等
* Burpsuite - Burpsuite
* fiddler - fiddler
* sqlmap - sqlmap
* HQLmap - hql注入工具
* NoSQLMap - nosql注入
* tplmap - 模板注入
* owtf - owtf
* JavaID - java id
* AntSwords - webshell 工具
* cobra - cobra代码审计
* POC-T - poc漏洞利用工具（大部分为web）
* WebShell - webshell
* Jenkins - Jenkins
* Jetleak-Testing-Script - Jetleak
* jetty - jetty
* jexboss - jexboss
* mitmproxy - 代理工具
* Photon - photonjs
* phpenv - php环境配置切换工具
* phpRandom - php伪随机hack
* javaRandomHack - java伪随机hack
* phpvulhunter - php vul hack
* Postman - postman
* pyshell - pyshell
* Struts2 - s2
* WeBaCoo - Web Backdoor Cookie Script-Kit
* web-log-parser - web log parser

## Others
其他工具
* Bashfuscator - bash混淆工具
* dirscraper - 提取文件中疑似的link
* LinkFinder - 提取文件中疑似的link
* dnscat2  - dns隧道工具
* impacket - 各种协议客户端，服务器
* DNSTunnel - dns隧道
* gost - gost 代理工具
* RSB-Framework - reverse shell backdoor
* Sn1per - Automated pentest framework for offensive security experts
* tcpproxy - tcpproxy
* tidos-framework - The Offensive Manual Web Application Penetration Testing Framework
* trojanizer - Trojanize your payload - WinRAR (SFX) automatization - under Linux distros

## 工具部署
github上存在的项目默认会从github上拉取，部分非github工具将保存在该备份仓库中。
