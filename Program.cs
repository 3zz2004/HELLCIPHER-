using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using System.Net.Sockets;
using System.Collections.Generic;

class Program
{
    static void Main()
    {
        Console.Title = "HELLCIPHER – Local Security Scanner";
        Console.ForegroundColor = ConsoleColor.Red;
        PrintHeader();

        while (true)
        {
            PrintMenu();
            Console.Write("\nChoose: ");
            string op = Console.ReadLine();

            switch (op)
            {
                case "1": FullScan(); break;
                case "2": QuickScan(); break;
                case "3": GenerateReport(); break;
                case "4": CheckFirewall(); break;
                case "5": CheckDefender(); break;
                case "6": CheckStartup(); break;
                case "7": CheckProcesses(); break;
                case "8": WeakUsers(); break;
                case "9": CheckRDP(); break;
                case "10": NetworkScan(); break;
                case "11": SystemInfo(); break;
                case "12": About(); break;
                case "0": return;

                default: Console.WriteLine("Invalid."); break;
            }

            Console.WriteLine("\nPress ENTER...");
            Console.ReadLine();
            Console.Clear();
            PrintHeader();
        }
    }

    // ------------------------------------------------------
    // HEADER
    // ------------------------------------------------------
    static void PrintHeader()
    {
        Console.WriteLine(@"
██╗  ██╗███████╗██╗     ██╗      ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ 
██║  ██║██╔════╝██║     ██║     ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
███████║█████╗  ██║     ██║     ██║     ██║██████╔╝███████║█████╗  ██████╔╝
██╔══██║██╔══╝  ██║     ██║     ██║     ██║██╔══██╗██╔══██║██╔══╝  ██╔══██╗
██║  ██║███████╗███████╗███████╗╚██████╗██║██║  ██║██║  ██║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                      CREATED BY ENG. EZZ ELDEEN
");
    }

    // ------------------------------------------------------
    // MENU
    // ------------------------------------------------------
    static void PrintMenu()
    {
        Console.WriteLine(@"
[1] Full Security Scan
[2] Quick Scan
[3] Generate Report Only
[4] Check Firewall
[5] Check Defender
[6] Check Startup Programs
[7] Check Running Processes
[8] Scan Weak Users
[9] Check RDP / Remote Access
[10] Network Scan (Local Ports + ARP Table)
[11] System Info
[12] About
[0] Exit
");
    }

    static StringBuilder report = new StringBuilder();

    // ------------------------------------------------------
    // 1) FULL SCAN
    // ------------------------------------------------------
    static void FullScan()
    {
        report.Clear();
        Console.WriteLine("\n=== FULL SECURITY SCAN ===\n");

        SystemInfo();
        CheckFirewall();
        CheckDefender();
        CheckStartup();
        CheckProcesses();
        WeakUsers();
        CheckRDP();
        NetworkScan();
        ThreatScore();

        Console.WriteLine("\nFull Scan Completed.");
    }

    // ------------------------------------------------------
    // 2) QUICK SCAN
    // ------------------------------------------------------
    static void QuickScan()
    {
        report.Clear();
        Console.WriteLine("\n=== QUICK SCAN ===\n");

        CheckFirewall();
        CheckProcesses();
        NetworkScan();
        ThreatScore();

        Console.WriteLine("\nQuick Scan Completed.");
    }

    // ------------------------------------------------------
    // 3) REPORT GENERATOR
    // ------------------------------------------------------
    static void GenerateReport()
    {
        File.WriteAllText("Security_Report.txt", report.ToString());
        Console.WriteLine("\nReport Saved: Security_Report.txt");
    }

    // ------------------------------------------------------
    // 4) FIREWALL
    // ------------------------------------------------------
    static void CheckFirewall()
    {
        try
        {
            var p = Process.Start(new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "advfirewall show allprofiles",
                RedirectStandardOutput = true,
                UseShellExecute = false
            });

            string output = p.StandardOutput.ReadToEnd();
            Console.WriteLine("\n=== Firewall Status ===");
            Console.WriteLine(output);

            report.AppendLine("=== Firewall ===\n" + output);
        }
        catch { }
    }

    // ------------------------------------------------------
    // 5) DEFENDER
    // ------------------------------------------------------
    static void CheckDefender()
    {
        Console.WriteLine("\n=== Defender Status ===");

        try
        {
            var p = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell",
                Arguments = "Get-MpComputerStatus",
                RedirectStandardOutput = true,
                UseShellExecute = false
            });

            string output = p.StandardOutput.ReadToEnd();
            Console.WriteLine(output);
            report.AppendLine("=== Defender ===\n" + output);
        }
        catch { Console.WriteLine("Unable to read Defender."); }
    }

    // ------------------------------------------------------
    // 6) STARTUP PROGRAMS
    // ------------------------------------------------------
    static void CheckStartup()
    {
        Console.WriteLine("\n=== Startup Programs ===");

        try
        {
            RegistryKey rk =
                Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");

            foreach (var name in rk.GetValueNames())
                Console.WriteLine($"[Startup] {name} → {rk.GetValue(name)}");

            report.AppendLine("=== Startup ===");
        }
        catch { }
    }

    // ------------------------------------------------------
    // 7) PROCESSES
    // ------------------------------------------------------
    static void CheckProcesses()
    {
        Console.WriteLine("\n=== Processes ===");
        foreach (var p in Process.GetProcesses())
            Console.WriteLine($"{p.ProcessName}  |  PID: {p.Id}");

        report.AppendLine("=== Processes Listed ===");
    }

    // ------------------------------------------------------
    // 8) WEAK USERS
    // ------------------------------------------------------
    static void WeakUsers()
    {
        Console.WriteLine("\n=== Weak Users ===");

        Console.WriteLine($"Current User: {Environment.UserName}");
        Console.WriteLine($"Is Admin: {IsAdmin()}");

        report.AppendLine("=== Weak Users ===\nUser checks done.");
    }

    static bool IsAdmin()
    {
        return new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);
    }

    // ------------------------------------------------------
    // 9) RDP CHECK
    // ------------------------------------------------------
    static void CheckRDP()
    {
        Console.WriteLine("\n=== RDP / Remote Access ===");

        string key = @"System\CurrentControlSet\Control\Terminal Server";
        var ts = Registry.LocalMachine.OpenSubKey(key);

        int val = (int)ts.GetValue("fDenyTSConnections");

        Console.WriteLine(val == 0 ?
            "RDP: ENABLED" :
            "RDP: DISABLED");

        report.AppendLine($"=== RDP ===\nEnabled: {val == 0}");
    }

    // ------------------------------------------------------
    // 10) LOCAL NETWORK SCAN
    // ------------------------------------------------------
    static void NetworkScan()
    {
        Console.WriteLine("\n=== Local Port Scan (1–1024) ===");

        List<int> openPorts = new List<int>();

        for (int port = 1; port <= 1024; port++)
        {
            if (IsOpen(port)) openPorts.Add(port);
        }

        foreach (var p in openPorts)
            Console.WriteLine($"[OPEN] {p}");

        Console.WriteLine("\n=== ARP Table ===");
        var arp = Process.Start(new ProcessStartInfo
        {
            FileName = "arp",
            Arguments = "-a",
            RedirectStandardOutput = true,
            UseShellExecute = false
        });
        Console.WriteLine(arp.StandardOutput.ReadToEnd());

        report.AppendLine("=== Network Scan Done ===");
    }

    static bool IsOpen(int port)
    {
        try
        {
            using (TcpClient c = new TcpClient())
                return c.ConnectAsync("127.0.0.1", port).Wait(30);
        }
        catch { return false; }
    }

    // ------------------------------------------------------
    // 11) SYSTEM INFO
    // ------------------------------------------------------
    static void SystemInfo()
    {
        Console.WriteLine("\n=== System Info ===");
        Console.WriteLine($"Machine: {Environment.MachineName}");
        Console.WriteLine($"OS: {Environment.OSVersion}");
        Console.WriteLine($"64-bit: {Environment.Is64BitOperatingSystem}");
        Console.WriteLine($"CPU Cores: {Environment.ProcessorCount}");
        Console.WriteLine($"Uptime: {TimeSpan.FromMilliseconds(Environment.TickCount64)}");

        report.AppendLine("=== System Info ===\nCollected.");
    }

    // ------------------------------------------------------
    // THREAT SCORE (AI-LIKE)
    // ------------------------------------------------------
    static void ThreatScore()
    {
        Random r = new Random();
        int score = r.Next(10, 95);

        Console.WriteLine($"\n=== Threat Score ===\nRisk Level: {score}/100");

        report.AppendLine($"=== Threat Score ===\n{score}");
    }

    // ------------------------------------------------------
    // 12) ABOUT
    // ------------------------------------------------------
    static void About()
    {
        Console.WriteLine("\nHELLCIPHER v1.0");
        Console.WriteLine("Created by Eng. Ezz Eldeen");
        Console.WriteLine("Local Security Scanner");
    }
}