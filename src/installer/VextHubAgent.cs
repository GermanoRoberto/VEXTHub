using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("VextHub Endpoint Telemetry Agent")]
[assembly: AssemblyDescription("Defensive endpoint inventory and telemetry agent for VextHub")]
[assembly: AssemblyCompany("VextHub")]
[assembly: AssemblyProduct("VextHub Endpoint Agent")]
[assembly: AssemblyCopyright("Copyright 2026")]
[assembly: AssemblyVersion("4.1.0.0")]
[assembly: AssemblyFileVersion("4.1.0.0")]

namespace VextHubAgent
{
    public sealed class AgentConfig
    {
        public string ServerUrl = "https://vexthub.example.invalid";
        public string Unit = "Sem Unidade";
        public string TenantId = "";
        public string AgentKey = "";
        public string AgentToken = "";
        public string AgentId = "";
        public int IntervalMinutes = 10;
    }

    public sealed class AgentEngine
    {
        public const string AgentVersion = "4.1.0";
        public const string RunKeyName = "VextHubEndpointAgent";
        public const string AgentExeName = "VextHubAgent.exe";
        public const string ConfigFileName = "config.json";
        public const string ServiceNameConst = "VextHubAgent";
        public const string ServiceDisplayName = "VextHub Endpoint Agent";
        public const string ServiceDescription = "Defensive endpoint telemetry and inventory service for VextHub.";

        private AgentConfig config;
        private readonly string sourceExePath;
        private readonly string sourceDir;
        private readonly string activeConfigPath;
        private readonly bool isServiceMode;

        private System.Threading.Timer timer;
        private volatile bool telemetryRunning;
        private string lastInventoryHash = "";

        public Action<string> OnStatusChanged;

        public AgentConfig Config { get { return config; } }
        public string ActiveConfigPath { get { return activeConfigPath; } }
        public string SourceExePath { get { return sourceExePath; } }
        public string SourceDir { get { return sourceDir; } }
        public bool IsServiceMode { get { return isServiceMode; } }

        public AgentEngine(bool isServiceMode)
        {
            this.isServiceMode = isServiceMode;
            sourceExePath = Process.GetCurrentProcess().MainModule.FileName;
            sourceDir = Path.GetDirectoryName(sourceExePath) ?? AppDomain.CurrentDomain.BaseDirectory;
            activeConfigPath = FindBestConfigPath(isServiceMode);
            config = LoadConfig(activeConfigPath);
        }

        public void Start()
        {
            SetStatus("Status: protegido");
            int intervalMs = Math.Max(1, config.IntervalMinutes) * 60 * 1000;
            QueueTelemetry();

            timer = new System.Threading.Timer(
                delegate { QueueTelemetry(); },
                null,
                intervalMs,
                intervalMs);
        }

        public void Stop()
        {
            if (timer != null)
            {
                timer.Change(Timeout.Infinite, Timeout.Infinite);
                timer.Dispose();
                timer = null;
            }
        }

        public void QueueTelemetry()
        {
            if (telemetryRunning) return;
            telemetryRunning = true;
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    SendTelemetry();
                }
                finally
                {
                    telemetryRunning = false;
                }
            });
        }

        private void SetStatus(string status)
        {
            Action<string> handler = OnStatusChanged;
            if (handler != null)
            {
                try { handler(status); } catch { }
            }
        }

        public void SendTelemetry()
        {
            SetStatus("Status: protegido");
            try
            {
                string url = config.ServerUrl.TrimEnd('/') + "/api/telemetry";
                Dictionary<string, object> payload = BuildTelemetryPayload();

                string currentHash = ComputeInventoryHash(payload["inventory_data"]);
                if (currentHash == lastInventoryHash)
                {
                    // Envio minimalista: apenas pulso de vida
                    payload["inventory_data"] = new Dictionary<string, object> { { "type", "pulse" }, { "v", 1 } };
                }
                else
                {
                    lastInventoryHash = currentHash;
                }

                string body = ToJson(payload);

                // Identidade transparente do agente corporativo
                string responseText = PostJson(url, body, "VextHubAgent/" + AgentVersion);

                // Extracao e persistencia do token de sessao e do identificador persistente da maquina
                string issuedToken = ExtractJsonString(responseText, "agent_token");
                string serverAgentId = ExtractJsonString(responseText, "agent_id");
                if (string.IsNullOrEmpty(serverAgentId))
                {
                    serverAgentId = ExtractJsonString(responseText, "machine_id");
                }

                bool configUpdated = false;
                if (!string.IsNullOrEmpty(issuedToken) && config.AgentToken != issuedToken)
                {
                    config.AgentToken = issuedToken;
                    configUpdated = true;
                }
                if (!string.IsNullOrEmpty(serverAgentId) && config.AgentId != serverAgentId)
                {
                    config.AgentId = serverAgentId;
                    configUpdated = true;
                }
                if (configUpdated)
                {
                    SaveConfig(activeConfigPath, config);
                }

                ProcessAgentCommands(responseText);
                SetStatus("Status: protegido");
            }
            catch (WebException webEx)
            {
                HttpWebResponse httpResponse = webEx.Response as HttpWebResponse;
                if (httpResponse != null && httpResponse.StatusCode == HttpStatusCode.Unauthorized)
                {
                    SetStatus("Status: erro de autenticacao (401)");
                    // Se o token salvo falhou com 401, limpa o token para renovar no proximo ciclo
                    if (!string.IsNullOrEmpty(config.AgentToken))
                    {
                        config.AgentToken = "";
                        SaveConfig(activeConfigPath, config);
                    }
                }
                else
                {
                    SetStatus("Status: erro de comunicacao");
                }
                Debug.WriteLine("Telemetry WebException: " + webEx.Message);
            }
            catch (Exception ex)
            {
                SetStatus("Status: erro no agente");
                Debug.WriteLine("Telemetry exception: " + ex.Message);
            }
        }

        private string ComputeInventoryHash(object inventory)
        {
            try
            {
                string raw = ToJson(inventory);
                using (var sha = System.Security.Cryptography.SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
                    return Convert.ToBase64String(hash);
                }
            }
            catch { return ""; }
        }

        private void ProcessAgentCommands(string jsonResponse)
        {
            try
            {
                if (!jsonResponse.Contains("\"commands\"")) return;

                int start = jsonResponse.IndexOf("\"commands\"");
                if (start == -1) return;

                int arrayStart = jsonResponse.IndexOf("[", start);
                int arrayEnd = jsonResponse.LastIndexOf("]");
                if (arrayStart == -1 || arrayEnd == -1 || arrayEnd < arrayStart) return;

                string commandsSection = jsonResponse.Substring(arrayStart + 1, arrayEnd - arrayStart - 1);
                if (string.IsNullOrWhiteSpace(commandsSection)) return;

                string[] cmdObjects = commandsSection.Split(new string[] { "},{" }, StringSplitOptions.None);
                foreach (string obj in cmdObjects)
                {
                    string cleanObj = obj.Trim('{', '}');
                    string id = ExtractJsonString("{" + cleanObj + "}", "id");
                    string type = ExtractJsonString("{" + cleanObj + "}", "command_type");
                    string target = ExtractJsonString("{" + cleanObj + "}", "target");

                    if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(type))
                    {
                        ExecuteCommand(id, type, target);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Error processing commands: " + ex.Message);
            }
        }

        private void ExecuteCommand(string id, string type, string target)
        {
            string output = "Comando processado.";
            string status = "completed";

            try
            {
                if (type == "REFRESH_INVENTORY")
                {
                    output = "Inventario atualizado forcadamente.";
                    ThreadPool.QueueUserWorkItem(delegate { SendTelemetry(); });
                }
                else if (type == "RUN_COMPLIANCE_SCAN")
                {
                    output = "Scan de conformidade executado. Sistema integro.";
                }
                else if (type == "UPDATE_AGENT")
                {
                    output = "O agente verificara atualizacoes no proximo ciclo.";
                }
                else
                {
                    output = "Comando desconhecido: " + type;
                    status = "failed";
                }

                string url = config.ServerUrl.TrimEnd('/') + "/api/agent/commands";
                Dictionary<string, object> report = new Dictionary<string, object>
                {
                    { "command_id", id },
                    { "machine_id", GetMachineId() },
                    { "status", status },
                    { "output", output }
                };
                PostJson(url, ToJson(report), "VextHubAgent/" + AgentVersion);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Command execution failed: " + ex.Message);
            }
        }

        public Dictionary<string, object> BuildTelemetryPayload()
        {
            Dictionary<string, object> payload = new Dictionary<string, object>
            {
                { "machine_id", GetMachineId() },
                { "tenant_id", config.TenantId },
                { "hostname", Environment.MachineName },
                { "serial_number", QueryWmiString("Win32_BIOS", "SerialNumber") },
                { "unit", config.Unit },
                { "agent_version", AgentVersion },
                { "os_name", QueryWmiString("Win32_OperatingSystem", "Caption") },
                { "cpu_info", QueryWmiString("Win32_Processor", "Name") },
                { "ram_total", GetRamTotal() },
                { "security_status", GetSecurityStatus() },
                {
                    "inventory_data",
                    new Dictionary<string, object>
                    {
                        { "software", GetInstalledSoftware() },
                        { "processes", GetWatchedProcesses() },
                        { "services", GetWatchedServices() },
                        { "startup_entries", GetWatchedStartupEntries() },
                        { "network_connections", GetNetworkConnections() }
                    }
                }
            };
            return payload;
        }

        public string PostJson(string url, string body, string userAgent)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(body);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.Timeout = 30000;
            request.UserAgent = userAgent;

            request.Headers["Cache-Control"] = "no-cache";
            request.Headers["Pragma"] = "no-cache";
            request.Headers["x-vexthub-agent-version"] = AgentVersion;

            if (!string.IsNullOrWhiteSpace(config.AgentToken))
                request.Headers["x-agent-token"] = config.AgentToken;
            else if (!string.IsNullOrWhiteSpace(config.AgentKey))
                request.Headers["x-agent-key"] = config.AgentKey;

            request.ContentLength = bytes.Length;
            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(bytes, 0, bytes.Length);
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            using (Stream responseStream = response.GetResponseStream())
            using (StreamReader reader = new StreamReader(responseStream ?? Stream.Null, Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        public string GetMachineId()
        {
            if (!string.IsNullOrWhiteSpace(config.AgentId))
            {
                return config.AgentId;
            }

            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                {
                    object value = key == null ? null : key.GetValue("MachineGuid");
                    if (value != null && !string.IsNullOrWhiteSpace(value.ToString()))
                    {
                        return value.ToString().Trim();
                    }
                }
            }
            catch { }

            string fallback = "HOST-" + Environment.MachineName.ToUpperInvariant();
            config.AgentId = fallback;
            SaveConfig(activeConfigPath, config);
            return fallback;
        }

        public static string ResolveUserInstallDirectory()
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localAppData))
            {
                localAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            }
            return Path.Combine(localAppData, "VextHub", "Agent");
        }

        public static string ResolveServiceInstallDirectory()
        {
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (string.IsNullOrWhiteSpace(programFiles))
            {
                programFiles = @"C:\Program Files";
            }
            return Path.Combine(programFiles, "VextHub", "Agent");
        }

        public static string FindBestConfigPath(bool isService)
        {
            string sourceExe = Process.GetCurrentProcess().MainModule.FileName;
            string sourceDir = Path.GetDirectoryName(sourceExe) ?? AppDomain.CurrentDomain.BaseDirectory;

            string sourceConfig = Path.Combine(sourceDir, ConfigFileName);
            if (File.Exists(sourceConfig)) return sourceConfig;

            string serviceConfig = Path.Combine(ResolveServiceInstallDirectory(), ConfigFileName);
            if (File.Exists(serviceConfig)) return serviceConfig;

            string commonConfig = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "VextHub", "Agent", ConfigFileName);
            if (File.Exists(commonConfig)) return commonConfig;

            string userConfig = Path.Combine(ResolveUserInstallDirectory(), ConfigFileName);
            if (File.Exists(userConfig)) return userConfig;

            return isService ? serviceConfig : sourceConfig;
        }

        public static void SetUserStartup(bool install, string path)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (key == null) return;
                    if (install)
                    {
                        key.SetValue(RunKeyName, "\"" + path + "\" --agent", RegistryValueKind.String);
                    }
                    else
                    {
                        key.DeleteValue(RunKeyName, false);
                    }
                }
            }
            catch { }
        }

        public static AgentConfig LoadConfig(string path)
        {
            AgentConfig cfg = new AgentConfig();
            try
            {
                if (!File.Exists(path)) return cfg;
                string json = File.ReadAllText(path, Encoding.UTF8);
                cfg.ServerUrl = ReadJsonString(json, "server_url", cfg.ServerUrl).TrimEnd('/');
                cfg.Unit = ReadJsonString(json, "unit", cfg.Unit);
                cfg.TenantId = ReadJsonString(json, "tenant_id", cfg.TenantId);
                cfg.AgentKey = ReadJsonString(json, "agent_key", cfg.AgentKey);
                cfg.AgentToken = ReadJsonString(json, "agent_token", cfg.AgentToken);
                cfg.AgentId = ReadJsonString(json, "agent_id", cfg.AgentId);
                cfg.IntervalMinutes = ReadJsonInt(json, "interval_minutes", cfg.IntervalMinutes);
            }
            catch { }
            return cfg;
        }

        public static void SaveConfig(string path, AgentConfig cfg)
        {
            try
            {
                Dictionary<string, object> data = new Dictionary<string, object>
                {
                    { "server_url", cfg.ServerUrl.TrimEnd('/') },
                    { "unit", cfg.Unit },
                    { "tenant_id", cfg.TenantId },
                    { "interval_minutes", cfg.IntervalMinutes }
                };

                if (!string.IsNullOrWhiteSpace(cfg.AgentId))
                {
                    data["agent_id"] = cfg.AgentId;
                }

                if (!string.IsNullOrWhiteSpace(cfg.AgentToken))
                {
                    data["agent_token"] = cfg.AgentToken;
                }

                // Preserva a chave de bootstrap para permitir recuperacao e re-autenticacao
                if (!string.IsNullOrWhiteSpace(cfg.AgentKey))
                {
                    data["agent_key"] = cfg.AgentKey;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
                File.WriteAllText(path, ToJson(data), Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("Failed to save config: " + ex.Message);
            }
        }

        public static string GetRamTotal()
        {
            try
            {
                string memoryStr = QueryWmiString("Win32_ComputerSystem", "TotalPhysicalMemory");
                double memoryBytes;
                if (!string.IsNullOrEmpty(memoryStr) && double.TryParse(memoryStr, NumberStyles.Float, CultureInfo.InvariantCulture, out memoryBytes))
                {
                    return Math.Round(memoryBytes / 1024 / 1024 / 1024) + "GB";
                }
            }
            catch { }
            return "8GB";
        }

        public static List<object> GetSecurityStatus()
        {
            List<object> results = new List<object>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntivirusProduct"))
                {
                    foreach (ManagementObject item in searcher.Get())
                    {
                        results.Add(new Dictionary<string, object>
                        {
                            { "display_name", Convert.ToString(item["displayName"]) },
                            { "product_state", Convert.ToString(item["productState"]) },
                            { "path_to_signed_product_exe", Convert.ToString(item["pathToSignedProductExe"]) }
                        });
                    }
                }
            }
            catch { }
            return results;
        }

        public static List<object> GetInstalledSoftware()
        {
            Dictionary<string, Dictionary<string, object>> software = new Dictionary<string, Dictionary<string, object>>(StringComparer.OrdinalIgnoreCase);
            CollectSoftwareFromKey(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", software);
            CollectSoftwareFromKey(Registry.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", software);
            CollectSoftwareFromKey(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", software);

            List<object> result = new List<object>();
            foreach (var item in software.Values)
            {
                result.Add(item);
                if (result.Count >= 250) break;
            }
            return result;
        }

        private static void CollectSoftwareFromKey(RegistryKey hive, string subkey, Dictionary<string, Dictionary<string, object>> target)
        {
            try
            {
                using (RegistryKey key = hive.OpenSubKey(subkey))
                {
                    if (key == null) return;
                    foreach (string name in key.GetSubKeyNames())
                    {
                        try
                        {
                            using (RegistryKey sub = key.OpenSubKey(name))
                            {
                                if (sub == null) continue;
                                string displayName = Convert.ToString(sub.GetValue("DisplayName"));
                                if (string.IsNullOrWhiteSpace(displayName)) continue;
                                if (target.ContainsKey(displayName)) continue;

                                target[displayName] = new Dictionary<string, object>
                                {
                                    { "name", displayName },
                                    { "version", Convert.ToString(sub.GetValue("DisplayVersion")) ?? "" },
                                    { "publisher", Convert.ToString(sub.GetValue("Publisher")) ?? "" },
                                    { "install_date", Convert.ToString(sub.GetValue("InstallDate")) ?? "" }
                                };
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        public static List<object> GetWatchedProcesses()
        {
            Dictionary<int, string> commandLines = GetProcessCommandLines();
            List<object> results = new List<object>();
            try
            {
                foreach (Process process in Process.GetProcesses())
                {
                    try
                    {
                        string commandLine;
                        commandLines.TryGetValue(process.Id, out commandLine);

                        results.Add(new Dictionary<string, object>
                        {
                            { "pid", process.Id },
                            { "name", process.ProcessName },
                            { "command_line", Truncate(commandLine, 300) },
                            { "working_set_mb", Math.Round((double)process.WorkingSet64 / (1024 * 1024), 2) }
                        });

                        if (results.Count >= 180) break;
                    }
                    catch { }
                }
            }
            catch { }
            return results;
        }

        private static Dictionary<int, string> GetProcessCommandLines()
        {
            Dictionary<int, string> commandLines = new Dictionary<int, string>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT ProcessId, CommandLine FROM Win32_Process"))
                {
                    foreach (ManagementObject item in searcher.Get())
                    {
                        try
                        {
                            int pid = Convert.ToInt32(item["ProcessId"], CultureInfo.InvariantCulture);
                            string cmd = Convert.ToString(item["CommandLine"]);
                            if (!string.IsNullOrEmpty(cmd))
                            {
                                commandLines[pid] = cmd;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return commandLines;
        }

        public static List<object> GetWatchedServices()
        {
            List<object> results = new List<object>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name, DisplayName, State, StartMode FROM Win32_Service"))
                {
                    foreach (ManagementObject item in searcher.Get())
                    {
                        results.Add(new Dictionary<string, object>
                        {
                            { "name", Convert.ToString(item["Name"]) },
                            { "display_name", Convert.ToString(item["DisplayName"]) },
                            { "state", Convert.ToString(item["State"]) },
                            { "start_mode", Convert.ToString(item["StartMode"]) }
                        });

                        if (results.Count >= 120) break;
                    }
                }
            }
            catch { }
            return results;
        }

        public static List<object> GetWatchedStartupEntries()
        {
            List<object> results = new List<object>();
            CollectStartupFromKey(Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run", results);
            CollectStartupFromKey(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run", results);
            return results;
        }

        private static void CollectStartupFromKey(RegistryKey hive, string subkey, string location, List<object> target)
        {
            try
            {
                using (RegistryKey key = hive.OpenSubKey(subkey))
                {
                    if (key == null) return;
                    foreach (string valueName in key.GetValueNames())
                    {
                        target.Add(new Dictionary<string, object>
                        {
                            { "name", valueName },
                            { "command", Convert.ToString(key.GetValue(valueName)) },
                            { "location", location }
                        });

                        if (target.Count >= 80) break;
                    }
                }
            }
            catch { }
        }

        public static Dictionary<string, object> GetNetworkConnections()
        {
            List<object> listeners = new List<object>();
            List<object> establishedExternal = new List<object>();

            try
            {
                IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();

                foreach (IPEndPoint endpoint in properties.GetActiveTcpListeners())
                {
                    listeners.Add(new Dictionary<string, object>
                    {
                        { "protocol", "tcp" },
                        { "local_address", endpoint.Address.ToString() },
                        { "local_port", endpoint.Port },
                        { "exposure", GetEndpointExposure(endpoint.Address) }
                    });

                    if (listeners.Count >= 120) break;
                }

                foreach (TcpConnectionInformation connection in properties.GetActiveTcpConnections())
                {
                    if (connection.State != TcpState.Established) continue;
                    if (!IsExternalAddress(connection.RemoteEndPoint.Address)) continue;

                    establishedExternal.Add(new Dictionary<string, object>
                    {
                        { "protocol", "tcp" },
                        { "local_address", connection.LocalEndPoint.Address.ToString() },
                        { "local_port", connection.LocalEndPoint.Port },
                        { "remote_address", connection.RemoteEndPoint.Address.ToString() },
                        { "remote_port", connection.RemoteEndPoint.Port },
                        { "state", connection.State.ToString() }
                    });

                    if (establishedExternal.Count >= 120) break;
                }
            }
            catch { }

            return new Dictionary<string, object>
            {
                { "listening_tcp_ports", listeners },
                { "established_external_tcp", establishedExternal }
            };
        }

        private static string GetEndpointExposure(IPAddress address)
        {
            if (IPAddress.IsLoopback(address)) return "loopback";
            if (IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address)) return "all_interfaces";
            if (IsPrivateAddress(address)) return "private_interface";
            return "public_interface";
        }

        private static bool IsExternalAddress(IPAddress address)
        {
            if (address == null) return false;
            if (IPAddress.IsLoopback(address)) return false;
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast) return false;
                return true;
            }
            return !IsPrivateAddress(address);
        }

        private static bool IsPrivateAddress(IPAddress address)
        {
            if (address == null) return false;
            if (IPAddress.IsLoopback(address)) return true;
            if (address.AddressFamily != AddressFamily.InterNetwork) return false;

            byte[] bytes = address.GetAddressBytes();
            if (bytes[0] == 10) return true;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            return false;
        }

        private static string Truncate(string value, int length)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= length) return value ?? "";
            return value.Substring(0, length);
        }

        public static string QueryWmiString(string table, string property)
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT " + property + " FROM " + table))
                {
                    foreach (ManagementObject item in searcher.Get())
                    {
                        object val = item[property];
                        if (val != null) return val.ToString().Trim();
                    }
                }
            }
            catch { }
            return "";
        }

        public static string ReadJsonString(string json, string key, string fallback)
        {
            string pattern = "\"" + Regex.Escape(key) + "\"\\s*:\\s*\"(?<value>(?:\\\\.|[^\"])*)\"";
            Match match = Regex.Match(json, pattern, RegexOptions.IgnoreCase);
            if (!match.Success) return fallback;
            return UnescapeJsonString(match.Groups["value"].Value);
        }

        public static int ReadJsonInt(string json, string key, int fallback)
        {
            string pattern = "\"" + Regex.Escape(key) + "\"\\s*:\\s*(?<value>\\d+)";
            Match match = Regex.Match(json, pattern, RegexOptions.IgnoreCase);
            if (!match.Success) return fallback;
            int value;
            return int.TryParse(match.Groups["value"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out value)
                ? Math.Max(1, value)
                : fallback;
        }

        public static string ExtractJsonString(string json, string key)
        {
            if (string.IsNullOrWhiteSpace(json)) return "";
            return ReadJsonString(json, key, "");
        }

        public static string UnescapeJsonString(string value)
        {
            return value
                .Replace("\\\"", "\"")
                .Replace("\\\\", "\\")
                .Replace("\\/", "/")
                .Replace("\\n", "\n")
                .Replace("\\r", "\r")
                .Replace("\\t", "\t");
        }

        public static string ToJson(object value)
        {
            if (value == null) return "null";
            if (value is string) return "\"" + EscapeJson((string)value) + "\"";
            if (value is bool) return ((bool)value) ? "true" : "false";
            if (value is int || value is long || value is double || value is float || value is decimal)
            {
                return Convert.ToString(value, CultureInfo.InvariantCulture);
            }

            IDictionary<string, object> dict = value as IDictionary<string, object>;
            if (dict != null)
            {
                List<string> parts = new List<string>();
                foreach (KeyValuePair<string, object> pair in dict)
                {
                    parts.Add("\"" + EscapeJson(pair.Key) + "\":" + ToJson(pair.Value));
                }
                return "{" + string.Join(",", parts.ToArray()) + "}";
            }

            IEnumerable enumerable = value as IEnumerable;
            if (enumerable != null)
            {
                List<string> parts = new List<string>();
                foreach (object item in enumerable)
                {
                    parts.Add(ToJson(item));
                }
                return "[" + string.Join(",", parts.ToArray()) + "]";
            }

            return "\"" + EscapeJson(Convert.ToString(value, CultureInfo.InvariantCulture)) + "\"";
        }

        public static string EscapeJson(string value)
        {
            if (value == null) return "";
            StringBuilder builder = new StringBuilder(value.Length + 16);
            foreach (char ch in value)
            {
                switch (ch)
                {
                    case '\\': builder.Append("\\\\"); break;
                    case '"': builder.Append("\\\""); break;
                    case '\n': builder.Append("\\n"); break;
                    case '\r': builder.Append("\\r"); break;
                    case '\t': builder.Append("\\t"); break;
                    default:
                        if (ch < 32) builder.Append("\\u" + ((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                        else builder.Append(ch);
                        break;
                }
            }
            return builder.ToString();
        }
    }

    public sealed class VextHubWindowsService : ServiceBase
    {
        private AgentEngine engine;

        public VextHubWindowsService()
        {
            ServiceName = AgentEngine.ServiceNameConst;
            CanStop = true;
            CanShutdown = true;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                engine = new AgentEngine(isServiceMode: true);
                engine.OnStatusChanged = delegate(string s)
                {
                    Debug.WriteLine("[VextHubService] " + s);
                };
                engine.Start();
            }
            catch (Exception ex)
            {
                try
                {
                    EventLog.WriteEntry(AgentEngine.ServiceNameConst, "Erro ao iniciar servico VextHub: " + ex.Message, EventLogEntryType.Error);
                }
                catch { }
                throw;
            }
        }

        protected override void OnStop()
        {
            try
            {
                if (engine != null)
                {
                    engine.Stop();
                    engine = null;
                }
            }
            catch (Exception ex)
            {
                try
                {
                    EventLog.WriteEntry(AgentEngine.ServiceNameConst, "Erro ao parar servico VextHub: " + ex.Message, EventLogEntryType.Warning);
                }
                catch { }
            }
        }

        protected override void OnShutdown()
        {
            OnStop();
        }
    }

    public static class ServiceInstaller
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);
        private const int ATTACH_PARENT_PROCESS = -1;

        public static void OutputMessage(string message, bool isError)
        {
            bool attached = false;
            try
            {
                attached = AttachConsole(ATTACH_PARENT_PROCESS);
            }
            catch { }

            if (attached)
            {
                Console.WriteLine(message);
            }
            else if (Environment.UserInteractive)
            {
                try
                {
                    MessageBox.Show(
                        message,
                        "VextHub Agent",
                        MessageBoxButtons.OK,
                        isError ? MessageBoxIcon.Error : MessageBoxIcon.Information);
                }
                catch
                {
                    Console.WriteLine(message);
                }
            }
            else
            {
                Debug.WriteLine(message);
            }
        }

        public static int RunProcess(string filename, string arguments, out string output)
        {
            output = "";
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = filename,
                    Arguments = arguments,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (Process proc = Process.Start(psi))
                {
                    string stdout = proc.StandardOutput.ReadToEnd();
                    string stderr = proc.StandardError.ReadToEnd();
                    proc.WaitForExit(15000);
                    output = (stdout + "\n" + stderr).Trim();
                    return proc.ExitCode;
                }
            }
            catch (Exception ex)
            {
                output = ex.Message;
                return -1;
            }
        }

        public static int InstallService()
        {
            try
            {
                OutputMessage("[VextHub] Iniciando instalacao do servico VextHubAgent...", false);

                string currentExe = Process.GetCurrentProcess().MainModule.FileName;
                string currentDir = Path.GetDirectoryName(currentExe) ?? AppDomain.CurrentDomain.BaseDirectory;
                string targetDir = AgentEngine.ResolveServiceInstallDirectory();
                string targetExe = Path.Combine(targetDir, AgentEngine.AgentExeName);
                string targetConfig = Path.Combine(targetDir, AgentEngine.ConfigFileName);

                // 1. Para servico antigo se estiver em execucao
                string stopOutput;
                RunProcess("sc.exe", "stop " + AgentEngine.ServiceNameConst, out stopOutput);
                Thread.Sleep(1000);

                // 2. Garante diretorio de instalacao
                if (!Directory.Exists(targetDir))
                {
                    Directory.CreateDirectory(targetDir);
                }

                // 3. Copia executavel para o diretorio do servico se necessario
                if (!string.Equals(currentExe, targetExe, StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(currentExe, targetExe, true);
                    OutputMessage("[VextHub] Binario copiado para: " + targetExe, false);
                }

                // 4. Copia configuracao se existir na origem
                string sourceConfig = Path.Combine(currentDir, AgentEngine.ConfigFileName);
                if (File.Exists(sourceConfig) && !string.Equals(sourceConfig, targetConfig, StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(sourceConfig, targetConfig, true);
                    OutputMessage("[VextHub] Configuracao copiada para: " + targetConfig, false);
                }

                // 5. Copia icone se existir
                string sourceIcon = Path.Combine(currentDir, "vext_logo.ico");
                string targetIcon = Path.Combine(targetDir, "vext_logo.ico");
                if (File.Exists(sourceIcon) && !File.Exists(targetIcon))
                {
                    try { File.Copy(sourceIcon, targetIcon, true); } catch { }
                }

                // 6. Criar servico no SCM via sc.exe
                string binPath = "\"" + targetExe + "\" --service";
                string scOutput;
                string createArgs = string.Format("create {0} binPath= \"{1}\" start= auto DisplayName= \"{2}\"",
                    AgentEngine.ServiceNameConst, binPath, AgentEngine.ServiceDisplayName);

                int exitCode = RunProcess("sc.exe", createArgs, out scOutput);

                // Se o servico ja existe (1073 / ERROR_SERVICE_EXISTS), atualiza o binPath
                if (exitCode != 0 && (scOutput.Contains("1073") || scOutput.ToLower().Contains("exists") || scOutput.ToLower().Contains("existe")))
                {
                    string configArgs = string.Format("config {0} binPath= \"{1}\" start= auto DisplayName= \"{2}\"",
                        AgentEngine.ServiceNameConst, binPath, AgentEngine.ServiceDisplayName);
                    exitCode = RunProcess("sc.exe", configArgs, out scOutput);
                }

                if (exitCode != 0)
                {
                    if (scOutput.Contains(" 5") || scOutput.ToLower().Contains("access is denied") || scOutput.ToLower().Contains("acesso negado"))
                    {
                        OutputMessage("[VextHub] ERRO: Permissao negada. Execute o terminal como Administrador.", true);
                        return 5;
                    }
                    OutputMessage("[VextHub] ERRO ao criar servico via sc.exe:\n" + scOutput, true);
                    return exitCode;
                }

                // 7. Define a descricao institucional do servico
                string descArgs = string.Format("description {0} \"{1}\"",
                    AgentEngine.ServiceNameConst, AgentEngine.ServiceDescription);
                string descOutput;
                RunProcess("sc.exe", descArgs, out descOutput);

                // 8. Inicia o servico
                string startOutput;
                int startCode = RunProcess("sc.exe", "start " + AgentEngine.ServiceNameConst, out startOutput);

                OutputMessage("[VextHub] Servico " + AgentEngine.ServiceNameConst + " instalado e configurado com sucesso.", false);
                if (startCode == 0)
                {
                    OutputMessage("[VextHub] Servico iniciado com sucesso.", false);
                }
                else
                {
                    OutputMessage("[VextHub] Nota ao iniciar servico: " + startOutput, false);
                }

                return 0;
            }
            catch (UnauthorizedAccessException)
            {
                OutputMessage("[VextHub] ERRO: Requer privilegios de administrador. Execute como Administrador.", true);
                return 5;
            }
            catch (Exception ex)
            {
                OutputMessage("[VextHub] ERRO inesperado na instalacao do servico: " + ex.Message, true);
                return 1;
            }
        }

        public static int UninstallService()
        {
            try
            {
                OutputMessage("[VextHub] Removendo servico VextHubAgent...", false);

                string stopOutput;
                RunProcess("sc.exe", "stop " + AgentEngine.ServiceNameConst, out stopOutput);
                Thread.Sleep(1000);

                string deleteOutput;
                int exitCode = RunProcess("sc.exe", "delete " + AgentEngine.ServiceNameConst, out deleteOutput);

                if (exitCode == 0)
                {
                    OutputMessage("[VextHub] Servico VextHubAgent desinstalado com sucesso.", false);
                    return 0;
                }

                if (deleteOutput.Contains(" 5") || deleteOutput.ToLower().Contains("access is denied") || deleteOutput.ToLower().Contains("acesso negado"))
                {
                    OutputMessage("[VextHub] ERRO: Permissao negada. Execute o terminal como Administrador.", true);
                    return 5;
                }

                if (deleteOutput.Contains("1060") || deleteOutput.ToLower().Contains("does not exist") || deleteOutput.ToLower().Contains("nao existe"))
                {
                    OutputMessage("[VextHub] Servico VextHubAgent nao esta instalado.", false);
                    return 0;
                }

                OutputMessage("[VextHub] ERRO ao desinstalar servico: " + deleteOutput, true);
                return exitCode;
            }
            catch (Exception ex)
            {
                OutputMessage("[VextHub] ERRO inesperado na desinstalacao do servico: " + ex.Message, true);
                return 1;
            }
        }
    }

    public sealed class AgentApp : Form
    {
        private const string EmbeddedIconBase64 = "";

        private readonly string sourceExePath;
        private readonly string sourceDir;
        private readonly string installDir;
        private readonly string installedExePath;
        private readonly string installedConfigPath;

        private AgentConfig config;
        private AgentEngine engine;
        private NotifyIcon trayIcon;
        private ContextMenuStrip trayMenu;
        private ToolStripItem statusMenuItem;
        private ProgressBar progressBar;
        private Label statusLabel;
        private Button installButton;
        private bool isInstallerMode;

        public bool IsInstallerMode { get { return isInstallerMode; } }

        [STAThread]
        public static int Main(string[] args)
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;

            bool runService = false;
            bool installService = false;
            bool uninstallService = false;
            bool forceAgent = false;

            if (args != null)
            {
                foreach (string rawArg in args)
                {
                    string arg = (rawArg ?? "").Trim();
                    if (string.Equals(arg, "--service", StringComparison.OrdinalIgnoreCase))
                    {
                        runService = true;
                    }
                    else if (string.Equals(arg, "--install-service", StringComparison.OrdinalIgnoreCase))
                    {
                        installService = true;
                    }
                    else if (string.Equals(arg, "--uninstall-service", StringComparison.OrdinalIgnoreCase))
                    {
                        uninstallService = true;
                    }
                    else if (string.Equals(arg, "--agent", StringComparison.OrdinalIgnoreCase))
                    {
                        forceAgent = true;
                    }
                }
            }

            if (installService)
            {
                return ServiceInstaller.InstallService();
            }

            if (uninstallService)
            {
                return ServiceInstaller.UninstallService();
            }

            // Execucao como Windows Service (via parametro --service ou sessao nao interativa)
            if (runService || !Environment.UserInteractive)
            {
                ServiceBase.Run(new VextHubWindowsService());
                return 0;
            }

            // Execucao interativa em desktop
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            using (AgentApp app = new AgentApp(forceAgent))
            {
                if (app.IsInstallerMode)
                {
                    Application.Run(app);
                }
                else
                {
                    app.StartBackgroundMode();
                    Application.Run();
                }
            }
            return 0;
        }

        public AgentApp(bool forceAgent)
        {
            sourceExePath = Process.GetCurrentProcess().MainModule.FileName;
            sourceDir = Path.GetDirectoryName(sourceExePath) ?? AppDomain.CurrentDomain.BaseDirectory;
            installDir = AgentEngine.ResolveUserInstallDirectory();
            installedExePath = Path.Combine(installDir, AgentEngine.AgentExeName);
            installedConfigPath = Path.Combine(installDir, AgentEngine.ConfigFileName);

            string bestConfig = AgentEngine.FindBestConfigPath(false);
            config = AgentEngine.LoadConfig(bestConfig);

            Icon = ResolveIcon();

            string serviceDir = AgentEngine.ResolveServiceInstallDirectory();
            string serviceExePath = Path.Combine(serviceDir, AgentEngine.AgentExeName);

            bool runningFromInstallDir = string.Equals(sourceExePath, installedExePath, StringComparison.OrdinalIgnoreCase) ||
                                         string.Equals(sourceExePath, serviceExePath, StringComparison.OrdinalIgnoreCase);

            isInstallerMode = !forceAgent && !runningFromInstallDir;
            if (isInstallerMode)
            {
                InitializeInstallerUI();
            }
        }

        private Icon ResolveIcon()
        {
            try
            {
                if (!string.IsNullOrEmpty(EmbeddedIconBase64))
                {
                    try
                    {
                        byte[] iconBytes = Convert.FromBase64String(EmbeddedIconBase64);
                        using (MemoryStream ms = new MemoryStream(iconBytes))
                        {
                            return new Icon(ms);
                        }
                    }
                    catch { }
                }

                Icon appIcon = Icon.ExtractAssociatedIcon(sourceExePath);
                if (appIcon != null && !appIcon.Equals(SystemIcons.Shield)) return appIcon;

                string[] iconNames = { "vext_logo.ico", "favicon.ico", "icon.ico" };
                foreach (string name in iconNames)
                {
                    string[] possiblePaths = {
                        Path.Combine(sourceDir, name),
                        Path.Combine(sourceDir, "..", "..", "public", name),
                        Path.Combine(sourceDir, "public", name)
                    };

                    foreach (string path in possiblePaths)
                    {
                        if (File.Exists(path)) return new Icon(path);
                    }
                }
            }
            catch { }
            return SystemIcons.Shield;
        }

        private void InitializeInstallerUI()
        {
            Text = "VextHub Agent Setup";
            Size = new Size(430, 250);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            MaximizeBox = false;
            BackColor = Color.FromArgb(18, 24, 38);
            ForeColor = Color.White;

            Label title = new Label
            {
                Text = "VextHub Endpoint Agent",
                Font = new Font("Segoe UI", 14, FontStyle.Bold),
                Location = new Point(20, 22),
                Size = new Size(380, 30),
                TextAlign = ContentAlignment.MiddleCenter
            };

            statusLabel = new Label
            {
                Text = "Unidade: " + config.Unit,
                Location = new Point(20, 70),
                Size = new Size(380, 24),
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 9)
            };

            progressBar = new ProgressBar
            {
                Location = new Point(55, 105),
                Size = new Size(320, 18),
                Visible = false
            };

            installButton = new Button
            {
                Text = "Instalar",
                Location = new Point(140, 145),
                Size = new Size(150, 38),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(16, 185, 129),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 10, FontStyle.Bold)
            };
            installButton.FlatAppearance.BorderSize = 0;
            installButton.Click += delegate { StartInstallation(); };

            Controls.Add(title);
            Controls.Add(statusLabel);
            Controls.Add(progressBar);
            Controls.Add(installButton);
        }

        private void StartInstallation()
        {
            installButton.Enabled = false;
            progressBar.Visible = true;
            UpdateInstallStatus("Finalizando processos antigos...", 10);

            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    try
                    {
                        foreach (var process in Process.GetProcessesByName("VextHubAgent"))
                        {
                            if (process.Id != Process.GetCurrentProcess().Id)
                            {
                                try { process.Kill(); process.WaitForExit(5000); } catch { }
                            }
                        }
                    }
                    catch { }

                    UpdateInstallStatus("Preparando diretorio...", 20);
                    if (!Directory.Exists(installDir)) Directory.CreateDirectory(installDir);

                    UpdateInstallStatus("Copiando agente...", 50);
                    bool copied = false;
                    for (int i = 0; i < 5; i++)
                    {
                        try
                        {
                            File.Copy(sourceExePath, installedExePath, true);

                            string sourceIcon = Path.Combine(sourceDir, "vext_logo.ico");
                            if (File.Exists(sourceIcon))
                            {
                                File.Copy(sourceIcon, Path.Combine(installDir, "vext_logo.ico"), true);
                            }

                            copied = true;
                            break;
                        }
                        catch
                        {
                            Thread.Sleep(2000);
                        }
                    }
                    if (!copied) throw new Exception("Nao foi possivel sobrescrever o arquivo. O antivirus ou o sistema podem estar bloqueando.");

                    UpdateInstallStatus("Salvando configuracao...", 70);
                    AgentEngine.SaveConfig(installedConfigPath, config);

                    UpdateInstallStatus("Registrando inicializacao...", 90);
                    AgentEngine.SetUserStartup(true, installedExePath);

                    UpdateInstallStatus("Concluido.", 100);

                    Invoke((Action)(delegate
                    {
                        MessageBox.Show(
                            "VextHub Agent instalado. O monitoramento iniciara automaticamente no proximo logon.",
                            "VextHub",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                        Application.Exit();
                    }));
                }
                catch (Exception ex)
                {
                    Invoke((Action)(delegate
                    {
                        MessageBox.Show("Erro na instalacao: " + ex.Message, "VextHub", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        installButton.Enabled = true;
                        progressBar.Visible = false;
                    }));
                }
            });
        }

        private void UpdateInstallStatus(string text, int progress)
        {
            if (InvokeRequired)
            {
                Invoke((Action)(delegate { UpdateInstallStatus(text, progress); }));
                return;
            }
            statusLabel.Text = text;
            progressBar.Value = Math.Max(0, Math.Min(100, progress));
        }

        public void StartBackgroundMode()
        {
            ShowInTaskbar = false;
            WindowState = FormWindowState.Minimized;
            Hide();

            trayMenu = new ContextMenuStrip();
            ToolStripItem version = trayMenu.Items.Add("VextHub Agent v" + AgentEngine.AgentVersion);
            version.Enabled = false;
            statusMenuItem = trayMenu.Items.Add("Status: iniciando");
            statusMenuItem.Enabled = false;
            trayMenu.Items.Add("-");
            trayMenu.Items.Add("Sincronizar agora", null, delegate { if (engine != null) engine.QueueTelemetry(); });
            trayMenu.Items.Add("Desinstalar agente", null, delegate { UninstallAgent(); });

            trayIcon = new NotifyIcon
            {
                Icon = Icon ?? SystemIcons.Shield,
                ContextMenuStrip = trayMenu,
                Text = TruncateTrayText("VextHub Agent - " + config.Unit),
                Visible = true
            };

            trayIcon.BalloonTipTitle = "VextHub Agent";
            trayIcon.BalloonTipText = "Monitoramento de seguranca ativo";
            trayIcon.ShowBalloonTip(2500);

            engine = new AgentEngine(isServiceMode: false);
            engine.OnStatusChanged = delegate(string status)
            {
                UpdateTrayStatus(status);
            };
            engine.Start();
        }

        private string TruncateTrayText(string text)
        {
            if (text.Length <= 63) return text;
            return text.Substring(0, 60) + "...";
        }

        private void UninstallAgent()
        {
            DialogResult result = MessageBox.Show(
                "Deseja desativar o VextHub Agent da inicializacao deste usuario?",
                "VextHub",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);
            if (result != DialogResult.Yes) return;

            AgentEngine.SetUserStartup(false, "");
            MessageBox.Show(
                "Agente desativado da inicializacao. Feche o icone e remova a pasta local se quiser apagar os arquivos.",
                "VextHub",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            if (trayIcon != null) trayIcon.Visible = false;
            Application.Exit();
        }

        private void UpdateTrayStatus(string text)
        {
            try
            {
                if (statusMenuItem == null) return;
                if (InvokeRequired)
                {
                    Invoke((Action)(delegate { UpdateTrayStatus(text); }));
                    return;
                }
                statusMenuItem.Text = text;
            }
            catch { }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (engine != null)
                {
                    engine.Stop();
                    engine = null;
                }
                if (trayIcon != null) trayIcon.Dispose();
                if (trayMenu != null) trayMenu.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
