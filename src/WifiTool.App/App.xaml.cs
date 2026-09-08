// 애플리케이션 시작 인수와 주 창 생성을 관리한다.
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;

namespace WifiTool.App;

public partial class App : Application
{
	protected override void OnStartup(StartupEventArgs e)
	{
		base.OnStartup(e);
		var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";
		if (e.Args.Contains("--version", StringComparer.OrdinalIgnoreCase))
		{
			WriteVersionToParentConsole(version);
			Shutdown(0);
			return;
		}

		var window = new MainWindow { Title = $"wifitool {version}" };
		MainWindow = window;
		window.Show();
		var evtxPaths = e.Args.Where(path => path.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)).ToArray();
		if (evtxPaths.Length > 0 && window.DataContext is MainViewModel viewModel)
		{
			_ = viewModel.LoadFilesAsync(evtxPaths);
		}
	}

	private static void WriteVersionToParentConsole(string version)
	{
		if (!AttachConsole(0xFFFFFFFF)) return;
		using var output = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
		output.WriteLine(version);
	}

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool AttachConsole(uint processId);
}
