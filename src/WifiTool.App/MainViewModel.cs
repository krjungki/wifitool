// 현장 분석 화면의 로컬 읽기, 필터, 프로필, 패키지 작업을 조정한다.
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Data;
using Microsoft.Win32;
using WifiTool.Core;
using WifiTool.Windows;

namespace WifiTool.App;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private static readonly string[] DefaultChannels = ["System", "Microsoft-Windows-WLAN-AutoConfig/Operational"];
    private readonly EventLogSource _eventSource = new();
    private readonly NativeWifiProfileSource _profileSource = new();
    private readonly DiagnosticPackageService _packageService = new();
    private readonly TimelineBuilder _timelineBuilder = new();
    private readonly AnalysisSummaryBuilder _summaryBuilder = new();
    private CancellationTokenSource? _cancellation;
    private string _statusText = "입력을 선택하십시오.";
    private string _coverageSummary = "수집 전";
    private string _analysisSummary = "EVTX 또는 로컬 로그를 선택하십시오.";
    private string _ssidFilter = string.Empty;
    private string _searchText = string.Empty;
    private string _profileSsid = string.Empty;
    private bool _isBusy;
    private TimelineEntry? _selectedTimeline;
    private WifiProfileSnapshot? _selectedProfile;

    public MainViewModel()
    {
        FilteredTimeline = CollectionViewSource.GetDefaultView(Timeline);
        FilteredTimeline.Filter = FilterTimeline;
        LoadLocalCommand = new AsyncRelayCommand(LoadLocalAsync, () => !IsBusy);
        OpenEvtxCommand = new AsyncRelayCommand(OpenEvtxAsync, () => !IsBusy);
        OpenPackageCommand = new AsyncRelayCommand(OpenPackageAsync, () => !IsBusy);
        LoadProfilesCommand = new AsyncRelayCommand(LoadProfilesAsync, () => !IsBusy);
        SavePackageCommand = new AsyncRelayCommand(SavePackageAsync, () => !IsBusy);
        CancelCommand = new RelayCommand(() => _cancellation?.Cancel(), () => IsBusy);
    }

    public ObservableCollection<TimelineEntry> Timeline { get; } = [];
    public ObservableCollection<TimelineEntry> SystemTimeline { get; } = [];
    public ObservableCollection<WifiProfileSnapshot> Profiles { get; } = [];
    public ObservableCollection<ChannelStatus> ChannelStatuses { get; } = [];
    public ObservableCollection<string> Findings { get; } = [];
    public ICollectionView FilteredTimeline { get; }
    public AsyncRelayCommand LoadLocalCommand { get; }
    public AsyncRelayCommand OpenEvtxCommand { get; }
    public AsyncRelayCommand OpenPackageCommand { get; }
    public AsyncRelayCommand LoadProfilesCommand { get; }
    public AsyncRelayCommand SavePackageCommand { get; }
    public RelayCommand CancelCommand { get; }
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }
    public string CoverageSummary { get => _coverageSummary; private set => Set(ref _coverageSummary, value); }
    public string AnalysisSummary { get => _analysisSummary; private set => Set(ref _analysisSummary, value); }
    public bool IsBusy { get => _isBusy; private set { if (Set(ref _isBusy, value)) RefreshCommands(); } }
    public string ProfileSsid { get => _profileSsid; set => Set(ref _profileSsid, value); }
    public TimelineEntry? SelectedTimeline { get => _selectedTimeline; set => Set(ref _selectedTimeline, value); }
    public WifiProfileSnapshot? SelectedProfile { get => _selectedProfile; set => Set(ref _selectedProfile, value); }
    public string SsidFilter { get => _ssidFilter; set { if (Set(ref _ssidFilter, value)) FilteredTimeline.Refresh(); } }
    public string SearchText { get => _searchText; set { if (Set(ref _searchText, value)) FilteredTimeline.Refresh(); } }
    public event PropertyChangedEventHandler? PropertyChanged;

    private async Task LoadLocalAsync() => await RunAsync("최근 24시간 로컬 로그를 읽는 중...", token =>
    {
        var result = _eventSource.ReadLive(DefaultChannels, DateTimeOffset.UtcNow.AddHours(-24), token);
        Application.Current.Dispatcher.Invoke(() => ApplyEvents(result));
    });

    private async Task OpenEvtxAsync()
    {
        var dialog = new OpenFileDialog { Filter = "Windows 이벤트 로그 (*.evtx)|*.evtx", Multiselect = true, CheckFileExists = true };
        if (dialog.ShowDialog() != true) return;
        await LoadFilesAsync(dialog.FileNames);
    }

    public async Task LoadFilesAsync(IEnumerable<string> paths)
    {
        var selectedPaths = paths.ToArray();
        if (selectedPaths.Length == 0) return;
        await RunAsync("EVTX 파일을 읽는 중...", token =>
        {
            var result = _eventSource.ReadFiles(selectedPaths, token);
            Application.Current.Dispatcher.Invoke(() => ApplyEvents(result));
        });
    }

    private async Task LoadProfilesAsync() => await RunAsync("현재 PC의 Wi-Fi 프로필을 읽는 중...", _ =>
    {
        var profiles = _profileSource.ReadProfiles(string.IsNullOrWhiteSpace(ProfileSsid) ? null : ProfileSsid.Trim());
        Application.Current.Dispatcher.Invoke(() =>
        {
            Profiles.Clear();
            foreach (var profile in profiles) Profiles.Add(profile);
            StatusText = $"프로필 {profiles.Count}개를 읽었습니다. XML은 메모리에서 비밀 필드를 제거했습니다.";
        });
    });

    private async Task SavePackageAsync()
    {
        var dialog = new SaveFileDialog { Filter = "wifitool 수집 패키지 (*.zip)|*.zip", FileName = $"wifitool-{DateTime.Now:yyyyMMdd-HHmmss}.zip", AddExtension = true, OverwritePrompt = true };
        if (dialog.ShowDialog() != true) return;
        await RunAsync("진단 ZIP을 만드는 중...", token =>
        {
            var result = _packageService.Create(dialog.FileName, DateTimeOffset.UtcNow.AddHours(-24), DateTimeOffset.UtcNow, DefaultChannels, Timeline.ToList(), Profiles.ToList(), token);
            Application.Current.Dispatcher.Invoke(() => StatusText = $"ZIP 저장 완료: {result.Path} ({(result.Manifest.Partial ? "일부 수집" : "완전 수집")})");
        });
    }

    private async Task OpenPackageAsync()
    {
        var dialog = new OpenFileDialog { Filter = "wifitool 수집 패키지 (*.zip)|*.zip", CheckFileExists = true };
        if (dialog.ShowDialog() != true) return;
        await RunAsync("수집 ZIP의 무결성을 확인하는 중...", token =>
        {
            var manifest = _packageService.Validate(dialog.FileName);
            token.ThrowIfCancellationRequested();
            using var archive = ZipFile.OpenRead(dialog.FileName);
            var timelineEntry = archive.GetEntry("timeline.json") ?? throw new InvalidDataException("timeline.json이 없습니다.");
            using var stream = timelineEntry.Open();
            var timeline = JsonSerializer.Deserialize<List<TimelineEntry>>(stream) ?? [];
            Application.Current.Dispatcher.Invoke(() =>
            {
                Timeline.Clear();
                foreach (var item in timeline) Timeline.Add(item);
                PopulateSystemTimeline(timeline);
                ChannelStatuses.Clear();
                foreach (var status in manifest.Channels) ChannelStatuses.Add(status);
                CoverageSummary = $"ZIP · {manifest.CollectedAt.LocalDateTime:g} · {(manifest.Partial ? "일부" : "완전")}";
                StatusText = $"무결성 검증을 통과한 타임라인 {timeline.Count}건을 열었습니다.";
                FilteredTimeline.Refresh();
            });
        });
    }

    private void ApplyEvents(EventReadResult result)
    {
        Timeline.Clear();
        foreach (var item in _timelineBuilder.Build(result.Events, TimeSpan.FromMinutes(5))) Timeline.Add(item);
        PopulateSystemTimeline(Timeline);
        ChannelStatuses.Clear();
        foreach (var status in result.Channels) ChannelStatuses.Add(status);
        var incomplete = result.Channels.Count(item => item.Status is not ("available" or "empty"));
        CoverageSummary = $"{result.Events.Count:N0} events · {result.Channels.Count} inputs · {incomplete} 제한";
        var overview = _summaryBuilder.Build(result.Events, Timeline.ToList());
        Findings.Clear();
        foreach (var finding in overview.Findings) Findings.Add(finding);
        AnalysisSummary = $"부팅 {overview.BootCount:N0} · 로그온 {overview.LogonCount:N0} · Wi-Fi 연결 {overview.WifiConnectedCount:N0} · 실패 {overview.WifiFailedCount:N0} · 로밍 {overview.WifiRoamedCount:N0}";
        StatusText = $"타임라인 {Timeline.Count:N0}건을 구성했습니다. Unknown과 Inferred를 확인하십시오.";
        FilteredTimeline.Refresh();
    }

    private void PopulateSystemTimeline(IEnumerable<TimelineEntry> timeline)
    {
        SystemTimeline.Clear();
        foreach (var item in timeline.Where(item => item.Kind is TimelineKind.Boot or TimelineKind.Shutdown or TimelineKind.Sleep or TimelineKind.Resume or TimelineKind.UnexpectedShutdown))
        {
            SystemTimeline.Add(item);
        }
    }

    private bool FilterTimeline(object item)
    {
        if (item is not TimelineEntry entry) return false;
        if (!string.IsNullOrWhiteSpace(SsidFilter) && !(entry.Ssid?.Contains(SsidFilter, StringComparison.OrdinalIgnoreCase) ?? false)) return false;
        if (string.IsNullOrWhiteSpace(SearchText)) return true;
        return entry.Stage.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ||
               (entry.Account?.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ?? false) ||
             (entry.Bssid?.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ?? false) ||
               entry.Summary.Contains(SearchText, StringComparison.OrdinalIgnoreCase);
    }

    private async Task RunAsync(string status, Action<CancellationToken> action)
    {
        _cancellation = new CancellationTokenSource();
        IsBusy = true;
        StatusText = status;
        try { await Task.Run(() => action(_cancellation.Token), _cancellation.Token); }
        catch (OperationCanceledException) { StatusText = "작업을 취소했습니다."; }
        catch (Exception exception)
        {
            StatusText = $"작업 실패: {exception.Message}";
            MessageBox.Show(exception.Message, "wifitool", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            IsBusy = false;
            _cancellation.Dispose();
            _cancellation = null;
        }
    }

    private void RefreshCommands()
    {
        LoadLocalCommand.RaiseCanExecuteChanged(); OpenEvtxCommand.RaiseCanExecuteChanged(); OpenPackageCommand.RaiseCanExecuteChanged();
        LoadProfilesCommand.RaiseCanExecuteChanged(); SavePackageCommand.RaiseCanExecuteChanged(); CancelCommand.RaiseCanExecuteChanged();
    }

    private bool Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }
}