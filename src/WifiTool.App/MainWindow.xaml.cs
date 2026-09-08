// 주 창을 ViewModel과 연결한다.
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;

namespace WifiTool.App;

public partial class MainWindow : Window
{
    private readonly HashSet<DataGrid> _connectedGrids = [];

    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();
        ConnectWhenLoaded(SystemDataGrid, SystemHorizontalScrollBar);
        ConnectWhenLoaded(TimelineDataGrid, TimelineHorizontalScrollBar);
        ConnectWhenLoaded(ProfilesDataGrid, ProfilesHorizontalScrollBar);
        ConnectWhenLoaded(CollectionDataGrid, CollectionHorizontalScrollBar);
    }

    private void ConnectWhenLoaded(DataGrid grid, ScrollBar bar)
    {
        grid.Loaded += (_, _) =>
        {
            if (_connectedGrids.Add(grid)) ConnectHorizontalScrollBar(grid, bar);
        };
    }

    private static void ConnectHorizontalScrollBar(DataGrid grid, ScrollBar bar)
    {
        grid.ApplyTemplate();
        var viewer = grid.Template.FindName("DG_ScrollViewer", grid) as ScrollViewer
            ?? FindVisualChild<ScrollViewer>(grid, "DG_ScrollViewer");
        if (viewer is null) return;
        var updating = false;

        void Synchronize()
        {
            updating = true;
            bar.Maximum = Math.Max(0, viewer.ScrollableWidth);
            bar.ViewportSize = Math.Max(0, viewer.ViewportWidth);
            bar.LargeChange = Math.Max(20, viewer.ViewportWidth * 0.8);
            bar.SmallChange = 40;
            bar.Value = Math.Min(viewer.HorizontalOffset, bar.Maximum);
            bar.IsEnabled = viewer.ScrollableWidth > 0;
            updating = false;
        }

        viewer.ScrollChanged += (_, _) => Synchronize();
        grid.SizeChanged += (_, _) => Synchronize();
        grid.LayoutUpdated += (_, _) => Synchronize();
        bar.ValueChanged += (_, _) =>
        {
            if (!updating) viewer.ScrollToHorizontalOffset(bar.Value);
        };
        Synchronize();
    }

    private static T? FindVisualChild<T>(DependencyObject parent, string? name = null) where T : FrameworkElement
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match && (name is null || match.Name == name)) return match;
            var nested = FindVisualChild<T>(child, name);
            if (nested is not null) return nested;
        }
        return null;
    }
}