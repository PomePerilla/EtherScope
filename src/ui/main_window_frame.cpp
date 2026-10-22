#include "ui/main_window.h"
#include "ui/style.h"
#include "ui/window_title_bar.h"
#include <QEvent>
#include <QGuiApplication>
#include <QShowEvent>
#include <QWindow>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>
#endif

namespace etherscope {
void MainWindow::showEvent(QShowEvent *event) {
    QMainWindow::showEvent(event);
    configureNativeFrame();
}
void MainWindow::changeEvent(QEvent *event) {
    QMainWindow::changeEvent(event);
    if (event->type() == QEvent::WindowStateChange)
        style::setFlag(this, "frameMaximized", isMaximized() || isFullScreen());
}
void MainWindow::configureNativeFrame() {
#ifdef _WIN32
    if (QGuiApplication::platformName() != "windows" || !windowHandle())
        return;
    const auto handle = reinterpret_cast<HWND>(windowHandle()->winId());
    const auto previous = GetWindowLongPtrW(handle, GWL_STYLE);
    const auto required = WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
    if ((previous & required) != required) {
        SetWindowLongPtrW(handle, GWL_STYLE, previous | required);
        SetWindowPos(handle, nullptr, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    }
    const BOOL dark = dark_;
    DwmSetWindowAttribute(handle, 20, &dark, sizeof(dark));
    const DWORD rounded = 2; // DWMWCP_ROUND; ignored on Windows versions without this attribute.
    DwmSetWindowAttribute(handle, 33, &rounded, sizeof(rounded));
    const QColor border(style::colors(dark_).border);
    const COLORREF color = RGB(border.red(), border.green(), border.blue());
    DwmSetWindowAttribute(handle, 34, &color, sizeof(color));
    const MARGINS shadow{1, 1, 1, 1};
    DwmExtendFrameIntoClientArea(handle, &shadow);
#endif
}
bool MainWindow::nativeEvent(const QByteArray &type, void *message, qintptr *result) {
#ifdef _WIN32
    const auto *msg = static_cast<MSG *>(message);
    if (msg && result) {
        switch (msg->message) {
        case WM_NCCALCSIZE:
            if (msg->lParam) {
                auto *client = reinterpret_cast<RECT *>(msg->lParam);
                if (IsZoomed(msg->hwnd) && !isFullScreen()) {
                    MONITORINFO monitor{sizeof(MONITORINFO)};
                    if (GetMonitorInfoW(MonitorFromWindow(msg->hwnd, MONITOR_DEFAULTTONEAREST),
                                        &monitor))
                        *client = monitor.rcWork;
                }
                *result = 0;
                return true;
            }
            break;
        case WM_GETMINMAXINFO: {
            auto *limits = reinterpret_cast<MINMAXINFO *>(msg->lParam);
            MONITORINFO monitor{sizeof(MONITORINFO)};
            if (limits &&
                GetMonitorInfoW(MonitorFromWindow(msg->hwnd, MONITOR_DEFAULTTONEAREST), &monitor)) {
                limits->ptMaxPosition = {monitor.rcWork.left - monitor.rcMonitor.left,
                                         monitor.rcWork.top - monitor.rcMonitor.top};
                limits->ptMaxSize = {monitor.rcWork.right - monitor.rcWork.left,
                                     monitor.rcWork.bottom - monitor.rcWork.top};
                const auto scale = devicePixelRatioF();
                limits->ptMinTrackSize = {qRound(minimumWidth() * scale),
                                          qRound(minimumHeight() * scale)};
                *result = 0;
                return true;
            }
            break;
        }
        case WM_NCHITTEST: {
            POINT position{GET_X_LPARAM(msg->lParam), GET_Y_LPARAM(msg->lParam)};
            RECT bounds{};
            if (!GetWindowRect(msg->hwnd, &bounds))
                break;
            if (!IsZoomed(msg->hwnd) && !isFullScreen()) {
                const auto dpi = GetDpiForWindow(msg->hwnd);
                const int edge = GetSystemMetricsForDpi(SM_CXSIZEFRAME, dpi) +
                                 GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
                const bool left = position.x < bounds.left + edge,
                           right = position.x >= bounds.right - edge;
                const bool top = position.y < bounds.top + edge,
                           bottom = position.y >= bounds.bottom - edge;
                const int hit =
                    top ? (left ? HTTOPLEFT : (right ? HTTOPRIGHT : HTTOP))
                        : (bottom ? (left ? HTBOTTOMLEFT : (right ? HTBOTTOMRIGHT : HTBOTTOM))
                                  : (left ? HTLEFT : (right ? HTRIGHT : HTCLIENT)));
                if (hit != HTCLIENT) {
                    *result = hit;
                    return true;
                }
            }
            ScreenToClient(msg->hwnd, &position);
            const auto scale = devicePixelRatioF();
            if (titleBar_ && titleBar_->isDragArea(
                                 QPoint(qRound(position.x / scale), qRound(position.y / scale)))) {
                *result = HTCAPTION;
                return true;
            }
            *result = HTCLIENT;
            return true;
        }
        default:
            break;
        }
    }
#endif
    return QMainWindow::nativeEvent(type, message, result);
}
} // namespace etherscope
