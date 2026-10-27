"""Check an owned application window with an isolated settings file and clean Qt environment."""
from pathlib import Path
import argparse
import ctypes as c
from ctypes import wintypes as w
import subprocess, os, time, tempfile, json
parser=argparse.ArgumentParser()
parser.add_argument('--application',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
root=Path(__file__).resolve().parent.parent; exe=args.application.resolve(strict=True)
u=c.WinDLL('user32',use_last_error=True)
u.SetProcessDpiAwarenessContext.argtypes=[c.c_void_p]
u.SetProcessDpiAwarenessContext(c.c_void_p(-4))
callback=c.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
u.EnumWindows.argtypes=[callback,w.LPARAM]
u.GetWindowThreadProcessId.argtypes=[w.HWND,c.POINTER(w.DWORD)]
u.GetWindowLongPtrW.argtypes=[w.HWND,c.c_int]; u.GetWindowLongPtrW.restype=c.c_ssize_t
u.SendMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]; u.SendMessageW.restype=c.c_ssize_t
u.PostMessageW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM]
u.GetWindowRect.argtypes=[w.HWND,c.POINTER(w.RECT)]
u.GetClientRect.argtypes=[w.HWND,c.POINTER(w.RECT)]
u.ClientToScreen.argtypes=[w.HWND,c.POINTER(w.POINT)]
u.GetDpiForWindow.argtypes=[w.HWND]; u.GetDpiForWindow.restype=w.UINT
u.IsZoomed.argtypes=[w.HWND]; u.IsIconic.argtypes=[w.HWND]
u.MonitorFromWindow.argtypes=[w.HWND,w.DWORD]; u.MonitorFromWindow.restype=w.HANDLE
class Monitor(c.Structure): _fields_=[('size',w.DWORD),('monitor',w.RECT),('work',w.RECT),('flags',w.DWORD)]
u.GetMonitorInfoW.argtypes=[w.HANDLE,c.POINTER(Monitor)]
env=dict(os.environ); env['PATH']=os.path.join(os.environ['SystemRoot'],'System32')+';'+os.environ['SystemRoot']; env.pop('QT_PLUGIN_PATH',None)
for key in ['QT_QPA_PLATFORM','QT_SCALE_FACTOR','QT_QPA_FONTDIR']: env.pop(key,None)
startup=subprocess.STARTUPINFO(); startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW; startup.wShowWindow=0
result={}
def wait(predicate):
    end=time.monotonic()+5
    while time.monotonic()<end:
        if predicate(): return
        time.sleep(.03)
    raise AssertionError('State change timeout')
with tempfile.TemporaryDirectory(prefix='etherscope-window-frame-') as temp:
    p=subprocess.Popen([str(exe),'--settings-file',str(Path(temp)/'settings.ini'),'--open',str(root/'samples/synthetic-protocols.pcap')],env=env,startupinfo=startup)
    hwnd=None
    try:
        end=time.monotonic()+10
        while time.monotonic()<end and p.poll() is None:
            matches=[]
            @callback
            def visit(handle,_):
                pid=w.DWORD(); u.GetWindowThreadProcessId(handle,c.byref(pid))
                name=c.create_unicode_buffer(128); u.GetWindowTextW(handle,name,128)
                if pid.value==p.pid and name.value=='EtherScope': matches.append(handle)
                return True
            u.EnumWindows(visit,0)
            if matches: hwnd=matches[0]; break
            time.sleep(.03)
        assert hwnd, ('No window',p.poll())
        wait(lambda: (u.GetWindowLongPtrW(hwnd,-16)&0xC40000)==0xC40000)
        time.sleep(.2)
        scale=u.GetDpiForWindow(hwnd)/96
        r=w.RECT(); assert u.GetWindowRect(hwnd,c.byref(r))
        result['dpi']=u.GetDpiForWindow(hwnd)
        def hit(x,y): return u.SendMessageW(hwnd,0x84,0,(int(x)&65535)|((int(y)&65535)<<16))
        middleX=(r.left+r.right)//2; middleY=(r.top+r.bottom)//2
        cases={'top_left':(r.left+2,r.top+2,13),'top':(middleX,r.top+2,12),'top_right':(r.right-3,r.top+2,14),
          'left':(r.left+2,middleY,10),'right':(r.right-3,middleY,11),'bottom_left':(r.left+2,r.bottom-3,16),
          'bottom':(middleX,r.bottom-3,15),'bottom_right':(r.right-3,r.bottom-3,17),
          'caption':(r.left+200*scale,r.top+17*scale,2),'maximize_button':(r.right-66*scale,r.top+17*scale,1),
          'close_button':(r.right-22*scale,r.top+17*scale,1),'workspace':(middleX,middleY,1)}
        result['hit_tests']={}
        for name,(x,y,expected) in cases.items():
            actual=hit(x,y); result['hit_tests'][name]=actual; assert actual==expected,(name,actual,expected)
        u.SendMessageW(hwnd,0x112,0xF030,0); wait(lambda: u.IsZoomed(hwnd))
        info=Monitor(); info.size=c.sizeof(info); assert u.GetMonitorInfoW(u.MonitorFromWindow(hwnd,2),c.byref(info))
        client=w.RECT(); origin=w.POINT(); u.GetClientRect(hwnd,c.byref(client)); u.ClientToScreen(hwnd,c.byref(origin))
        result['maximized_client']=[origin.x,origin.y,origin.x+client.right,origin.y+client.bottom]
        result['monitor_work_area']=[info.work.left,info.work.top,info.work.right,info.work.bottom]
        assert result['maximized_client']==result['monitor_work_area'], result
        u.SendMessageW(hwnd,0x112,0xF120,0); wait(lambda: not u.IsZoomed(hwnd))
        lp=(int(r.left+200*scale)&65535)|((int(r.top+17*scale)&65535)<<16)
        u.SendMessageW(hwnd,0xA3,2,lp); wait(lambda: u.IsZoomed(hwnd))
        result['native_double_click']=True
        u.SendMessageW(hwnd,0x112,0xF120,0); wait(lambda: not u.IsZoomed(hwnd))
        u.SendMessageW(hwnd,0x112,0xF020,0); wait(lambda: u.IsIconic(hwnd))
        u.SendMessageW(hwnd,0x112,0xF120,0); wait(lambda: not u.IsIconic(hwnd))
        result['minimize_restore']=True
        restored=w.RECT(); u.GetWindowRect(hwnd,c.byref(restored))
        result['normal_bounds']=[r.left,r.top,r.right,r.bottom]
        result['restored_bounds']=[restored.left,restored.top,restored.right,restored.bottom]
        assert result['normal_bounds']==result['restored_bounds'], result
        result['large_and_small_icons']=all(u.SendMessageW(hwnd,0x7F,kind,0) for kind in [0,1])
        result['passed']=True
    finally:
        if hwnd: u.PostMessageW(hwnd,0x10,0,0)
        try: p.wait(timeout=10)
        except subprocess.TimeoutExpired: p.terminate(); p.wait(); raise
result['exit_code']=p.returncode
assert result['exit_code']==0
args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,indent=2))
