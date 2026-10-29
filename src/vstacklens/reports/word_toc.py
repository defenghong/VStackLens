"""Optional, isolated Microsoft Word TOC update, with an always-valid fallback."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from zipfile import ZipFile
from io import BytesIO
from xml.etree import ElementTree as ET

LOG = logging.getLogger('vstacklens.report_generation')

WORKER = r'''
param([string]$DocumentPath, [string]$StatePath)
$ErrorActionPreference='Stop'
$prior=@(Get-Process WINWORD -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
$app=$null;$doc=$null;$blank=$null;$window=$null;$owned=$false;$shared=$false;$state=@{status='starting';owned=$false}
function Save-State { $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8 }
try {
 Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class WordWindowOwner { [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid); }'
 $app=New-Object -ComObject Word.Application
 if($app.UserControl){$shared=$true;throw 'Refuse a user-controlled Word session'}
 $app.Visible=$false
 $app.DisplayAlerts=0
 $app.AutomationSecurity=3
 # Unlike Excel, Word exposes the HWND on a Window, not Application.
 # Bootstrap one private blank document without showing a window.
 $blank=$app.Documents.Add()
 $window=$blank.ActiveWindow
 [uint32]$wordPid=0
 [void][WordWindowOwner]::GetWindowThreadProcessId([IntPtr]$window.Hwnd,[ref]$wordPid)
 if($wordPid -eq 0 -or $prior -contains [int]$wordPid){$shared=$true;throw 'No new privately owned Word instance; do not modify an existing user session'}
 $owned=$true
 $state=@{status='owned';owned=$true;pid=[int]$wordPid;creation_filetime=(Get-Process -Id $wordPid).StartTime.ToFileTimeUtc()}
 Save-State
 $app.Visible=$false
 $app.DisplayAlerts=0
 $app.AutomationSecurity=3
 $blank.Close(0)
 [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($window);$window=$null
 [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($blank);$blank=$null
 $doc=$app.Documents.Open($DocumentPath,$false,$false,$false)
 $doc.Repaginate()
 foreach($toc in $doc.TablesOfContents){$toc.Update()}
 [void]$doc.Fields.Update()
 $doc.Repaginate()
 foreach($toc in $doc.TablesOfContents){$toc.Update()}
 $doc.Save()
 $state.status='updated';Save-State
} catch {
 $state.status='fallback';$state.reason=$_.Exception.Message;Save-State
} finally {
 if($null -ne $blank){try{$blank.Close(0)}catch{}}
 if($owned){
  if($null -ne $doc){try{$doc.Close(0)}catch{}}
  if($null -ne $app){try{$app.Quit(0)}catch{}}
 } elseif($null -ne $app -and -not $shared -and $prior.Count -eq 0){
  try{$app.Quit(0)}catch{}
 }
 if($null -ne $window){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($window)}
 if($null -ne $blank){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($blank)}
 if($null -ne $doc){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($doc)}
 if($null -ne $app){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($app)}
 [GC]::Collect();[GC]::WaitForPendingFinalizers()
}
'''


def word_executable() -> Path | None:
    if sys.platform != 'win32':
        return None
    import winreg
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, 'Word.Application\\CLSID', 0, winreg.KEY_READ | view) as key:
                clsid = winreg.QueryValue(key, None)
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f'CLSID\\{clsid}\\LocalServer32', 0, winreg.KEY_READ | view) as key:
                command = winreg.QueryValue(key, None)
            match = re.match(r'^"?(.+?WINWORD\.EXE)"?(?:\s|$)', command, flags=re.I)
            if match and Path(match.group(1)).is_file():
                return Path(match.group(1))
        except (OSError, ValueError):
            continue
    return None


def _creation_time(pid: int) -> int | None:
    if sys.platform != 'win32':
        return None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return None if ctypes.get_last_error() in (87,1168) else -1
    try:
        status=wintypes.DWORD()
        if not kernel.GetExitCodeProcess(handle,ctypes.byref(status)):
            return -1
        if status.value!=259:
            return None # A terminated process object can still have open handles.
        values = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(v) for v in values)):
            return -1
        return (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
    finally:
        kernel.CloseHandle(handle)


def _cleanup_owned(state: dict) -> bool:
    if not state.get('owned') or not state.get('pid'):
        return True
    pid, expected = int(state['pid']), int(state.get('creation_filetime') or 0)
    actual = _creation_time(pid)
    if actual==-1:
        return False
    if actual is None or actual != expected:
        return True  # Ended or PID reused; never touch a different process.
    # Quit may be asynchronous. Give the private instance a short grace period.
    for _ in range(10):
        identity=_creation_time(pid)
        if identity==-1:return False
        if identity != expected:
            return True
        time.sleep(0.1)
    subprocess.run(['taskkill.exe', '/PID', str(pid), '/T', '/F'], capture_output=True, timeout=10)
    for _ in range(40):
        identity=_creation_time(pid)
        if identity==-1:return False
        if identity != expected:
            return True
        time.sleep(0.1)
    return False


def update_word_toc(path: Path, *, timeout: float = 30) -> dict:
    """Never fail report delivery just because an optional layout engine fails."""
    path = Path(path)
    original = path.read_bytes()
    result = {'mode': 'open_on_update', 'reason': '', 'owned_process_exited': True}
    if os.environ.get('VSTACKLENS_WORD_TOC_MODE') == 'disabled':
        result['reason'] = 'disabled_for_automatic_tests'
    elif word_executable() is None:
        result['reason'] = 'microsoft_word_not_installed'
    else:
        state = {}
        try:
            with tempfile.TemporaryDirectory(prefix='vsl-word-toc-') as temporary:
                root = Path(temporary)
                candidate=root/'report.docx'
                shutil.copy2(path,candidate)
                script, state_file = root / 'update.ps1', root / 'state.json'
                script.write_text(WORKER, 'utf-8-sig')
                command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(script),
                           '-DocumentPath', str(candidate), '-StatePath', str(state_file)]
                timed_out=False
                try:
                    process = subprocess.run(command, capture_output=True, timeout=timeout,
                                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                    result['reason'] = 'word_worker_failed' if process.returncode else 'word_update_failed'
                except subprocess.TimeoutExpired:
                    timed_out=True
                    result['reason'] = 'word_update_timeout'
                finally:
                    if state_file.exists():
                        state = json.loads(state_file.read_text('utf-8-sig'))
                    result['owned_process_exited'] = _cleanup_owned(state)
                if state.get('status') == 'updated' and not timed_out and result['owned_process_exited']:
                    with ZipFile(candidate) as archive:
                        assert archive.testzip() is None
                        ET.fromstring(archive.read('word/document.xml'))
                    # Preserve software metadata after Office updates its cache.
                    buffer=BytesIO()
                    with ZipFile(candidate) as source, ZipFile(buffer,'w') as target:
                        for info in source.infolist():
                            content=source.read(info.filename)
                            if info.filename=='docProps/core.xml':
                                metadata=ET.fromstring(content)
                                for element in metadata:
                                    if element.tag.rsplit('}',1)[-1] in {'creator','lastModifiedBy'}:
                                        element.text='VStackLens'
                                content=ET.tostring(metadata,encoding='utf-8',xml_declaration=True)
                            target.writestr(info,content)
                    candidate.write_bytes(buffer.getvalue())
                    from vstacklens.application.artifact_safety import scan_artifacts
                    if scan_artifacts([candidate]):
                        result['reason']='native_output_failed_safety_scan_original_retained'
                    elif path.read_bytes()!=original:
                        result['reason']='generated_document_changed_no_overwrite'
                    else:
                        pending=path.with_name(path.name+'.toc-'+uuid.uuid4().hex)
                        try:
                            shutil.copy2(candidate,pending)
                            os.replace(pending,path)
                        finally:
                            if pending.exists():pending.unlink()
                        result.update(mode='native_word',reason='table_of_contents_updated')
                elif state.get('reason'):
                    result['reason'] = state['reason']
        except Exception as error:
            result['reason'] = f'{type(error).__name__}: {error}'
    # Word only ever opens the private candidate. Every fallback leaves the
    # generated original (with its standard open-on-update TOC) byte-for-byte.
    LOG.info('Word TOC generation: %s', json.dumps(result, ensure_ascii=False))
    return result
