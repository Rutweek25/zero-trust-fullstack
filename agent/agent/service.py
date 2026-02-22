from __future__ import annotations

import threading

from agent.main import AgentRuntime


try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError:  # Service mode optional
    servicemanager = None
    win32event = None
    win32service = None
    win32serviceutil = None


if win32serviceutil and win32service and win32event:
    class CryptoAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "CryptoAgentService"
        _svc_display_name_ = "Crypto Agent Monitoring Service"
        _svc_description_ = "Zero Trust endpoint monitoring agent"

        def __init__(self, args):
            super().__init__(args)
            self.h_wait_stop = win32event.CreateEvent(None, 0, 0, None)
            self.runtime = AgentRuntime()
            self.worker_thread = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.runtime.stop()
            if self.worker_thread and self.worker_thread.is_alive():
                self.worker_thread.join(timeout=10)
            win32event.SetEvent(self.h_wait_stop)

        def SvcDoRun(self):
            servicemanager.LogInfoMsg("CryptoAgentService starting")
            self.worker_thread = threading.Thread(target=self.runtime.start, daemon=True)
            self.worker_thread.start()
            win32event.WaitForSingleObject(self.h_wait_stop, win32event.INFINITE)


def run_service_cli() -> None:
    if not win32serviceutil:
        raise RuntimeError("pywin32 is required for Windows service mode")
    win32serviceutil.HandleCommandLine(CryptoAgentService)


if __name__ == "__main__":
    run_service_cli()
