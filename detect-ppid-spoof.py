'''
Author: In Ming Loh
Email: inming.loh@countercept.com

Requirements:
    1. Python 3 
    2. pip install pywintrace
    3. pip install psutil
    4. Windows machine 
'''

import time
import etw
import psutil

def getService(name):
        service = None
        try:
            service = psutil.win_service_get(name)
            service = service.as_dict()
        except Exception as ex:
            print("Something went wrong. Please contact the developer.")
            print(str(ex))
        return service

def get_me_my_parent(x):
    _etwData = x[1]
    _realParentPid = int(_etwData['EventHeader']['ProcessId']) # PID that generated this event 
    _parentPid = int(_etwData['ParentProcessID'])
    _pid = int(_etwData['ProcessID'])

    # Check parent pid with pid that causes this event (In other words, the original parent).
    _isSpoofed = _realParentPid != _parentPid

    if _isSpoofed:
        # Get PID for service Appinfo. This is the one that will cause consent.exe to run
        service = getService('Appinfo')
        if service and service['status'] == 'running' :
            appinfo_pid = service["pid"]
        else :
            print("Appinfo service not found or is not running.")
            return

        # Check if this is caused by UAC. (UAC will spoof your parent process by using svchost service name appinfo)
        _isCausedByUac = True if _realParentPid == appinfo_pid else False

        if _isSpoofed and not _isCausedByUac:
            process_name = ""
            fake_parent_process_name = ""
            real_parent_process_name = ""

            for proc in psutil.process_iter():
                if proc.pid == _pid:
                    process_name = proc.name()
                elif proc.pid == _parentPid:
                    fake_parent_process_name = proc.name()
                elif proc.pid == _realParentPid:
                    real_parent_process_name = proc.name()

            print("Spoofed parent process detected!!!\n\t{0}({1}) is detected with parent {2}({3}) but originally from parent {4}({5}).".format(process_name, _pid, fake_parent_process_name, _parentPid, real_parent_process_name, _realParentPid))

def main_function():
    # define capture provider info
    providers = [etw.ProviderInfo('Microsoft-Windows-Kernel-Process', etw.GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"))]
    
    # create instance of ETW class
    job = etw.ETW(providers=providers, event_callback=lambda x: get_me_my_parent(x), task_name_filters="PROCESSSTART")
    
    # start capture
    job.start()

    try:
        while True:
            pass
    except(KeyboardInterrupt):
        job.stop()
        print("ETW monitoring stopped.")

if __name__ == '__main__':
    main_function()
