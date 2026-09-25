import os
from pathlib import Path

def set_reader_access(path, access):
    if os.name != 'nt':
        os.chmod(path, 0o700 if Path(path).is_dir() else 0o600)
        return
    import win32security as s, ntsecuritycon as n, win32api, win32con
    token=s.OpenProcessToken(win32api.GetCurrentProcess(),win32con.TOKEN_QUERY)
    owner=s.GetTokenInformation(token,s.TokenUser)[0]
    restricted=s.ConvertStringSidToSid('S-1-5-12')
    system=s.ConvertStringSidToSid('S-1-5-18')
    acl=s.ACL()
    inherit=3 if Path(path).is_dir() else 0
    if access=='none':
        acl.AddAccessDeniedAceEx(s.ACL_REVISION,inherit,n.FILE_ALL_ACCESS,restricted)
    elif access=='read':
        mask=n.FILE_GENERIC_WRITE | n.DELETE | n.FILE_DELETE_CHILD | n.WRITE_DAC | n.WRITE_OWNER
        # READ_CONTROL and SYNCHRONIZE are shared by generic read/write.
        mask &= ~(n.READ_CONTROL | n.SYNCHRONIZE)
        acl.AddAccessDeniedAceEx(s.ACL_REVISION,inherit,mask,restricted)
    acl.AddAccessAllowedAceEx(s.ACL_REVISION,inherit,n.FILE_ALL_ACCESS,owner)
    acl.AddAccessAllowedAceEx(s.ACL_REVISION,inherit,n.FILE_ALL_ACCESS,system)
    if access!='none':
        acl.AddAccessAllowedAceEx(s.ACL_REVISION,inherit,n.FILE_ALL_ACCESS if access=='modify' else n.FILE_GENERIC_READ|n.FILE_GENERIC_EXECUTE,restricted)
    s.SetNamedSecurityInfo(str(path),s.SE_FILE_OBJECT,s.DACL_SECURITY_INFORMATION|s.PROTECTED_DACL_SECURITY_INFORMATION,None,None,acl,None)

def configure(runtime):
    set_reader_access(runtime,'read')
    set_reader_access(runtime/'keys','none')
    set_reader_access(runtime/'journal','read')
    set_reader_access(runtime/'journal'/'pending','modify')
    set_reader_access(runtime/'journal'/'received','none')
