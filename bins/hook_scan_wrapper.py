import os
import sys
import argparse

# NOTE: To actually validate the findings, you'll want to also dump the output to a file, 
#    then you can process manually by verifying that the functions/library that was resolved 
#    either does in-fact export that symbol, or if its loaded and just referenced as a global.
#    To do this, you need to run `nm -D /path/to/library.so |grep SymbolName` if it returns 
#    a line like "                 U SymbolName" then its a global and the real symbol probably 
#    lives somewhere else.

# VDSO functions will be in the vdso region, time/gettimeofday
# Functions where the remote is all 00's you can ignore.
FalsePostiveList = ["time", "gettimeofday", "getcpu", "clock_gettime", "_ITM_deregisterTMCloneTable", "__gmon_start__", "_ITM_registerTMCloneTable", "__tls_get_addr"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pid", default=None, help="PID to scan or default scan all")
    parser.add_argument("-o", "--outfile", default=None, help="File to save raw output to in addition to parsing")
    args = parser.parse_args()
    myPid = str(os.getpid())
    fout = None
    if args.outfile != None:
        fout = open(args.outfile, "w")
    if args.pid != None:
        procName = os.readlink("/proc/%s/exe"%(args.pid))
        fin = os.popen("./memloader_test.out %s"%(args.pid), "r")
        readin = fin.read()
        print(readin)
        fin.close()
        sys.exit(0)

    ProcListing = os.listdir("/proc/")
    for item in ProcListing:
        pid = None
        try:
            pid = str(int(item))
        except:
            continue
        procName = "UNKNOWN"
        try:
            procName = os.readlink("/proc/%s/exe"%(pid))
        except:
            print("Failed to get procname for PID %s, skipping"%(pid))
            print("="*50)
            continue
        if myPid == pid:
            continue
        #print("Scanning %s (%s)\n"%(procName, pid))
        fin = os.popen("./memloader_test.out %s"%(pid), "r")
        readin = fin.read()
        fin.close()
        try:
            if "Differs offset" in readin:
                print("="*50)
                print(readin)
        except Exception as e:
            print("Crash on %s(%s): %s"%(procName, pid, e))

        if args.outfile != None:
            fout.write(readin)
            fout.write("="*50)
            fout.write("\n");
    if args.outfile != None:
        fout.close()
