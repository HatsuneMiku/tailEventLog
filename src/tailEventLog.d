/*
  tailEventLog.d

  *** set compile option -version=Unicode
  *** but use ANSI version Win32API (OpenEventLogA, ReadEventLogA) for char *

  release
  c:\dmd2\windows\bin\dmd -version=Unicode
    -run tailEventLog.d logname
  test
  c:\dmd2\windows\bin\dmd -version=Unicode -version=DisplayEvents
    -run tailEventLog.d logname

  logname: Application, Security, System
*/

import std.c.windows.windows;
import core.sys.windows.dll;

import win32.core; // use Unicode(W) version Win32API when -version=Unicode
// import std.c.windows.windows; // phobos supports only ANSI version Win32API

import std.windows.charset; // toMBSz()
import std.utf;
import std.stdio;
import std.string;
import std.conv;
import std.array;
import std.datetime;
import core.time;
// import std.path;
// import std.file;
// import sqlite3;

extern(Windows) { // force use ANSI API for char * parameters (LPCTSTR->LPCSTR)
  // kernel32.lib
  HANDLE CreateEventA(
    core.sys.windows.windows.LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
  DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
  BOOL CloseHandle(HANDLE hObject);
  // advapi32.lib
  HANDLE OpenEventLogA(LPCSTR lpUNCServerName, LPCSTR lpSourceName);
  BOOL ReadEventLogA(HANDLE hEventLog, DWORD dwReadFlags, DWORD dwRecordOffset,
    LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    DWORD *pnBytesRead, DWORD *pnMinNumberOfBytesNeeded);
  BOOL GetNumberOfEventLogRecords(HANDLE hEventLog, PDWORD NumberOfRecords);
  BOOL NotifyChangeEventLog(HANDLE hEventLog, HANDLE hEvent);
  BOOL CloseEventLog(HANDLE hEventLog);
}

wchar *_ws2wc(wstring ws){ return cast(wchar *)(ws~"(U)\0").ptr; }
char *_s2c(string s){ return cast(char *)s.toMBSz(); }
version(Unicode){
  alias wstring _string;
  wchar *_T(wstring str){ return _ws2wc(str); }
}else{
  alias string _string;
  char *_T(string str){ return _s2c(str); }
}

private int fake_strlen(const char *zString)
{
  int i;
  for(i = 0; zString[i]; ++i){}
  return i;
}

const size_t BUF_SIZE = 4096;

alias int function(uint lc, EVENTLOGRECORD *pelr) eventcbfunc_t; // custom

int getLastLogs(uint *rn, uint direc, HANDLE eventlog, eventcbfunc_t cbfunc)
{
  BYTE buf[BUF_SIZE];
  EVENTLOGRECORD *pelr;
  uint rd = 0, nle = 0;
  DWORD rc = 0, lc = 0, mrn = 0;
version(DisplayEvents){
  if(!GetNumberOfEventLogRecords(eventlog, &rc)) return -1;
  writefln("There are events ... (%d)", rc);
}
  while(ReadEventLogA(eventlog,
    direc | EVENTLOG_SEQUENTIAL_READ,   // read flags
    0,              // record offset (use with EVENTLOG_SEEK_READ)
    (pelr = cast(EVENTLOGRECORD *)buf), // a pointer to a buffer (never NULL)
    buf.sizeof,     // the number of bytes to read (the size of the buffer)
    &rd,            // the number of bytes read
    &nle            // the number of bytes required for the next log entry
  )){
    while(rd > 0){
      if(!lc++) mrn = pelr.RecordNumber;
      if(*rn && pelr.RecordNumber <= *rn){
        *rn = mrn;
        break;
      }
      cbfunc(lc, pelr);
      if(!*rn) *rn = pelr.RecordNumber;
      pelr = cast(EVENTLOGRECORD *)(cast(LPBYTE)pelr + pelr.Length);
      rd -= pelr.Length;
    }
    if(*rn == mrn) break;
  }
version(DisplayEvents){
  writefln("Last record number ... (%d)", *rn);
}
  return 0;
}

int waitForNewEventLogs(HANDLE eventlog, HANDLE event)
{
  NotifyChangeEventLog(eventlog, event);
  WaitForSingleObject(event, core.sys.windows.windows.INFINITE);
  return 0;
}

int dispEvents(uint lc, EVENTLOGRECORD *pelr)
{
  LPBYTE src = cast(LPBYTE)pelr + EVENTLOGRECORD.sizeof;
  LPBYTE cmp = src + fake_strlen(cast(char *)src) + 1;
  LPBYTE sp = cast(LPBYTE)pelr + pelr.StringOffset;
  DWORD ns = pelr.NumStrings;
  DWORD ss;
  writefln("event - %3d, -Ln:0x%08x, Src:%s, Cmp:%s",
    lc, *cast(DWORD *)(cast(LPBYTE)pelr + pelr.Length - DWORD.sizeof),
    cast(LPSTR)src, cast(LPSTR)cmp
  );
  writefln("Ln:0x%08x, Rs:%3d, Rn:%10d, TG:%10d, TW:%10d",
    pelr.Length, pelr.Reserved, pelr.RecordNumber,
    pelr.TimeGenerated, pelr.TimeWritten
  );
  writefln("EI:0x%08x, ET:%3d, NS:%3d, EC:%3d, RF:%3d",
    pelr.EventID, pelr.EventType, pelr.NumStrings,
    pelr.EventCategory, pelr.ReservedFlags
  );
  writef("CR:%10d, SO:0x%08x, USL:%3d, USO:0x%08x, ",
    pelr.ClosingRecordNumber, pelr.StringOffset,
    pelr.UserSidLength, pelr.UserSidOffset
  );
  writefln("DL:%3d, DO:0x%08x",
    pelr.DataLength, pelr.DataOffset
  );
  for(ss = 0; ss < ns; ss++){
    writefln("%3d: [%s]", ss, cast(LPSTR)sp);
    sp += fake_strlen(cast(char *)sp) + 1;
  }
  return 0;
}

int caughtEvents(uint lc, EVENTLOGRECORD *pelr)
{
  writeln(__FUNCTION__);
  return 0;
}

int tailEventLog(string logname)
{
  uint rn = 0;
  writefln("%s log", logname);
  char *zcomputer = null;
  char *zlogname = cast(char *)logname.toMBSz();
version(DisplayEvents){
  eventcbfunc_t callback = &dispEvents;
}else{
  eventcbfunc_t callback = &caughtEvents;
}
  HANDLE eventlog = OpenEventLogA(zcomputer, zlogname);
  if(!eventlog) return -1;
  scope(exit) CloseEventLog(eventlog);
  HANDLE event = CreateEventA(null, true, false, null); // attr,reset,init,name
  if(!event) return -2;
  scope(exit) CloseHandle(event);
  // seek to tail of eventlog
  getLastLogs(&rn, EVENTLOG_BACKWARDS_READ, eventlog, callback); // *backward*
  while(true){ // must read forward once before next event
    getLastLogs(&rn, EVENTLOG_FORWARDS_READ, eventlog, callback); // *forward*
    waitForNewEventLogs(eventlog, event);
  }
  return 0;
}

int main(string[] args)
{
  // foreach(int i, ref arg; args) writefln("args[%3d] = [%s]", i, arg);

  if(args.length < 2){
    writefln("Usage: %s (Application|Security|System)", args[0]);
    return 1;
  }
  return tailEventLog(args[1]);
}
