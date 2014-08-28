/*
  tailEventLog.d

  release
  c:\dmd2\windows\bin\dmd -version=Unicode
    -run tailEventLog.d logname
  test
  c:\dmd2\windows\bin\dmd -version=DisplayEvents -version=Unicode
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

extern(Windows) {
  HANDLE OpenEventLogA(LPCTSTR lpUNCServerName, LPCTSTR lpSourceName);
  BOOL CloseEventLog(HANDLE hEventLog);
  BOOL ReadEventLogA(HANDLE hEventLog, DWORD dwReadFlags, DWORD dwRecordOffset,
    LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    DWORD *pnBytesRead, DWORD *pnMinNumberOfBytesNeeded);
  BOOL GetNumberOfEventLogRecords(HANDLE hEventLog, PDWORD NumberOfRecords);
}

alias int function(uint lc, EVENTLOGRECORD *pelr) eventcbfunc_t; // custom

const size_t BUF_SIZE = 4096;

int getLastLogs(uint *rn, char *computer, char *logname, eventcbfunc_t cbfunc)
{
  BYTE buf[BUF_SIZE];
  EVENTLOGRECORD *pelr;
  uint rd = 0, nle = 0;
  DWORD rc = 0, lc = 0, mrn = 0;
  HANDLE eventlog = OpenEventLogA(computer, logname);
  if(!eventlog) return -1;
version(DisplayEvents){
  if(!GetNumberOfEventLogRecords(eventlog, &rc)){
    CloseEventLog(eventlog);
    return -2;
  }
  writefln("There are events ... (%d)", rc);
}
  while(ReadEventLogA(eventlog,
    EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ,     // read flags
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
  CloseEventLog(eventlog);
  return 0;
}

int waitForNewEventLogs(char *computer, char *logname)
{
  return 0;
}

int dispEvent(uint lc, EVENTLOGRECORD *pelr)
{
  return 0;
}

int tailEventLog(string logname)
{
  uint rn = 0;
  writefln("%s log", logname);
  getLastLogs(&rn, cast(char *)0, cast(char *)logname.toMBSz(), &dispEvent);
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
