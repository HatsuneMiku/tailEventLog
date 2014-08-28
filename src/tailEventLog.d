/*
  tailEventLog.d

  c:\dmd2\windows\bin\dmd -version=Unicode -run tailEventLog.d logname

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

alias int function(uint lc, EVENTLOGRECORD *pelr) callbacktype;

int getLastLogs(uint *rn, char *computer, char *logname, callbacktype callback)
{
  return 0;
}

int waitForNewEventLogs(char *computer, char *logname)
{
  return 0;
}

int caughtEvent(uint lc, EVENTLOGRECORD *pelr)
{
  return 0;
}

int tailEventLog(string logname)
{
  writefln("%s log", logname);
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
