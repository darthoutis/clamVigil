/*
 *  clam-vigil
 *  Scans your selected files for viruses, quarantines files using AES and logs scans to an SQLite database.
 *  Syntax: ./clam-vigil <filepath>
 *
 *  Repositories: Make sure you install the following repositories before compilation:
 *  (1) sqlite3 (not sqlite).  Linked to the application at compilation.
 *  (2) libsqlite3-dev.  You can install this library from the repository or include this library locally. 
 *  (3) clamav.  Linked to the application at compilation.
 *  (4) libclamav-dev.  You can install this library from the repository or include this library locally.
 *  (5) libcrypto++-dev.  Crypto++.
 *
 *  Compilation: g++ -I/usr/include/cryptopp clam-vigil.cpp -o clam-vigil -lclamav -lsqlite3 -lcryptopp
 *
 *  Copyright (C) 2013
 *  Author: Michael Streeter <mstreeter@aggienetwork.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#include <iostream>
#include <string>
#include <cstring>
using namespace std;

#include <fstream> // std::ifstream.
#include <cstdlib> // exit(), atoi().
#include <cerrno> // errno.
#include <fcntl.h> // read().

#include <time.h> // For log timestamp.

#include <sys/types.h>
#include <sys/inotify.h>
#include <sqlite3.h>
#include <clamav.h> 

// Crypto++ libraries.
#include "osrng.h"
#include "cryptlib.h"
#include "hex.h"
#include "filters.h"
#include "aes.h"
#include "modes.h"
#include "files.h"

#include <sqlite3.h>

#include "lib/wrapper.h" // contains local wrapper routines
#include "lib/classes.h" // includes container classes for logging scans in SQLit

int main(int argc, char *argv[])
{		
	if ((argc < 2) || (argc > 3))
	{
		cout << "Syntax: " << argv[0] << "<filepath>.\n"
		<< "Type \"" << argv[0] << " help\" for a list of command arguments.\n";
		exit(1);
	}

	if ((strcmp(argv[1], "restore")) == 0)
	{
		file_restore(argv); // see wrapper.h
		exit(0);
	}
	if ((strcmp(argv[1], "help")) == 0)
	{
		cout << "List of command arguments forthcoming.\n";
		exit(0);
	}

	struct cl_engine *clam_engine; // points to a ClamAV instantiation returned by cl_engine_new()
	int cl_ret;
	int cl_fd;
	unsigned int clam_sigs = 0;
	unsigned long int clam_size = 0;			
	const char *vir_name; // must pass a C-style string by reference to cl_scandesc()
	
	clam_engine = init_clamav(argc, argv, clam_sigs, cl_fd); // See wrapper.h.

	int inotify_fd; // file descriptor that inotify will assign to inotify's monitoring of new.txt
	int inotify_wd; // variable to catch watch descriptor from inotify
	size_t buf_size = sizeof(struct inotify_event); // presupposes the event corresponds to a watched file, not directory
	ssize_t bytes_read; // use ssize_t instead of size_t, because read() will return a negative value if an error occurs
	char buf[buf_size]; // buffer to store inotify events.  Buffer can be any data type, since read() takes a void pointer.
	
	start_watch(inotify_fd, inotify_wd, argv); // see wrapper.h

	// read events for an infinite duration
	while(1)
	{		
		bytes_read = read(inotify_fd, buf, buf_size); // read events from the inotify file descriptor -- store events in buf
		// if no events occur, read() blocks the thread, so the kernel can run other threads
		if (bytes_read == 0)
		{
			cout << "End of file descriptor reached.\n";
			exit(1);
		}

		if (bytes_read < 0)
		{
			cout << "Error reading events from inotify file descriptor.  Error " << errno << ".\n";
			exit(1);
		}

		if (((struct inotify_event *) buf)->mask & IN_ALL_EVENTS) // if the event stored in typecasted buf = IN_ALL_EVENTS, then run ClamAV.
		{
					
			if((cl_ret = cl_scandesc(cl_fd, &vir_name, &clam_size, clam_engine, CL_SCAN_STDOPT)) == CL_VIRUS)
			{
				// log scan				
				tbl_scan logfile;
				string *virus_name = new string(vir_name); // convert C string to std::string
				string *file_name = new string(argv[1]); // ""				
				if ((logfile.log_scan(*virus_name, *file_name)) == 1)
				{
					cout << "Warning: Could not log scan!\n\n"; 
				}
				// Prompt user for options.
				cout << vir_name << " detected in " << argv[1] << ".\n"
				<< "(1) Quarantine (recommended).\n"
				<< "(2) Delete.\n"
				<< "(3) Do nothing (not recommended).\n"
				<< "Choice: ";				
				char response;				
				cin >> response;
				if (response == '1') // to do: Use switch case statements		
					quarantine(argv); //see wrapper.h				
				cl_engine_free(clam_engine);
				exit(1);
			}
			
			else
			{
				if(cl_ret == CL_CLEAN)
				{
					cout << "No virus detected in " << argv[1] << ".\n";
					cl_engine_free(clam_engine);
					close(cl_fd);
					exit(1);
				}
				else
				{
					cout << "Unable to scan " << argv[1] << " for viruses.  Error " << errno << ".\n";
	   				cl_engine_free(clam_engine);
	    				close(cl_fd);
	    				exit(1);
				}
    			}
		}
	}
	inotify_rm_watch(inotify_fd, inotify_wd);
	close(inotify_fd);	
	return 0;
}
