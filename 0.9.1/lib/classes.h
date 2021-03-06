// Container class for logging virus scans.  Includes wrapper methods for rote SQLite statements.

#define LOG_DB "clamlog.db"
#define VERIFY_TBL_SCAN "SELECT id, timestamp, virus, filepath, login FROM tbl_scans"
#define MAX_ID_TBL_SCAN "SELECT MAX(id) FROM tbl_scans"

class tbl // Base class.
{
	protected:
	int id;
	int timestamp;
};

class tbl_scan: protected tbl
{
	protected:
	string virus_name;
	string file_path;
	const char *login_name;
	
	public:
	int log_scan(string vir_name, string file);
};

/* class tbl_actions:protected tbl
{
	protected:
	int scan_id;
	string action;	
	
	public:	
	int log_action(int fk, // Foreign key.
			string action);
}; */

int tbl_scan::log_scan(string vir_name, string file)
{
	
	sqlite3 *db; // points to an sqlite3 database object
	string sql_stmt;
	sqlite3_stmt *compiled_stmt; // points to a compiled SQL statement (output)
	
	int sql_ret; // catches return values for SQLite functions
	char *err_msg = 0;
	
	time_t current_time;	
	timestamp = time(&current_time); // retain unix time -- sqlite lacks a time data type but recognizes Unix time as an integer value.	
	login_name = getenv("USER"); // capture login name of the session

	virus_name = vir_name;
	file_path = file;

	sql_ret = sqlite3_open(LOG_DB, &db); // open sqlite database -- will re-create the logfile if the file does not exist.
	if (sql_ret != 0)
	{
		cout << "Error: Cannot open or create a log file for Clam Vigil.  Make sure you have SQLite3 installed.\n";
		return 1;
	}
		
	// verify table schema
	sql_stmt = VERIFY_TBL_SCAN;	
	sql_ret = sqlite3_exec(db, sql_stmt.c_str(), 0, 0, &err_msg);
	
	if (sql_ret != 0) // attempt to re-create table if code cannot verify table schema.
	{
		sql_ret = sqlite3_exec(db, 
		"CREATE TABLE tbl_scans (id INTEGER PRIMARY KEY, timestamp INTEGER, virus TEXT, filepath TEXT, login TEXT)", 0, 0, &err_msg);
		if (sql_ret != 0) // return an error if code fails to re-create table
		{
			cout << "Clam Vigil's log appears to be corrupted.  See the error message below:\n"
			<< err_msg << "\n";
			sqlite3_free(err_msg);
			sqlite3_close(db);
			return 1;
		}
	}
	
	sql_stmt = "INSERT INTO tbl_scans (timestamp, virus, filepath, login) VALUES (?1, ?2, ?3, ?4)";
	// const char **sql_tail; // null, because sql_stmt does not have multiple statements
	sql_ret = sqlite3_prepare_v2(db, sql_stmt.c_str(), strlen(sql_stmt.c_str()) + 1, &compiled_stmt, NULL);
	
	if (sql_ret != 0) // compile the statement
	{
		cout << "Cannot compile SQL statement to modify log file.\n";
		return 1;
	}

	if (compiled_stmt)
	{
		// bind class members to SQL statement parameters.
		// sqlite3_bind_int(compiled_stmt, 1, new_id);
		sqlite3_bind_int(compiled_stmt, 1, timestamp);
		sqlite3_bind_text(compiled_stmt, 2, virus_name.c_str(), -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(compiled_stmt, 3, file_path.c_str(), -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(compiled_stmt, 4, login_name, -1, SQLITE_TRANSIENT);
		sqlite3_step(compiled_stmt); // execute prepared statement, including bound parameters
		sqlite3_finalize(compiled_stmt); // free up memory reserved for prepared statement
		sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
	}

	else
	{
		cout << "Failed to execute SQL statement on log file.  See error message below:\n"
		<< err_msg << "\n";
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return 1;
	}

	// sql_ret = sqlite3_exec(db, "END", NULL, NULL, NULL);
	sqlite3_close(db);
	return sql_ret;
}

/* int tbl_actions::log_action(int scanid, string action_str)
{
	timestamp(&timestamp); // Retain Unix time. SQLite lacks a time data type but recognizes Unix time as an integer value.
	scan_id = fk;
	action = action_str;
	// id = ; // Get max id from tbl_actions.
} */
