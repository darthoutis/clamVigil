/*
*
* cv-header/wrapper.h: Epitomizes rote tasks, such as ClamAV initializing and SQLite statements, into single routines -- whether functions or methods.
*
*/

// Wrapper function for ClamAV: (1) returns a pointer to AV engine and (2) initializes virus signature and file descriptor variables.
struct cl_engine *init_clamav(int argc, char *argv[], unsigned int &clam_sigs, int &cl_fd)
{
	int cl_ret;
	struct cl_engine *clam_engine;

	// (1) open file on which events occurred, (2) capture file descriptor for ClamAV, (3) verify filepath.
	if((cl_fd = open(argv[1], O_RDONLY)) == -1)
	{
		cout << "Cannot open " << argv[1] << " for ClamAV.  Error: " << errno << ".\n";
		exit(1);	
	}
	// initiate ClamAV
	if(((cl_ret = cl_init(0)) == CL_SUCCESS) && ((clam_engine = cl_engine_new()) == NULL))
	{
		cout << "Cannot initiate ClamAV.  Error " << errno << ".\n";
		cl_engine_free(clam_engine);
		exit(1);
	}

	// load virus database
	if((cl_ret = cl_load(cl_retdbdir(), clam_engine, &clam_sigs, CL_DB_STDOPT)) != CL_SUCCESS)
	{
		cout << "Cannot load virus databases.  Error " << errno << ".\n";
		close(cl_fd);
		cl_engine_free(clam_engine);
		exit(1);
	}

	// compile engine			
	if((cl_ret = cl_engine_compile(clam_engine)) != CL_SUCCESS) 
	{
		cout << "Cannot build ClamAV engine.  Error " << errno << ".\n";
		cl_engine_free(clam_engine);
		close(cl_fd);
		exit(1);
	}
	return clam_engine;
}

// wrapper function for inotify: (1) returns 0 if no error occurs and (2) initializes file and watch descriptors for inotify.
int start_watch(int &inotify_fd, int &inotify_wd, char *argv[])
{
	// instantiate inotify
	inotify_fd = inotify_init();

	if (inotify_fd == -1)
	{
		cout << "Cannot instantiate inotify.  Error " << errno << ".\n";
		exit(1);
	}
	else
	{
		cout << "Monitoring " << argv[1] << ".\n";
	}
	
	// watch file for all events
	inotify_wd = inotify_add_watch(inotify_fd, argv[1], IN_ALL_EVENTS);

	if (inotify_wd == -1)
	{
		cout << "Cannot assign watch to " << argv[1] << ".  Error " << errno << ".\n";
		exit(1);
	}
	else
	{
		cout << "Watching " << argv[1] << " for all events.\n";
	}
	return 0;
}

// Wrapper function for quarantining.  Uses AES in CFB mode.  See http://www.cryptopp.com/wiki/Advanced_Encryption_Standard.
int quarantine(char *argv[])
{
	using namespace CryptoPP;	

	string *encrypted_fname = new string(argv[1]); // convert argv into std::string.
	// dynamically allocate memory, because std::string can only convert C strings at declaration.  "New" returns a pointer.
	*encrypted_fname += ".aes";

	AutoSeededRandomPool prng;
	
	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));
	
	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string orig_contents, hex_contents, encr_contents;

	/*
	* Note: StringSink(), FileSink(), StringSource(), FileSource() and HexEncoder() are class declarations, not functions.  
	* The code dynamically allocates memory for the objects or instantiates anonymous objects (e.g., StringSource/FileSource).
	*/

	// read file
	FileSource (argv[1], true, new StringSink(orig_contents));
	
	// convert file to hexadecimal, so the code can manipulate the contents if binary
	FileSource (argv[1], true, new HexEncoder(new StringSink(hex_contents)));

	// convert key from byte to hexadecimal, so code can save the key to a readable file
	StringSource(key, sizeof(key), true, new HexEncoder(new FileSink("key.txt", true)));

	// convert IV from byte to hexadecimal
	StringSource(iv, sizeof(iv), true, new HexEncoder(new FileSink("iv.txt", true)));

	// encrypt file using key and IV
	CFB_Mode<AES>::Encryption e; // using AES template
	e.SetKeyWithIV(key, sizeof(key), iv);
	StringSource(hex_contents, // when decrypted, *.aes will return hexadecimal contents
		true, new StreamTransformationFilter(e, new FileSink((*encrypted_fname).c_str(), true)));
	cout << argv[1] << " quarantined in " << *encrypted_fname << ".  To restore use \"" << argv[0] << " restore\".\n";
	delete encrypted_fname;
	return 0;
}

// wrapper function to restore a quarantined file
int file_restore(char *argv[])
{
	using namespace CryptoPP;	

	char key_buf[33]; // file size is 32 bytes, but the array has 33 slots to account for the null terminator.
	char iv_buf[33]; // see above.

	ifstream src_f("key.txt"); // retrieve the key
	if (src_f)
	{
		src_f >> key_buf; // reads one string, which contains the key, from the file		
		src_f.close();
	}
	else 
	{
		cout << "Cannot restore file, because key source is inaccessible.\n";
		exit(1);
	}


	src_f.open("iv.txt");  // Retrieve the IV.
	if (src_f)
	{
		src_f >> iv_buf;		
		src_f.close();
	}
	else
	{
		cout << "Cannot restore file, because IV source is inaccessible.\n";
		exit(1);
	}
	
	// cout << "Key: " << key_buf << ".\n";
	// cout << "IV: " << iv_buf << ".\n";

	string key_str;
	StringSource(key_buf, sizeof(key_buf), new HexDecoder(new StringSink(key_str))); // Decode the hexadecimal key into binary.
	// cout << "Decoded key: " << (byte*)key_str.data() << ".\n";

	string iv_str;
	StringSource(iv_buf, sizeof(iv_buf), new HexDecoder(new StringSink(iv_str))); // Decode the hex IV into binary.
	// cout << "Decoded IV: " << (byte*)iv_str.data() << ".\n";

	// Decrypt file using key and IV.
	CFB_Mode<AES>::Decryption d; // Using AES template.
	d.SetKeyWithIV((byte*)key_str.data(),
		key_str.size(), (byte*)iv_str.data()); // Member function requires the code to typecast C strings as byte objects.
	FileSource(argv[2], true, new StreamTransformationFilter(d, new FileSink("test2.txt", true)));

	return 0;
}
