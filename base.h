#ifndef __BASE_H___
#define __BASE_H___

#include <iostream>
#include <string>
#include <inttypes.h>



using namespace std;

#define SAVE_FILE "/data/input/"
#define SAVE_TEMP_FILE "/data/input/temp/"
#define DATE_FORMAT "%y%m%d%H%M%S"

void _hex_dump(const u_char *p,int len);
string inaddr_2_ip(uint32_t addr);
int get_save_file_name(string strPath,string strTbl,string &strTmpFile,string &strFile);
int ls_dir(string strPath,char *pfilter,char *suffix,vector<string> &v);

#endif
