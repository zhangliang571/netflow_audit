#include "date_time.h"

CDateTime::CDateTime()
{

}
CDateTime::~CDateTime()
{

}

//return : "2017-05-25 17:11:00"
string CDateTime::current_time()
{
	ptime pnow(second_clock::local_time());
	string stime = to_iso_extended_string(pnow);
	stime[10] = ' ';
	return stime;
}

//return : "20170525171100"
string CDateTime::current_iso_time()
{
	ptime pnow(second_clock::local_time());
	string stime = to_iso_string(pnow);
	stime = stime.substr(0,8) + stime.substr(9);
	return stime.substr(0,14);
}

time_t CDateTime::date_time_2_timestamp(string strt)
{
	ptime pt(time_from_string(strt));
	struct tm tmm = to_tm(pt);
	return mktime(&tmm);

}
string CDateTime::timestamp_2_string(time_t t)
{
	struct tm *ptm = localtime(&t);
	ptime pt = ptime_from_tm(*ptm);
	string retstr = to_iso_extended_string(pt);
	retstr[10] = ' ';
	return retstr;
}

void CDateTime::echo_time()
{
	time_t t;    
	struct tm *tmp;
	struct timeval tv;        
	char buf[64];

	gettimeofday(&tv,0);      
	t = tv.tv_sec;
	tmp = localtime(&t);      
	snprintf(buf,64,"------time now------[%02d:%02d:%02d.%ld]\n",tmp->tm_hour,tmp->tm_min,tmp->tm_sec,tv.tv_usec);
	cout<<buf;
}

#if 0
void usage()
{
	cout<<"Usage: time_format timestamp/date\n";
}
int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		usage();
		return 0;
	}
	string arg  = argv[1];
	CDateTime *ctime = new CDateTime;
	cout<<"time:"<<ctime->current_time()<<endl;
	if(isdigit(*argv[1]))
		cout<<ctime->timestamp_2_string(lexical_cast<uint32_t>(arg))<<endl;
	else
		cout<<ctime->date_time_2_timestamp(arg);
	
	delete ctime;
	return 0;
}
#endif
